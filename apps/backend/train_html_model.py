from __future__ import annotations

import argparse
import json
import os
import random
import re
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import joblib
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit

from app.ml.html_feature_extractor import HTML_MODEL_FEATURE_COLUMNS, extract_html_features


BACKEND_ROOT = Path(__file__).resolve().parent
MENDELEY_ROOT = BACKEND_ROOT / "Mendeley_dataset"
INDEX_SQL_PATH = MENDELEY_ROOT / "index.sql"
MODEL_OUTPUT_PATH = BACKEND_ROOT / "phishcatch_html_model.pkl"
METADATA_OUTPUT_PATH = BACKEND_ROOT / "phishcatch_html_model.metadata.json"
MAX_HTML_BYTES = 1024 * 1024
ROW_PATTERN = re.compile(
    r"^\((?P<rec_id>\d+), '(?P<url>.*)', '(?P<website>[^']+\.html)', (?P<result>[01]), '(?P<created_date>[^']+)'\),?$"
)


def main() -> None:
    args = parse_args()
    random.seed(args.seed)

    print("1. Mendeley index ve HTML dosyalari okunuyor...", flush=True)
    rows, skipped_rows = parse_mendeley_index(args.index_sql)
    html_paths = html_file_index(args.dataset_root)
    rows = [row for row in rows if row["website"] in html_paths]

    use_all_data = args.use_all_data or args.no_balance
    selected_rows = select_training_rows(rows, max_per_class=args.max_per_class, balance=not use_all_data, seed=args.seed)
    print(f"Index satiri: {len(rows)} | atlanan SQL satiri: {skipped_rows}", flush=True)
    print(f"Veri secimi: {'tum eslesen satirlar' if use_all_data else 'sinif dengeli orneklem'}", flush=True)
    print(f"Egitim icin secilen satir: {len(selected_rows)} | dagilim: {dict(label_counts(selected_rows))}", flush=True)

    print(f"2. HTML feature'lari cikariliyor... workers={args.workers}", flush=True)
    records: list[dict[str, float]] = []
    labels: list[int] = []
    groups: list[str] = []

    feature_tasks = [
        (row, str(html_paths[row["website"]]))
        for row in selected_rows
    ]
    for index, (feature_dict, label, group) in enumerate(
        iter_feature_rows(feature_tasks, args.workers, args.chunk_size),
        start=1,
    ):
        records.append(feature_dict)
        labels.append(label)
        groups.append(group)

        if index % args.progress_every == 0:
            print(f"  {index}/{len(selected_rows)} feature tamamlandi", flush=True)

    feature_frame = pd.DataFrame.from_records(records, columns=HTML_MODEL_FEATURE_COLUMNS).fillna(0.0)
    label_series = pd.Series(labels, name="result")
    sample_weight, class_weights = build_sample_weights(label_series, args.class_weight)

    print(f"Feature matrisi: {feature_frame.shape[0]} satir, {feature_frame.shape[1]} feature", flush=True)
    print(f"Sinif agirligi: {args.class_weight} | {class_weights}", flush=True)

    print("3. Domain-gruplu validation split ile model degerlendiriliyor...", flush=True)
    train_indices, test_indices = next(
        GroupShuffleSplit(n_splits=1, test_size=args.test_size, random_state=args.seed).split(
            feature_frame,
            label_series,
            groups=groups,
        )
    )

    candidate = build_model(args.seed)
    candidate.fit(
        feature_frame.iloc[train_indices],
        label_series.iloc[train_indices],
        sample_weight=sample_weight.iloc[train_indices] if sample_weight is not None else None,
    )

    probabilities = candidate.predict_proba(feature_frame.iloc[test_indices])[:, 1]
    predictions = (probabilities >= args.threshold).astype(int)
    metrics = calculate_metrics(label_series.iloc[test_indices], predictions, probabilities)
    print_metrics(metrics)

    print("4. Final model tum secili veriyle tekrar egitiliyor...", flush=True)
    final_model = build_model(args.seed)
    final_model.fit(feature_frame, label_series, sample_weight=sample_weight)

    joblib.dump(final_model, args.model_output, compress=3)
    metadata = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "model_type": type(final_model).__name__,
        "threshold": args.threshold,
        "source": {
            "index_sql": str(args.index_sql),
            "dataset_root": str(args.dataset_root),
            "rows_after_file_match": len(rows),
            "workers": args.workers,
            "chunk_size": args.chunk_size,
            "selected_rows": len(selected_rows),
            "selected_label_counts": dict(label_counts(selected_rows)),
            "selection_mode": "all_matched_rows" if use_all_data else "balanced_sample",
            "class_weight": args.class_weight,
            "class_weights": class_weights,
            "skipped_sql_rows": skipped_rows,
            "max_html_bytes": MAX_HTML_BYTES,
        },
        "features": HTML_MODEL_FEATURE_COLUMNS,
        "validation": metrics,
    }
    args.metadata_output.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    print(f"Model kaydedildi: {args.model_output}", flush=True)
    print(f"Metadata kaydedildi: {args.metadata_output}", flush=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train a compact HTML/DOM phishing model from the Mendeley dataset.")
    parser.add_argument("--index-sql", type=Path, default=INDEX_SQL_PATH)
    parser.add_argument("--dataset-root", type=Path, default=MENDELEY_ROOT / "dataset")
    parser.add_argument("--model-output", type=Path, default=MODEL_OUTPUT_PATH)
    parser.add_argument("--metadata-output", type=Path, default=METADATA_OUTPUT_PATH)
    parser.add_argument("--max-per-class", type=int, default=0, help="0 means use the minority-class count when balanced.")
    parser.add_argument("--use-all-data", action="store_true", help="Use every matched HTML row instead of undersampling.")
    parser.add_argument("--no-balance", action="store_true", help="Deprecated alias for --use-all-data.")
    parser.add_argument(
        "--class-weight",
        choices=("balanced", "none"),
        default="balanced",
        help="Use balanced sample weights during fitting, or disable weighting.",
    )
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--progress-every", type=int, default=1000)
    parser.add_argument("--workers", type=int, default=max(1, min(4, os.cpu_count() or 1)))
    parser.add_argument("--chunk-size", type=int, default=100)
    return parser.parse_args()


def parse_mendeley_index(index_sql_path: Path) -> tuple[list[dict[str, object]], int]:
    rows: list[dict[str, object]] = []
    skipped = 0

    for raw_line in index_sql_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line.startswith("("):
            continue

        match = ROW_PATTERN.match(line)
        if not match:
            skipped += 1
            continue

        rows.append(
            {
                "rec_id": int(match.group("rec_id")),
                "url": match.group("url"),
                "website": match.group("website"),
                "result": int(match.group("result")),
                "created_date": match.group("created_date"),
            }
        )

    return rows, skipped


def html_file_index(dataset_root: Path) -> dict[str, Path]:
    return {path.name: path for path in dataset_root.glob("dataset_part_*/dataset-part-*/*.html")}


def select_training_rows(rows: list[dict[str, object]], max_per_class: int, balance: bool, seed: int) -> list[dict[str, object]]:
    shuffled = rows[:]
    random.Random(seed).shuffle(shuffled)

    if not balance:
        if max_per_class <= 0:
            return shuffled
        per_label: dict[int, list[dict[str, object]]] = {0: [], 1: []}
        for row in shuffled:
            label = int(row["result"])
            if len(per_label[label]) < max_per_class:
                per_label[label].append(row)
        return per_label[0] + per_label[1]

    by_label: dict[int, list[dict[str, object]]] = {0: [], 1: []}
    for row in shuffled:
        by_label[int(row["result"])].append(row)

    class_size = min(len(by_label[0]), len(by_label[1]))
    if max_per_class > 0:
        class_size = min(class_size, max_per_class)

    selected = by_label[0][:class_size] + by_label[1][:class_size]
    random.Random(seed).shuffle(selected)
    return selected


def label_counts(rows: list[dict[str, object]]) -> Counter:
    return Counter(int(row["result"]) for row in rows)


def iter_feature_rows(
    feature_tasks: list[tuple[dict[str, object], str]],
    workers: int,
    chunk_size: int,
):
    if workers <= 1:
        for task in feature_tasks:
            yield extract_feature_row(task)
        return

    with ProcessPoolExecutor(max_workers=workers) as executor:
        yield from executor.map(extract_feature_row, feature_tasks, chunksize=max(1, chunk_size))


def extract_feature_row(task: tuple[dict[str, object], str]) -> tuple[dict[str, float], int, str]:
    row, html_path = task
    html = read_html(Path(html_path))
    features = extract_html_features(url=str(row["url"]), raw_html=html)
    label = int(row["result"])
    group = domain_group(str(row["url"]))
    return features.to_dict(), label, group


def build_sample_weights(labels: pd.Series, class_weight: str) -> tuple[pd.Series | None, dict[int, float]]:
    if class_weight == "none":
        return None, {}

    counts = Counter(int(value) for value in labels)
    if not counts:
        return None, {}

    total = len(labels)
    class_count = len(counts)
    weights = {
        label: round(total / (class_count * count), 6)
        for label, count in sorted(counts.items())
    }
    return labels.map(weights).astype(float), weights


def read_html(path: Path) -> str:
    return path.read_bytes()[:MAX_HTML_BYTES].decode("utf-8", errors="ignore")


def domain_group(url: str) -> str:
    hostname = urlparse(url if url.startswith(("http://", "https://")) else f"http://{url}").hostname or ""
    parts = [part for part in hostname.lower().split(".") if part]
    if len(parts) <= 2:
        return hostname.lower()
    return ".".join(parts[-2:])


def build_model(seed: int) -> HistGradientBoostingClassifier:
    return HistGradientBoostingClassifier(
        learning_rate=0.06,
        max_iter=220,
        max_leaf_nodes=31,
        min_samples_leaf=25,
        l2_regularization=0.02,
        early_stopping=True,
        validation_fraction=0.12,
        random_state=seed,
    )


def calculate_metrics(y_true: pd.Series, y_pred, y_prob) -> dict[str, object]:
    matrix = confusion_matrix(y_true, y_pred, labels=[0, 1])
    report = classification_report(y_true, y_pred, labels=[0, 1], output_dict=True, zero_division=0)
    return {
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 6),
        "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 6),
        "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 6),
        "f1": round(float(f1_score(y_true, y_pred, zero_division=0)), 6),
        "roc_auc": round(float(roc_auc_score(y_true, y_prob)), 6),
        "confusion_matrix": matrix.tolist(),
        "classification_report": report,
        "test_label_counts": dict(Counter(int(value) for value in y_true)),
    }


def print_metrics(metrics: dict[str, object]) -> None:
    print("Validation metrikleri", flush=True)
    print(f"  accuracy : {metrics['accuracy']}", flush=True)
    print(f"  precision: {metrics['precision']}", flush=True)
    print(f"  recall   : {metrics['recall']}", flush=True)
    print(f"  f1       : {metrics['f1']}", flush=True)
    print(f"  roc_auc  : {metrics['roc_auc']}", flush=True)
    print(f"  labels   : {metrics['test_label_counts']}", flush=True)
    print(f"  matrix   : {metrics['confusion_matrix']}", flush=True)


if __name__ == "__main__":
    main()
