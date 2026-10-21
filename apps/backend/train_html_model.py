from __future__ import annotations

import argparse
import os
import random
import re
import sys
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from urllib.parse import urlparse

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

from app.ml.html_feature_extractor import HTML_MODEL_FEATURE_COLUMNS, extract_html_features
from app.ml.incremental_model import IncrementalBinaryClassifier


BACKEND_ROOT = Path(__file__).resolve().parent
MENDELEY_ROOT = BACKEND_ROOT / "Mendeley_dataset"
INDEX_SQL_PATH = MENDELEY_ROOT / "index.sql"
MODEL_OUTPUT_PATH = BACKEND_ROOT / "models" / "candidates" / "phishcatch_html_model_legacy.pkl"
METADATA_OUTPUT_PATH = MODEL_OUTPUT_PATH.with_suffix(".metadata.json")
MAX_HTML_BYTES = 1024 * 1024
ROW_PATTERN = re.compile(
    r"^\((?P<rec_id>\d+), '(?P<url>.*)', '(?P<website>[^']+\.html)', (?P<result>[01]), '(?P<created_date>[^']+)'\),?$"
)


def main() -> int:
    parse_args()
    print(
        "Bu eski HTML egitim komutu kaldirildi; hicbir model veya metadata "
        "dosyasi yazilmadi. Dogrulanmis ornekleri "
        "scripts/export_training_datasets.py ile aktarip scripts/retrain_models.py "
        "ile aday model olusturun. Aktif model yalniz "
        "scripts/promote_candidate_models.py kontrollerinden sonra degistirilebilir.",
        file=sys.stderr,
    )
    return 2


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Retired HTML trainer: use scripts/retrain_models.py; no artifacts are written.")
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
    parser.add_argument("--model-family", choices=("incremental", "batch"), default="incremental")
    parser.add_argument("--incremental-alpha", type=float, default=0.0001)
    parser.add_argument("--incremental-epochs", type=int, default=8)
    parser.add_argument("--incremental-batch-size", type=int, default=512)
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


def build_training_model(args: argparse.Namespace):
    if args.model_family == "incremental":
        return IncrementalBinaryClassifier(
            feature_names=HTML_MODEL_FEATURE_COLUMNS,
            alpha=args.incremental_alpha,
            epochs=args.incremental_epochs,
            batch_size=args.incremental_batch_size,
            random_state=args.seed,
        )

    return build_model(args.seed)


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
    raise SystemExit(main())
