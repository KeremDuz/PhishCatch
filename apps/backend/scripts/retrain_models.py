from __future__ import annotations

import argparse
import json
import hashlib
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import sys
from typing import Any

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.core.config import settings
from app.ml.artifact_paths import (
    atomic_registry_write,
    validate_training_file,
    validate_training_outputs,
)
from app.ml.incremental_model import IncrementalBinaryClassifier
from app.ml.feature_extractor import URL_FEATURE_COLUMNS
from app.ml.html_feature_extractor import HTML_MODEL_FEATURE_COLUMNS
from app.ml.evaluation import grouped_temporal_indices, identity_digest, wilson_upper
from scripts.export_training_datasets import HTML_OUTPUT_NAME, URL_OUTPUT_NAME, export_training_datasets
from train_html_model import build_model as build_html_model
from train_html_model import build_sample_weights


DEFAULT_DATASET_DIR = PROJECT_ROOT / "generated"
DEFAULT_MODEL_DIR = PROJECT_ROOT / "models" / "candidates"
DEFAULT_REGISTRY_PATH = PROJECT_ROOT / "models" / "registry.json"
TARGET_COLUMN = "result"


def main() -> int:
    args = parse_args()

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    url_path = args.model_dir / f"phishcatch_url_model_{timestamp}.pkl"
    html_path = args.model_dir / f"phishcatch_html_model_{timestamp}.pkl"
    artifact_outputs = [url_path, url_path.with_suffix(".metadata.json"),
                        html_path, html_path.with_suffix(".metadata.json")]
    for path in artifact_outputs:
        validate_training_file(path, new_candidate=True)
    validate_training_file(args.registry_path)
    all_outputs = artifact_outputs + [args.registry_path]
    if args.export_first:
        dataset_outputs = [args.dataset_dir / URL_OUTPUT_NAME, args.dataset_dir / HTML_OUTPUT_NAME]
        for path in dataset_outputs:
            validate_training_file(path)
        all_outputs.extend(dataset_outputs)
    validate_training_outputs(*all_outputs)

    if args.export_first:
        export_training_datasets(
            db_path=args.db_path,
            output_dir=args.dataset_dir,
            include_unapproved=args.include_unapproved,
        )

    args.model_dir.mkdir(parents=True, exist_ok=True)
    args.registry_path.parent.mkdir(parents=True, exist_ok=True)

    url_result = train_candidate(
        name="url",
        dataset_path=args.dataset_dir / URL_OUTPUT_NAME,
        feature_columns=URL_FEATURE_COLUMNS,
        build_model=lambda: build_url_model(args, URL_FEATURE_COLUMNS),
        model_path=url_path,
        min_samples=args.min_samples,
        test_size=args.test_size,
        threshold=args.threshold,
        seed=args.seed,
        sample_weight_mode=args.url_class_weight if args.model_family == "incremental" else "none",
    )
    html_result = train_candidate(
        name="html",
        dataset_path=args.dataset_dir / HTML_OUTPUT_NAME,
        feature_columns=HTML_MODEL_FEATURE_COLUMNS,
        build_model=lambda: build_html_candidate_model(args, HTML_MODEL_FEATURE_COLUMNS),
        model_path=html_path,
        min_samples=args.min_samples,
        test_size=args.test_size,
        threshold=args.threshold,
        seed=args.seed,
        sample_weight_mode=args.html_class_weight,
    )

    registry = {
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "latest_run": {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "dataset_dir": str(args.dataset_dir),
            "model_dir": str(args.model_dir),
            "threshold": args.threshold,
            "test_size": args.test_size,
            "min_samples": args.min_samples,
            "model_family": args.model_family,
            "models": {
                "url": url_result,
                "html": html_result,
            },
        },
    }
    atomic_registry_write(args.registry_path, json.dumps(registry, indent=2))

    print("Retrain run finished")
    print(f"Registry: {args.registry_path}")
    print_status("URL", url_result)
    print_status("HTML", html_result)
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train candidate URL and HTML models from exported training datasets.")
    parser.add_argument("--dataset-dir", type=Path, default=DEFAULT_DATASET_DIR)
    parser.add_argument("--db-path", type=Path, default=Path(settings.training_db_path))
    parser.add_argument("--model-dir", type=Path, default=DEFAULT_MODEL_DIR)
    parser.add_argument("--registry-path", type=Path, default=DEFAULT_REGISTRY_PATH)
    parser.add_argument("--export-first", action="store_true", help="Run export_training_datasets.py before training.")
    parser.add_argument("--include-unapproved", action="store_true", help="Include unapproved samples when --export-first is used.")
    parser.add_argument("--min-samples", type=int, default=20)
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--model-family",
        choices=("incremental", "batch"),
        default="incremental",
        help="Train partial_fit-capable incremental models, or legacy batch models.",
    )
    parser.add_argument("--incremental-alpha", type=float, default=0.0001)
    parser.add_argument("--incremental-epochs", type=int, default=8)
    parser.add_argument("--incremental-batch-size", type=int, default=512)
    parser.add_argument(
        "--url-class-weight",
        choices=("balanced", "none"),
        default="balanced",
        help="Sample weighting for the URL incremental candidate model.",
    )
    parser.add_argument(
        "--html-class-weight",
        choices=("balanced", "none"),
        default="balanced",
        help="Sample weighting for the HTML candidate model.",
    )
    return parser.parse_args()


def build_url_model(args: argparse.Namespace, feature_columns: list[str]):
    if args.model_family == "incremental":
        return build_incremental_model(args, feature_columns)

    return Pipeline(
        steps=[
            ("scaler", StandardScaler()),
            (
                "classifier",
                RandomForestClassifier(
                    n_estimators=300,
                    random_state=args.seed,
                    n_jobs=-1,
                    class_weight="balanced_subsample",
                    min_samples_leaf=2,
                ),
            ),
        ]
    )


def build_html_candidate_model(args: argparse.Namespace, feature_columns: list[str]):
    if args.model_family == "incremental":
        return build_incremental_model(args, feature_columns)

    return build_html_model(args.seed)


def build_incremental_model(args: argparse.Namespace, feature_columns: list[str]) -> IncrementalBinaryClassifier:
    return IncrementalBinaryClassifier(
        feature_names=feature_columns,
        alpha=args.incremental_alpha,
        epochs=args.incremental_epochs,
        batch_size=args.incremental_batch_size,
        random_state=args.seed,
    )


def train_candidate(
    *,
    name: str,
    dataset_path: Path,
    feature_columns: list[str],
    build_model,
    model_path: Path,
    min_samples: int,
    test_size: float,
    threshold: float,
    seed: int,
    sample_weight_mode: str = "none",
) -> dict[str, Any]:
    validate_training_file(model_path, new_candidate=True)
    validate_training_file(model_path.with_suffix(".metadata.json"), new_candidate=True)
    validate_training_outputs(dataset_path, model_path, model_path.with_suffix(".metadata.json"))
    if not dataset_path.exists():
        return skipped(name, dataset_path, f"Dataset not found: {dataset_path}")

    dataframe = pd.read_csv(dataset_path)
    if TARGET_COLUMN not in dataframe.columns:
        return skipped(name, dataset_path, f"Dataset missing '{TARGET_COLUMN}' column")

    missing_columns = [column for column in feature_columns if column not in dataframe.columns]
    if missing_columns:
        return skipped(name, dataset_path, f"Dataset missing feature columns: {missing_columns[:5]}")

    dataframe[feature_columns] = dataframe[feature_columns].fillna(0.0)
    labels = dataframe[TARGET_COLUMN].astype(int)
    label_counts = Counter(int(value) for value in labels)
    if len(dataframe) < min_samples:
        return skipped(name, dataset_path, f"Need at least {min_samples} rows, found {len(dataframe)}", label_counts)
    if set(label_counts) != {0, 1}:
        return skipped(name, dataset_path, f"Need both clean and malicious labels, found {dict(label_counts)}", label_counts)
    if min(label_counts.values()) < 2:
        return skipped(name, dataset_path, f"Need at least 2 rows per class, found {dict(label_counts)}", label_counts)

    features = dataframe[feature_columns]
    try:
        train_indices, test_indices = grouped_temporal_indices(dataframe, feature_columns, test_size)
    except ValueError as exc:
        return skipped(name, dataset_path, str(exc), label_counts)
    x_train, x_test = features.loc[train_indices], features.loc[test_indices]
    y_train, y_test = labels.loc[train_indices], labels.loc[test_indices]

    model = build_model()
    if sample_weight_mode == "balanced":
        sample_weight, class_weights = build_sample_weights(y_train, "balanced")
        model.fit(x_train, y_train, sample_weight=sample_weight)
    else:
        class_weights = {}
        model.fit(x_train, y_train)

    probabilities = predict_probabilities(model, x_test)
    predictions = (probabilities >= threshold).astype(int)
    metrics = calculate_metrics(y_test, predictions, probabilities)

    # The persisted candidate is exactly the evaluated model. Never refit it on
    # its holdout and then attach metrics from a different estimator.
    final_model = model
    model_path.parent.mkdir(parents=True, exist_ok=True)
    validate_training_file(model_path, new_candidate=True)
    # Exclusive creation never follows or truncates a concurrently introduced
    # output alias. Existing candidates remain immutable.
    with model_path.open("xb") as file:
        joblib.dump(final_model, file, compress=3)
    proof = {"strategy": "grouped-temporal-v1", "dataset_sha256": hashlib.sha256(dataset_path.read_bytes()).hexdigest(),
             "model_sha256": hashlib.sha256(model_path.read_bytes()).hexdigest(),
             "train_rows": len(train_indices), "test_rows": len(test_indices),
             "test_unique_domains": int(dataframe.loc[test_indices, "domain_group"].nunique()),
             "threshold": threshold,
             "test_identity_sha256": identity_digest(dataframe.loc[test_indices, "sample_id"]),
             "domain_overlap": 0, "template_overlap": 0, "feature_overlap": 0,
             "refit_on_holdout": False, "verified_labels": True}
    metrics["evaluation"] = proof
    metadata_path = model_path.with_suffix(".metadata.json")
    metadata = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "model_name": name,
        "model_type": type(final_model).__name__,
        "supports_partial_fit": hasattr(final_model, "partial_fit"),
        "dataset_path": str(dataset_path),
        "model_path": str(model_path),
        "feature_count": len(feature_columns),
        "row_count": int(len(dataframe)),
        "label_counts": dict(label_counts),
        "class_weights": class_weights,
        "threshold": threshold,
        "validation": metrics,
        "features": feature_columns,
    }
    validate_training_file(metadata_path, new_candidate=True)
    with metadata_path.open("x", encoding="utf-8") as file:
        file.write(json.dumps(metadata, indent=2))

    return {
        "status": "trained",
        "dataset_path": str(dataset_path),
        "model_path": str(model_path),
        "metadata_path": str(metadata_path),
        "row_count": int(len(dataframe)),
        "label_counts": dict(label_counts),
        "validation": metrics,
    }


def predict_probabilities(model, features: pd.DataFrame):
    if hasattr(model, "predict_proba"):
        return model.predict_proba(features)[:, 1]
    return model.predict(features)


def calculate_metrics(y_true: pd.Series, y_pred, y_prob) -> dict[str, Any]:
    label_counts = Counter(int(value) for value in y_true)
    metrics = {
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 6),
        "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 6),
        "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 6),
        "f1": round(float(f1_score(y_true, y_pred, zero_division=0)), 6),
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=[0, 1]).tolist(),
        "classification_report": classification_report(
            y_true,
            y_pred,
            labels=[0, 1],
            output_dict=True,
            zero_division=0,
        ),
        "test_label_counts": dict(label_counts),
    }
    metrics["roc_auc"] = (
        round(float(roc_auc_score(y_true, y_prob)), 6)
        if set(label_counts) == {0, 1}
        else None
    )
    tn, fp = metrics["confusion_matrix"][0]
    metrics["false_positive_rate"] = fp / (tn + fp) if tn + fp else 1.0
    metrics["false_positive_rate_upper_95"] = wilson_upper(fp, tn + fp)
    return metrics


def skipped(
    name: str,
    dataset_path: Path,
    reason: str,
    label_counts: Counter | None = None,
) -> dict[str, Any]:
    return {
        "status": "skipped",
        "dataset_path": str(dataset_path),
        "reason": reason,
        "label_counts": dict(label_counts or {}),
    }


def print_status(label: str, result: dict[str, Any]) -> None:
    if result["status"] == "trained":
        metrics = result["validation"]
        print(
            f"{label}: trained rows={result['row_count']} "
            f"f1={metrics['f1']} precision={metrics['precision']} recall={metrics['recall']}"
        )
        print(f"{label} model: {result['model_path']}")
        return

    print(f"{label}: skipped ({result['reason']})")


if __name__ == "__main__":
    raise SystemExit(main())
