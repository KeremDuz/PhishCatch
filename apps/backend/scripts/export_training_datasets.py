from __future__ import annotations

import argparse
import csv
from pathlib import Path
import sys
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.core.config import settings
from app.ml.feature_extractor import URL_FEATURE_COLUMNS, extract_features_dict
from app.ml.html_feature_extractor import HTML_MODEL_FEATURE_COLUMNS
from app.storage import TrainingStore


DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "generated"
URL_OUTPUT_NAME = "url_training_dataset.csv"
HTML_OUTPUT_NAME = "html_training_dataset.csv"
TARGET_COLUMN = "result"


def main() -> int:
    args = parse_args()
    return export_training_datasets(
        db_path=args.db_path,
        output_dir=args.output_dir,
        include_unapproved=args.include_unapproved,
    )


def export_training_datasets(
    *,
    db_path: Path,
    output_dir: Path,
    include_unapproved: bool = False,
) -> int:
    store = TrainingStore(db_path)
    store.init_db()

    samples = store.training_samples(approved_only=not include_unapproved)
    output_dir.mkdir(parents=True, exist_ok=True)

    url_rows = build_url_rows(samples)
    html_rows = build_html_rows(samples)

    url_output = output_dir / URL_OUTPUT_NAME
    html_output = output_dir / HTML_OUTPUT_NAME
    write_dataset(url_output, URL_FEATURE_COLUMNS, url_rows)
    write_dataset(html_output, HTML_MODEL_FEATURE_COLUMNS, html_rows)

    print("Training datasets exported")
    print(f"DB: {store.db_path}")
    print(f"Samples read: {len(samples)}")
    print(f"URL rows: {len(url_rows)} -> {url_output}")
    print(f"HTML rows: {len(html_rows)} -> {html_output}")
    print(f"HTML skipped without features: {len(samples) - len(html_rows)}")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Export approved training samples to URL and HTML model CSV datasets.")
    parser.add_argument("--db-path", type=Path, default=Path(settings.training_db_path))
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument(
        "--include-unapproved",
        action="store_true",
        help="Export all training samples instead of only approved_for_training=1 samples.",
    )
    return parser.parse_args()


def build_url_rows(samples: list[dict[str, Any]]) -> list[dict[str, float | int]]:
    rows: list[dict[str, float | int]] = []
    for sample in samples:
        features = sample.get("url_features")
        if not isinstance(features, dict):
            features = extract_features_dict(str(sample.get("final_url") or sample["url"]))

        rows.append(feature_row(features, URL_FEATURE_COLUMNS, int(sample["label"])))
    return rows


def build_html_rows(samples: list[dict[str, Any]]) -> list[dict[str, float | int]]:
    rows: list[dict[str, float | int]] = []
    for sample in samples:
        features = sample.get("html_features")
        if not isinstance(features, dict):
            continue
        rows.append(feature_row(features, HTML_MODEL_FEATURE_COLUMNS, int(sample["label"])))
    return rows


def feature_row(features: dict[str, Any], columns: list[str], label: int) -> dict[str, float | int]:
    row: dict[str, float | int] = {}
    for column in columns:
        row[column] = float(features.get(column, 0.0) or 0.0)
    row[TARGET_COLUMN] = label
    return row


def write_dataset(path: Path, feature_columns: list[str], rows: list[dict[str, float | int]]) -> None:
    fieldnames = feature_columns + [TARGET_COLUMN]
    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


if __name__ == "__main__":
    raise SystemExit(main())
