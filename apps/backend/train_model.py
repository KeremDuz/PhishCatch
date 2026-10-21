from __future__ import annotations

import argparse
import sys
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from app.ml.incremental_model import IncrementalBinaryClassifier

INPUT_DATA_PATH = "phishcatch_training_data_url.csv"
MODEL_OUTPUT_PATH = "models/candidates/phishcatch_url_model_legacy.pkl"
TARGET_COLUMN = "result"


def main() -> int:
    parse_args()
    print(
        "Bu eski egitim komutu kaldirildi; hicbir model dosyasi yazilmadi. "
        "Dogrulanmis ornekleri scripts/export_training_datasets.py ile aktarip "
        "scripts/retrain_models.py ile aday model olusturun. "
        "Aktif model yalniz scripts/promote_candidate_models.py kontrollerinden "
        "sonra degistirilebilir.",
        file=sys.stderr,
    )
    return 2


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Retired URL trainer: use scripts/retrain_models.py; no artifacts are written.")
    parser.add_argument("--input-data", default=INPUT_DATA_PATH)
    parser.add_argument("--model-output", default=MODEL_OUTPUT_PATH)
    parser.add_argument("--model-family", choices=("incremental", "batch"), default="incremental")
    parser.add_argument("--incremental-alpha", type=float, default=0.0001)
    parser.add_argument("--incremental-epochs", type=int, default=8)
    parser.add_argument("--incremental-batch-size", type=int, default=512)
    parser.add_argument("--seed", type=int, default=42)
    return parser.parse_args()


def build_model(args: argparse.Namespace, feature_columns: list[str]):
    if args.model_family == "incremental":
        return IncrementalBinaryClassifier(
            feature_names=feature_columns,
            alpha=args.incremental_alpha,
            epochs=args.incremental_epochs,
            batch_size=args.incremental_batch_size,
            random_state=args.seed,
        )

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


if __name__ == "__main__":
    raise SystemExit(main())
