from __future__ import annotations

import argparse
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from app.ml.feature_extractor import URL_FEATURE_COLUMNS
from app.ml.incremental_model import IncrementalBinaryClassifier

INPUT_DATA_PATH = "phishcatch_training_data_url.csv"
MODEL_OUTPUT_PATH = "phishcatch_url_model.pkl"
TARGET_COLUMN = "result"


def main() -> None:
    args = parse_args()
    print("1. Egitim verisi yukleniyor...")
    dataframe = pd.read_csv(args.input_data)

    if TARGET_COLUMN not in dataframe.columns:
        raise ValueError(f"{args.input_data} must include '{TARGET_COLUMN}' column")

    feature_columns = [column for column in URL_FEATURE_COLUMNS if column in dataframe.columns]
    if len(feature_columns) != len(URL_FEATURE_COLUMNS):
        feature_columns = [column for column in dataframe.columns if column != TARGET_COLUMN]

    features = dataframe[feature_columns].fillna(0.0)
    labels = dataframe[TARGET_COLUMN].astype(int)

    print(f"Veri boyutu: {len(features)} satir, {features.shape[1]} feature")

    x_train, x_test, y_train, y_test = train_test_split(
        features,
        labels,
        test_size=0.2,
        random_state=42,
        stratify=labels,
    )

    print(f"2. Model egitiliyor ({args.model_family})...")
    pipeline = build_model(args, feature_columns)
    pipeline.fit(x_train, y_train)

    print("3. Test setinde degerlendirme yapiliyor...")
    predictions = pipeline.predict(x_test)
    accuracy = accuracy_score(y_test, predictions)

    print("\nModel Degerlendirme Sonucu")
    print(f"Accuracy: {accuracy:.6f}")
    print("\nSiniflandirma Raporu:\n", classification_report(y_test, predictions, digits=4))

    final_model = build_model(args, feature_columns)
    final_model.fit(features, labels)
    joblib.dump(final_model, args.model_output)
    print(f"\nModel kaydedildi: {args.model_output}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train the URL phishing model.")
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
    main()
