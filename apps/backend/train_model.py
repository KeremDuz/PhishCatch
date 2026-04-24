from __future__ import annotations

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

INPUT_DATA_PATH = "phishcatch_training_data_url.csv"
MODEL_OUTPUT_PATH = "phishcatch_url_model.pkl"
TARGET_COLUMN = "result"


def main() -> None:
    print("1. Egitim verisi yukleniyor...")
    dataframe = pd.read_csv(INPUT_DATA_PATH)

    if TARGET_COLUMN not in dataframe.columns:
        raise ValueError(f"{INPUT_DATA_PATH} must include '{TARGET_COLUMN}' column")

    features = dataframe.drop(columns=[TARGET_COLUMN])
    labels = dataframe[TARGET_COLUMN].astype(int)

    print(f"Veri boyutu: {len(features)} satir, {features.shape[1]} feature")

    x_train, x_test, y_train, y_test = train_test_split(
        features,
        labels,
        test_size=0.2,
        random_state=42,
        stratify=labels,
    )

    print("2. Model egitiliyor (StandardScaler + RandomForest)...")
    pipeline = Pipeline(
        steps=[
            ("scaler", StandardScaler()),
            (
                "classifier",
                RandomForestClassifier(
                    n_estimators=300,
                    random_state=42,
                    n_jobs=-1,
                    class_weight="balanced_subsample",
                    min_samples_leaf=2,
                ),
            ),
        ]
    )
    pipeline.fit(x_train, y_train)

    print("3. Test setinde degerlendirme yapiliyor...")
    predictions = pipeline.predict(x_test)
    accuracy = accuracy_score(y_test, predictions)

    print("\nModel Degerlendirme Sonucu")
    print(f"Accuracy: {accuracy:.6f}")
    print("\nSiniflandirma Raporu:\n", classification_report(y_test, predictions, digits=4))

    joblib.dump(pipeline, MODEL_OUTPUT_PATH)
    print(f"\nModel pipeline kaydedildi: {MODEL_OUTPUT_PATH}")


if __name__ == "__main__":
    main()
