from __future__ import annotations

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

INPUT_DATA_PATH = "phishcatch_training_data_48.csv"
MODEL_OUTPUT_PATH = "phishcatch_rf_model_48.pkl"
SCALER_OUTPUT_PATH = "phishcatch_scaler_48.pkl"
TARGET_COLUMN = "result"


def main() -> None:
    print("1. Eğitim verisi yükleniyor...")
    dataframe = pd.read_csv(INPUT_DATA_PATH)

    if TARGET_COLUMN not in dataframe.columns:
        raise ValueError(f"{INPUT_DATA_PATH} must include '{TARGET_COLUMN}' column")

    features = dataframe.drop(columns=[TARGET_COLUMN])
    labels = dataframe[TARGET_COLUMN].astype(int)

    print(f"Veri boyutu: {len(features)} satır, {features.shape[1]} feature")

    x_train, x_test, y_train, y_test = train_test_split(
        features,
        labels,
        test_size=0.2,
        random_state=42,
        stratify=labels,
    )

    scaler = StandardScaler()
    x_train_scaled = scaler.fit_transform(x_train)
    x_test_scaled = scaler.transform(x_test)

    print("2. Model eğitiliyor (RandomForest)...")
    model = RandomForestClassifier(
        n_estimators=300,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced_subsample",
        min_samples_leaf=2,
    )
    model.fit(x_train_scaled, y_train)

    print("3. Test setinde değerlendirme yapılıyor...")
    predictions = model.predict(x_test_scaled)
    accuracy = accuracy_score(y_test, predictions)

    print("\n✅ Model Değerlendirme Sonucu")
    print(f"Accuracy: {accuracy:.6f}")
    print("\nSınıflandırma Raporu:\n", classification_report(y_test, predictions, digits=4))

    joblib.dump(model, MODEL_OUTPUT_PATH)
    joblib.dump(scaler, SCALER_OUTPUT_PATH)
    print(f"\n🎉 Model kaydedildi: {MODEL_OUTPUT_PATH}")
    print(f"🎉 Scaler kaydedildi: {SCALER_OUTPUT_PATH}")

if __name__ == "__main__":
    main()