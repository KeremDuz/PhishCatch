import pandas as pd
import os
import numpy as np
import matplotlib.pyplot as plt
from scipy.io import arff  # ARFF dosyalarını okumak için ekledik
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score
import joblib

print("1. Mendeley ARFF Veri Seti yükleniyor...")


# Dosyanın tam yolunu dinamik olarak buluyoruz (Spagetti kodu engellemek için en güvenli yol)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
dosya_adi = os.path.join(BASE_DIR, 'Mendeley_dataset', 'Phishing_Legitimate_full.arff')
data, meta = arff.loadarff(dosya_adi)
df = pd.DataFrame(data)

# ÖNEMLİ: ARFF formatında kategorik veriler "byte" (b'1', b'-1') olarak gelebiliyor.
# Yapay zeka algoritmalarının kafası karışmasın diye hepsini float'a (sayıya) çeviriyoruz.
for col in df.select_dtypes(['object']).columns:
    df[col] = df[col].apply(lambda x: x.decode('utf-8') if isinstance(x, bytes) else x).astype(float)

# Veri setinde 'id' kolonu varsa modelin bunu bir kural sanmaması için siliyoruz
if 'id' in df.columns:
    df = df.drop('id', axis=1)

print("2. Veriler ayrıştırılıyor ve ölçeklendiriliyor...")
# Hedef kolonu belirliyoruz (Genelde en son kolondur, adı 'CLASS_LABEL' olabilir)
hedef_kolon = df.columns[-1] 
X = df.drop(hedef_kolon, axis=1)
y = df[hedef_kolon]

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 48 farklı özelliği aynı matematiğe çekmek için StandardScaler kullanıyoruz
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

print("\n3. Ağır Toplar Sahaya Sürülüyor! Modeller eğitiliyor...\n")
models = {
    "Random Forest": RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1),
    "Gradient Boosting": GradientBoostingClassifier(n_estimators=100, random_state=42),
    "XGBoost": XGBClassifier(eval_metric='logloss', random_state=42, n_jobs=-1)
}

best_model = None
best_accuracy = 0
best_model_name = ""

for name, model in models.items():
    print(f"[{name}] çalışıyor...")
    model.fit(X_train_scaled, y_train)
    y_pred = model.predict(X_test_scaled)
    
    acc = accuracy_score(y_test, y_pred)
    print(f"-> {name} Başarı Oranı: % {acc * 100:.2f}\n")
    
    if acc > best_accuracy:
        best_accuracy = acc
        best_model = model
        best_model_name = name

print("-" * 50)
print(f"🏆 ŞAMPİYON MODEL: {best_model_name} (Başarı: % {best_accuracy * 100:.2f})")
print("-" * 50)

print("\n4. Şampiyon Model ve Scaler API için kaydediliyor...")
joblib.dump(best_model, 'phishcatch_champion_model.pkl')
joblib.dump(scaler, 'phishcatch_scaler.pkl')

print("5. Özellik Analizi (Feature Importance) Çizdiriliyor...")
importances = best_model.feature_importances_
indices = np.argsort(importances)[::-1]
top_features = 15

plt.figure(figsize=(12, 8))
plt.title(f"{best_model_name} - Phishing Tespitinde En Etkili 15 Özellik")
plt.bar(range(top_features), importances[indices][:top_features], align="center", color='darkred')
plt.xticks(range(top_features), [X.columns[i] for i in indices[:top_features]], rotation=45, ha='right')
plt.tight_layout()
plt.savefig('feature_importance.png')

print("İşlem Tamam! 'feature_importance.png' dosyasını inceleyebilirsiniz.")