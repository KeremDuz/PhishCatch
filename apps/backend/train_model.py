import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib

print("1. Veri seti yükleniyor...")
# Az önce oluşturduğumuz dosyayı okuyoruz
df = pd.read_csv('phishcatch_training_data.csv')

# Eksik veya hatalı satırları (NaN) temizliyoruz ki model hata vermesin
df = df.dropna()

print("2. Veriler eğitim ve test olarak ayrılıyor...")
# 'result' kolonu bizim etiketimiz (0: Temiz, 1: Phishing)
# Geri kalan tüm kolonlar ise özelliklerimiz (X)
X = df.drop('result', axis=1)
y = df['result']

# Verinin %80'ini eğitime, %20'sini test etmeye ayırıyoruz
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

print("3. Random Forest Modeli eğitiliyor... (Bu biraz sürebilir)")
# 100 karar ağacından oluşan bir model kuruyoruz
model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
model.fit(X_train, y_train)

print("4. Model test ediliyor...")
# Modelin daha önce hiç görmediği %20'lik test verisiyle tahmin yaptırıyoruz
y_pred = model.predict(X_test)

# Sonuçları hesaplıyoruz
accuracy = accuracy_score(y_test, y_pred)
print(f"\nModel Başarı Oranı (Accuracy): % {accuracy * 100:.2f}")
print("\nDetaylı Sınıflandırma Raporu:")
print(classification_report(y_test, y_pred, target_names=['Temiz (0)', 'Zararlı (1)']))

print("\n5. Model kaydediliyor...")
# Eğitilmiş modeli daha sonra API'de kullanmak üzere diske kaydediyoruz
joblib.dump(model, 'phishcatch_rf_model.pkl')
print("İşlem tamam! 'phishcatch_rf_model.pkl' dosyası başarıyla oluşturuldu.")