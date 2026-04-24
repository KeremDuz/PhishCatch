# PhishCatch

FastAPI tabanlı URL phishing analiz servisi. Repo şu an sürüm takibinde backend odaklıdır; `apps/flutter_app/` yerelde bulunabilir ama `.gitignore` ile dışarıda bırakılmıştır.

## Backend Akışı

1. `UrlResolverScanner`: Redirect zincirini güvenli şekilde çözer.
2. `WhoisScanner`: Domain yaşını kontrol eder.
3. `URLhausScanner`: Bilinen zararlı URL veritabanını sorgular.
4. `GoogleSafeBrowsingScanner`: API key varsa Google Safe Browsing sorgular.
5. `VirusTotalScanner`: API key varsa VirusTotal sorgular.
6. `MLModelScanner`: Yeni modeller için URL-only lexical feature şeması kullanır; eski 48-feature ve legacy 16-feature artifact'leri de uyumluluk için desteklenir.
7. `HtmlScraperScanner`: ML kararsızsa DOM/form/JS sinyallerini inceler.

URL fetch eden scanner'lar localhost/private/reserved IP hedeflerini engeller ve redirect'leri manuel takip eder.

## Kurulum

```bash
cd /home/keremduz/Phishing_detection_system
source .venv/bin/activate
pip install -r apps/backend/requirements.txt
```

Backend `.env` için başlangıç dosyası:

```bash
cp apps/backend/.env.example apps/backend/.env
```

## Çalıştırma

```bash
cd /home/keremduz/Phishing_detection_system/apps/backend
source ../../.venv/bin/activate
uvicorn app.main:app --reload --port 8001
```

## Hızlı Kontrol

Bu smoke test gerçek internet çağrısı veya model tahmini yapmaz; sadece FastAPI app import, route ve health fonksiyonunu kontrol eder.

```bash
cd /home/keremduz/Phishing_detection_system/apps/backend
source ../../.venv/bin/activate
python scripts/smoke_test_fastapi.py
```

Tüm lokal kalite kontrolleri için:

```bash
bash scripts/quality_check.sh
```

## URL Analizi

```bash
cd /home/keremduz/Phishing_detection_system/apps/backend
source ../../.venv/bin/activate
python scripts/check_url.py -u "https://example.com"
```

## Model Eğitimi

```bash
cd /home/keremduz/Phishing_detection_system/apps/backend
source ../../.venv/bin/activate
python feature_extractor.py
python train_model.py
```

Varsayılan eğitim artık sadece URL'den görülebilen lexical feature'ları üretir. Site içeriği, form alanları, iframe ve JavaScript sinyalleri ML feature setinde değil, `HtmlScraperScanner` katmanında değerlendirilir.

`feature_extractor.py`, varsayılan olarak `phishcatch_training_data_url.csv` üretir. Eski 48 kolonlu uyumluluk datası gerektiğinde:

```bash
python feature_extractor.py --schema mendeley48
```

`train_model.py`, `StandardScaler + RandomForestClassifier` içeren tek bir sklearn pipeline artifact'i üretir: `phishcatch_url_model.pkl`.

Eski ayrık artifact seti kullanılıyorsa `.env` içinde `ML_MODEL_PATH=phishcatch_rf_model_48.pkl` ve `ML_SCALER_PATH=phishcatch_scaler_48.pkl` birlikte verilmelidir. Yeni pipeline artifact yeniden üretildikten sonra `ML_SCALER_PATH` boş bırakılabilir.

## Yerel Artifact Notları

`Mendeley_dataset/`, `.pkl` model dosyaları, generated CSV sonuçları, `.venv/` ve `apps/flutter_app/` git dışında bırakılmıştır. Büyük veri/model dosyaları paylaşılacaksa Git yerine artifact storage, DVC veya Git LFS tercih edilmeli. Detaylar: `docs/artifacts.md`.
