# PhishCatch

FastAPI tabanlı URL phishing analiz servisi ve Flutter tabanlı web/mobil istemci.

## Backend Akışı

1. `UrlResolverScanner`: Redirect zincirini güvenli şekilde çözer.
2. `WhoisScanner`: Domain yaşını kontrol eder.
3. `URLhausScanner`: Bilinen zararlı URL veritabanını sorgular.
4. `GoogleSafeBrowsingScanner`: API key varsa Google Safe Browsing sorgular.
5. `VirusTotalScanner`: API key/key listesi varsa VirusTotal sorgular; 429 limitinde sıradaki key'e geçer.
6. `MLModelScanner`: Yeni modeller için URL-only lexical feature şeması kullanır; eski 48-feature ve legacy 16-feature artifact'leri de uyumluluk için desteklenir.
7. `HtmlScraperScanner`: DOM/form/JS sinyallerini inceler.
8. `RiskAggregator`: Tüm sinyalleri birleştirip kullanıcıya `malicious`, `clean` veya `unknown` sonucu döndürür.

URL fetch eden scanner'lar localhost/private/reserved IP hedeflerini engeller ve redirect'leri manuel takip eder.
Bu tip güvenli olmayan hedefler üçüncü taraf reputation servislerine de gönderilmez; ilgili stage'ler `skipped` olarak raporlanır.
Tekil scanner'lar artık final kararı erken kesmez; WHOIS gibi zayıf sinyaller risk puanına katkı yapar, URLhaus/Google Safe Browsing/VirusTotal gibi güçlü reputation kaynakları daha yüksek ağırlık alır.

## Kurulum

```bash
cd /home/keremduz/Phishing_detection_system
source .venv/bin/activate
pip install -r apps/backend/requirements.txt
```

Backend gerçek ayarları `apps/backend/.env` dosyasından okur. Projeyi zip ile paylaşırken bu dosyanın klasörde kaldığından emin olun.

VirusTotal için tek key hâlâ desteklenir, çoklu key için virgülle ayrılmış liste verilebilir:

```bash
VIRUSTOTAL_API_KEY=ilk_key
VIRUSTOTAL_API_KEYS=ikinci_key,ucuncu_key
```

Numaralı key formatı da desteklenir:

```bash
VIRUSTOTAL_API_KEY1=ilk_key
VIRUSTOTAL_API_KEY2=ikinci_key
VIRUSTOTAL_API_KEY3=ucuncu_key
VIRUSTOTAL_API_KEY4=dorduncu_key
VIRUSTOTAL_API_KEY5=besinci_key
VIRUSTOTAL_API_KEY6=altinci_key
VIRUSTOTAL_API_KEY7=yedinci_key
```

Değişkenler birlikte kullanılırsa sistem önce `VIRUSTOTAL_API_KEY`, sonra `VIRUSTOTAL_API_KEYS`, sonra `VIRUSTOTAL_API_KEY1`, `VIRUSTOTAL_API_KEY2` şeklinde sırayla dener.

## Çalıştırma

```bash
cd /home/keremduz/Phishing_detection_system/apps/backend
source ../../.venv/bin/activate
uvicorn app.main:app --reload --port 8001
```

## Docker

Backend ve Flutter web'i tek komutla ayağa kaldırmak için:

```bash
cd /home/keremduz/Phishing_detection_system
scripts/start_project.sh
```

- Frontend: `http://localhost:8080`
- Backend health: `http://localhost:8001/health`

Arka planda çalıştırmak için:

```bash
scripts/start_project.sh --detached
```

Script önce Flutter web build'ini `PHISHCATCH_API_BASE_URL=http://localhost:8001` ile üretir, sonra Docker Compose ile backend ve frontend konteynerlerini build edip başlatır. Backend konteyneri `apps/backend/.env` dosyasını runtime'da okur; VirusTotal/Google/API key değerleri imaja gömülmez.

Tekil imajlar:

```bash
docker build -t phishcatch-backend:local apps/backend
PHISHCATCH_API_BASE_URL=http://localhost:8001 scripts/build_flutter_web.sh
docker build -t phishcatch-frontend:local apps/flutter_app
```

Azure Container Apps deploy adımları için: `apps/backend/DEPLOY_AZURE.md`.

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

API yanıtında `final_verdict`, `risk_score`, `confidence`, `summary`, `signals` ve scanner bazlı `stages` bulunur. Uygulama tarafında kullanıcıya `final_verdict` gösterilmeli; debug veya açıklama ekranı için `summary/signals/stages` kullanılabilir.

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

`Mendeley_dataset/`, generated CSV sonuçları, `.venv/`, `apps/flutter_app/.dart_tool/` ve `apps/flutter_app/build/` yerel/üretilen artifact olarak görülmelidir. Proje zip ile paylaşılacaksa gerçek `apps/backend/.env` ve çalışan model dosyaları klasörde kalmalı; büyük eğitim veri seti ve sanal ortam zip dışında bırakılmalıdır.
