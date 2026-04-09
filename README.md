# PhishCatch Monorepo

Bu repo artık monorepo düzeninde yapılandırılmıştır.

## Klasör Yapısı

- `apps/backend/`: FastAPI backend ve ML pipeline
- `apps/web/`: Web frontend (placeholder)
- `apps/mobile/`: Mobile app (placeholder)
- `shared/`: Ortak şema/helper alanı (opsiyonel)
- `infra/`: Deploy/infra dosyaları (opsiyonel)
- `docs/`: Süreç ve teknik dokümantasyon

## Backend Mimari Özeti

- `Tier 1`: `VirusTotalScanner`
- `Tier 2`: `MLModelScanner`
- Zincir yürütümü: `apps/backend/app/core/pipeline.py`

## Backend Kurulum

```bash
cd /home/keremduz/Phishing_detection_system
source .venv/bin/activate
pip install -r apps/backend/requirements.txt
```

## Backend Çalıştırma

```bash
cd /home/keremduz/Phishing_detection_system/apps/backend
source ../../.venv/bin/activate
uvicorn app.main:app --reload --port 8001
```

## Backend Smoke Test

```bash
cd /home/keremduz/Phishing_detection_system/apps/backend
source ../../.venv/bin/activate
python scripts/smoke_test_fastapi.py
```

## CLI ile URL Testi

```bash
cd /home/keremduz/Phishing_detection_system/apps/backend
source ../../.venv/bin/activate
python scripts/check_url.py -u "https://example.com"
```

## Branch Akışı (Özet)

- `main`: stabil/prod
- `develop`: entegrasyon branch'i
- `feature/*`: yeni özellikler
- `release/*`: sürüm hazırlığı
- `hotfix/*`: acil prod düzeltmeleri
