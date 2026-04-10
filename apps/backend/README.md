# PhishCatch Backend

FastAPI tabanlı hibrit phishing tarama servisi.

## Endpointler

### `POST /api/v1/scan/fast`
Tier-1 hızlı tarama (VirusTotal).

**Request**

```json
{
  "url": "example.com"
}
```

**Response (örnek)**

```json
{
  "url": "https://example.com",
  "original_input": "example.com",
  "normalized_url": "https://example.com",
  "tier": "tier1_virustotal",
  "status": "safe",
  "risk_score": 0.0,
  "reason": "VirusTotal shows clean/unrated result."
}
```

### `POST /api/v1/scan/deep`
Tier-2 derin tarama (HTML özellik çıkarımı + scaler + XGBoost).

**Request**

```json
{
  "url": "https://example.com"
}
```

**Response (örnek)**

```json
{
  "url": "https://example.com",
  "original_input": "https://example.com",
  "normalized_url": "https://example.com",
  "tier": "tier2_ml_deep",
  "status": "unknown",
  "risk_score": 0.0,
  "malicious_probability": 0.0,
  "confidence": 0.0,
  "model_name": "xgboost",
  "html_fetched": false,
  "error": "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed"
}
```

## Çevresel Değişkenler

- `VIRUSTOTAL_API_KEY`: VT API key.
- `VIRUSTOTAL_TIMEOUT_SECONDS`: Fast scan timeout (varsayılan `10`).
- `ML_CHAMPION_MODEL_PATH`: Model dosya yolu (varsayılan `phishcatch_champion_model.pkl`).
- `ML_SCALER_PATH`: Scaler dosya yolu (varsayılan `phishcatch_scaler.pkl`).
- `ML_MALICIOUS_THRESHOLD`: Malicious karar eşiği (varsayılan `0.5`).
- `HTML_FETCH_TIMEOUT_SECONDS`: Deep scan HTML fetch timeout (varsayılan `4`).
- `HTML_FETCH_VERIFY_SSL`: SSL doğrulama (`true/false`, varsayılan `true`).
- `HTML_FETCH_CA_BUNDLE_PATH`: Özel CA bundle yolu. Doluysa SSL verify için bu yol kullanılır.

## Çalıştırma

```bash
cd /home/keremduz/Phishing_detection_system/apps/backend
source ../../.venv/bin/activate
uvicorn app.main:app --reload --port 8001
```
