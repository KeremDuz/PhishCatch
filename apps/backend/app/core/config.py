import os
from pathlib import Path
from pydantic import BaseModel, Field
from dotenv import load_dotenv


BACKEND_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(BACKEND_ROOT / ".env")

DEFAULT_CORS_ALLOWED_ORIGINS = (
    "http://localhost:3000,"
    "http://localhost:5173,"
    "http://localhost:8000,"
    "http://localhost:8080,"
    "http://127.0.0.1:3000,"
    "http://127.0.0.1:5173,"
    "http://127.0.0.1:8000,"
    "http://127.0.0.1:8080"
)


def _csv_env(name: str, default: str) -> list[str]:
    return [value.strip() for value in os.getenv(name, default).split(",") if value.strip()]


class Settings(BaseModel):
    app_name: str = "PhishCatch Backend"
    app_version: str = "1.0.0"
    cors_allowed_origins: list[str] = Field(
        default_factory=lambda: _csv_env("CORS_ALLOWED_ORIGINS", DEFAULT_CORS_ALLOWED_ORIGINS)
    )

    virustotal_api_key: str | None = Field(default_factory=lambda: os.getenv("VIRUSTOTAL_API_KEY"))
    virustotal_timeout_seconds: int = int(os.getenv("VIRUSTOTAL_TIMEOUT_SECONDS", "10"))

    google_safe_browsing_api_key: str | None = Field(default_factory=lambda: os.getenv("GOOGLE_SAFE_BROWSING_API_KEY"))

    ml_model_path: str = os.getenv("ML_MODEL_PATH", "phishcatch_url_model.pkl")
    ml_scaler_path: str | None = Field(default_factory=lambda: os.getenv("ML_SCALER_PATH") or None)
    ml_malicious_threshold: float = float(os.getenv("ML_MALICIOUS_THRESHOLD", "0.5"))
    ml_confident_malicious_threshold: float = float(os.getenv("ML_CONFIDENT_MALICIOUS_THRESHOLD", "0.95"))
    ml_confident_clean_threshold: float = float(os.getenv("ML_CONFIDENT_CLEAN_THRESHOLD", "0.15"))

    urlhaus_auth_key: str | None = Field(default_factory=lambda: os.getenv("URLHAUS_AUTH_KEY"))


settings = Settings()
