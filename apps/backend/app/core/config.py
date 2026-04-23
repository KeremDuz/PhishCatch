import os
from pathlib import Path
from pydantic import BaseModel, Field
from dotenv import load_dotenv


BACKEND_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(BACKEND_ROOT / ".env")


class Settings(BaseModel):
    app_name: str = "PhishCatch Backend"
    app_version: str = "1.0.0"

    virustotal_api_key: str | None = Field(default_factory=lambda: os.getenv("VIRUSTOTAL_API_KEY"))
    virustotal_timeout_seconds: int = int(os.getenv("VIRUSTOTAL_TIMEOUT_SECONDS", "10"))

    google_safe_browsing_api_key: str | None = Field(default_factory=lambda: os.getenv("GOOGLE_SAFE_BROWSING_API_KEY"))

    ml_model_path: str = os.getenv("ML_MODEL_PATH", "phishcatch_rf_model.pkl")
    ml_malicious_threshold: float = float(os.getenv("ML_MALICIOUS_THRESHOLD", "0.5"))

    urlhaus_auth_key: str | None = Field(default_factory=lambda: os.getenv("URLHAUS_AUTH_KEY"))


settings = Settings()
