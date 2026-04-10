import os
from pathlib import Path
from pydantic import BaseModel, Field
from dotenv import load_dotenv


BACKEND_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(BACKEND_ROOT / ".env")


def _parse_env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


class Settings(BaseModel):
    app_name: str = "PhishCatch Backend"
    app_version: str = "1.0.0"

    virustotal_api_key: str | None = Field(default_factory=lambda: os.getenv("VIRUSTOTAL_API_KEY"))
    virustotal_timeout_seconds: int = int(os.getenv("VIRUSTOTAL_TIMEOUT_SECONDS", "10"))

    ml_champion_model_path: str = os.getenv("ML_CHAMPION_MODEL_PATH", "phishcatch_champion_model.pkl")
    ml_scaler_path: str = os.getenv("ML_SCALER_PATH", "phishcatch_scaler.pkl")
    ml_malicious_threshold: float = float(os.getenv("ML_MALICIOUS_THRESHOLD", "0.5"))
    html_fetch_timeout_seconds: float = float(os.getenv("HTML_FETCH_TIMEOUT_SECONDS", "4"))
    html_fetch_verify_ssl: bool = _parse_env_bool("HTML_FETCH_VERIFY_SSL", True)
    html_fetch_ca_bundle_path: str | None = os.getenv("HTML_FETCH_CA_BUNDLE_PATH")


settings = Settings()
