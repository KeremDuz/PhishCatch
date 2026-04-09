from pathlib import Path
import sys

from fastapi.testclient import TestClient

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.main import app


if __name__ == "__main__":
    client = TestClient(app)

    health_response = client.get("/health")
    print("/health ->", health_response.status_code, health_response.json())

    analyze_response = client.post(
        "/api/v1/analyze",
        json={"url": "https://secure-login-example.com/verify-account"},
    )
    print("/api/v1/analyze ->", analyze_response.status_code)
    print(analyze_response.json())
