from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.main import app, health


def main() -> int:
    route_paths = {getattr(route, "path", None) for route in app.routes}
    required_routes = {"/health", "/api/v1/analyze"}
    missing_routes = sorted(required_routes - route_paths)

    if missing_routes:
        print("Missing routes:", ", ".join(missing_routes))
        return 1

    health_payload = health()
    if health_payload != {"status": "ok"}:
        print("Unexpected health payload:", health_payload)
        return 1

    print("FastAPI app sanity check passed")
    print("Routes:", ", ".join(sorted(required_routes)))
    print("Health:", health_payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
