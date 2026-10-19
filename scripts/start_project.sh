#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
API_BASE_URL="${PHISHCATCH_API_BASE_URL:-http://localhost:8001}"
DETACHED=0
SKIP_FLUTTER_BUILD=0

usage() {
  cat <<'EOF'
Usage: scripts/start_project.sh [--detached] [--skip-flutter-build]

Builds the Flutter web bundle, builds Docker images, and starts backend + frontend.

Environment:
  PHISHCATCH_API_BASE_URL  Browser-facing backend URL. Default: http://localhost:8001

Options:
  --detached            Run docker compose in the background.
  --skip-flutter-build  Reuse the existing apps/flutter_app/build/web output.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --detached|-d)
      DETACHED=1
      shift
      ;;
    --skip-flutter-build)
      SKIP_FLUTTER_BUILD=1
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ ! -f "${ROOT_DIR}/apps/backend/.env" ]]; then
  echo "Missing apps/backend/.env. This project expects the real apps/backend/.env file to be present." >&2
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is not installed or not available in PATH." >&2
  exit 1
fi

if docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE=(docker-compose)
else
  echo "Docker Compose is not installed." >&2
  exit 1
fi

cd "${ROOT_DIR}"

if [[ "${SKIP_FLUTTER_BUILD}" -eq 0 ]]; then
  echo "Building Flutter web bundle with PHISHCATCH_API_BASE_URL=${API_BASE_URL}"
  PHISHCATCH_API_BASE_URL="${API_BASE_URL}" scripts/build_flutter_web.sh
else
  if [[ ! -f "${ROOT_DIR}/apps/flutter_app/build/web/index.html" ]]; then
    echo "apps/flutter_app/build/web is missing. Run without --skip-flutter-build first." >&2
    exit 1
  fi
  echo "Skipping Flutter build; reusing apps/flutter_app/build/web"
fi

echo "Starting Docker services..."
if [[ "${DETACHED}" -eq 1 ]]; then
  "${COMPOSE[@]}" up --build -d
  echo "Frontend: http://localhost:8080"
  echo "Backend health: http://localhost:8001/health"
  echo "Logs: docker compose logs -f"
else
  "${COMPOSE[@]}" up --build
fi
