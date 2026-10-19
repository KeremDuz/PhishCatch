#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
API_BASE_URL="${PHISHCATCH_API_BASE_URL:-http://localhost:8001}"

cd "${ROOT_DIR}/apps/flutter_app"

flutter pub get
flutter build web --release \
  --dart-define="PHISHCATCH_API_BASE_URL=${API_BASE_URL}"

echo "Flutter web build ready at apps/flutter_app/build/web"
