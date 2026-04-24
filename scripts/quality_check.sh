#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-$ROOT_DIR/.venv/bin/python}"

if [[ ! -x "$PYTHON_BIN" ]]; then
  PYTHON_BIN="python"
fi

echo "== Backend compile =="
"$PYTHON_BIN" -m compileall -q \
  "$ROOT_DIR/apps/backend/app" \
  "$ROOT_DIR/apps/backend/feature_extractor.py" \
  "$ROOT_DIR/apps/backend/train_model.py" \
  "$ROOT_DIR/apps/backend/scripts/smoke_test_fastapi.py"

echo "== Backend tests =="
(
  cd "$ROOT_DIR/apps/backend"
  "$PYTHON_BIN" -m unittest discover -s tests -p 'test_*.py'
)

echo "== Backend smoke =="
"$PYTHON_BIN" "$ROOT_DIR/apps/backend/scripts/smoke_test_fastapi.py"

if [[ -d "$ROOT_DIR/apps/flutter_app" ]] && command -v flutter >/dev/null 2>&1; then
  echo "== Flutter analyze =="
  (
    cd "$ROOT_DIR/apps/flutter_app"
    flutter analyze
  )
else
  echo "== Flutter analyze skipped =="
  echo "Flutter app directory or flutter command was not found."
fi
