#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

APP_PREFIX="${APP_PREFIX:-phishcatch}"
LOCATION="${AZURE_LOCATION:-westeurope}"
RESOURCE_GROUP="${AZURE_RESOURCE_GROUP:-${APP_PREFIX}-rg}"
ENVIRONMENT="${AZURE_CONTAINERAPPS_ENV:-${APP_PREFIX}-env}"
BACKEND_APP="${AZURE_BACKEND_APP:-${APP_PREFIX}-api}"
FRONTEND_APP="${AZURE_FRONTEND_APP:-${APP_PREFIX}-web}"
ACR_NAME="${AZURE_ACR_NAME:-}"

BACKEND_IMAGE="${BACKEND_APP}:latest"
FRONTEND_IMAGE="${FRONTEND_APP}:latest"

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

require_command az
require_command flutter

echo "Using resource group: ${RESOURCE_GROUP}"
echo "Using location: ${LOCATION}"

retry() {
  local attempt=1
  local max_attempts=3
  local delay_seconds=20

  until "$@"; do
    local status=$?
    if (( attempt >= max_attempts )); then
      return "${status}"
    fi
    echo "Command failed on attempt ${attempt}/${max_attempts}; retrying in ${delay_seconds}s: $*"
    sleep "${delay_seconds}"
    attempt=$((attempt + 1))
  done
}

build_image() {
  local image_name="$1"
  local dockerfile="$2"
  local context_dir="$3"
  local full_image_name="${ACR_LOGIN_SERVER}/${image_name}"

  echo "Building ${image_name} with ACR Tasks..."
  if retry az acr build \
    --registry "${ACR_NAME}" \
    --image "${image_name}" \
    --file "${dockerfile}" \
    "${context_dir}"; then
    return 0
  fi

  echo "ACR Tasks upload failed; falling back to local Docker build and push..."
  require_command docker
  az acr login --name "${ACR_NAME}" || \
    echo "${ACR_PASSWORD}" | docker login "${ACR_LOGIN_SERVER}" --username "${ACR_USERNAME}" --password-stdin
  docker build -t "${full_image_name}" -f "${dockerfile}" "${context_dir}"
  retry docker push "${full_image_name}"
}

az group create \
  --name "${RESOURCE_GROUP}" \
  --location "${LOCATION}" \
  --output table

az extension add --name containerapp --upgrade --output none
az provider register --namespace Microsoft.ContainerRegistry --wait
az provider register --namespace Microsoft.App --wait
az provider register --namespace Microsoft.OperationalInsights --wait

if [[ -z "${ACR_NAME}" ]]; then
  ACR_NAME="$(az acr list --resource-group "${RESOURCE_GROUP}" --query "[0].name" -o tsv 2>/dev/null || true)"
  if [[ -z "${ACR_NAME}" || "${ACR_NAME}" == "None" ]]; then
    ACR_NAME="${APP_PREFIX}${RANDOM}${RANDOM}"
  fi
fi

echo "Using ACR: ${ACR_NAME}"

if az acr show --name "${ACR_NAME}" --resource-group "${RESOURCE_GROUP}" >/dev/null 2>&1; then
  echo "Using existing Azure Container Registry: ${ACR_NAME}"
else
  az acr create \
    --resource-group "${RESOURCE_GROUP}" \
    --name "${ACR_NAME}" \
    --sku Basic \
    --admin-enabled true \
    --output table
fi

if az containerapp env show --name "${ENVIRONMENT}" --resource-group "${RESOURCE_GROUP}" >/dev/null 2>&1; then
  echo "Using existing Container Apps environment: ${ENVIRONMENT}"
else
  az containerapp env create \
    --name "${ENVIRONMENT}" \
    --resource-group "${RESOURCE_GROUP}" \
    --location "${LOCATION}" \
    --output table
fi

ACR_LOGIN_SERVER="$(az acr show --name "${ACR_NAME}" --query loginServer -o tsv)"
ACR_USERNAME="$(az acr credential show --name "${ACR_NAME}" --query username -o tsv)"
ACR_PASSWORD="$(az acr credential show --name "${ACR_NAME}" --query passwords[0].value -o tsv)"

echo "Building backend image in ACR..."
build_image "${BACKEND_IMAGE}" "${ROOT_DIR}/apps/backend/Dockerfile" "${ROOT_DIR}/apps/backend"

if az containerapp show --name "${BACKEND_APP}" --resource-group "${RESOURCE_GROUP}" >/dev/null 2>&1; then
  echo "Updating backend Container App..."
  az containerapp update \
    --name "${BACKEND_APP}" \
    --resource-group "${RESOURCE_GROUP}" \
    --image "${ACR_LOGIN_SERVER}/${BACKEND_IMAGE}" \
    --min-replicas 0 \
    --max-replicas 1 \
    --set-env-vars \
      PORT=8000 \
      CORS_ALLOWED_ORIGINS='*' \
      HTML_BROWSER_RENDER_ENABLED=0 \
      SCANNER_CACHE_ENABLED=1 \
      SCANNER_CACHE_TTL_SECONDS=900 \
    --output table
else
  echo "Creating backend Container App..."
  az containerapp create \
    --name "${BACKEND_APP}" \
    --resource-group "${RESOURCE_GROUP}" \
    --environment "${ENVIRONMENT}" \
    --image "${ACR_LOGIN_SERVER}/${BACKEND_IMAGE}" \
    --registry-server "${ACR_LOGIN_SERVER}" \
    --registry-username "${ACR_USERNAME}" \
    --registry-password "${ACR_PASSWORD}" \
    --target-port 8000 \
    --ingress external \
    --cpu 1.0 \
    --memory 2Gi \
    --min-replicas 0 \
    --max-replicas 1 \
    --env-vars \
      PORT=8000 \
      CORS_ALLOWED_ORIGINS='*' \
      HTML_BROWSER_RENDER_ENABLED=0 \
      SCANNER_CACHE_ENABLED=1 \
      SCANNER_CACHE_TTL_SECONDS=900 \
    --query properties.configuration.ingress.fqdn \
    -o tsv
fi

BACKEND_FQDN="$(az containerapp show --name "${BACKEND_APP}" --resource-group "${RESOURCE_GROUP}" --query properties.configuration.ingress.fqdn -o tsv)"
BACKEND_URL="https://${BACKEND_FQDN}"

if [[ -n "${VIRUSTOTAL_API_KEY:-}" || -n "${GOOGLE_SAFE_BROWSING_API_KEY:-}" || -n "${URLHAUS_AUTH_KEY:-}" ]]; then
  echo "Configuring optional reputation API secrets..."
  secret_args=()
  env_args=()
  if [[ -n "${VIRUSTOTAL_API_KEY:-}" ]]; then
    secret_args+=("virustotal-api-key=${VIRUSTOTAL_API_KEY}")
    env_args+=("VIRUSTOTAL_API_KEY=secretref:virustotal-api-key")
  fi
  if [[ -n "${GOOGLE_SAFE_BROWSING_API_KEY:-}" ]]; then
    secret_args+=("google-safe-browsing-api-key=${GOOGLE_SAFE_BROWSING_API_KEY}")
    env_args+=("GOOGLE_SAFE_BROWSING_API_KEY=secretref:google-safe-browsing-api-key")
  fi
  if [[ -n "${URLHAUS_AUTH_KEY:-}" ]]; then
    secret_args+=("urlhaus-auth-key=${URLHAUS_AUTH_KEY}")
    env_args+=("URLHAUS_AUTH_KEY=secretref:urlhaus-auth-key")
  fi
  az containerapp secret set \
    --name "${BACKEND_APP}" \
    --resource-group "${RESOURCE_GROUP}" \
    --secrets "${secret_args[@]}"
  az containerapp update \
    --name "${BACKEND_APP}" \
    --resource-group "${RESOURCE_GROUP}" \
    --set-env-vars "${env_args[@]}" \
    --output table
fi

echo "Building Flutter web locally for backend URL: ${BACKEND_URL}"
(
  cd "${ROOT_DIR}/apps/flutter_app"
  flutter pub get
  flutter build web --release \
    --dart-define="PHISHCATCH_API_BASE_URL=${BACKEND_URL}"
)

echo "Building frontend nginx image in ACR..."
build_image "${FRONTEND_IMAGE}" "${ROOT_DIR}/apps/flutter_app/Dockerfile" "${ROOT_DIR}/apps/flutter_app"

if az containerapp show --name "${FRONTEND_APP}" --resource-group "${RESOURCE_GROUP}" >/dev/null 2>&1; then
  echo "Updating frontend Container App..."
  az containerapp update \
    --name "${FRONTEND_APP}" \
    --resource-group "${RESOURCE_GROUP}" \
    --image "${ACR_LOGIN_SERVER}/${FRONTEND_IMAGE}" \
    --min-replicas 0 \
    --max-replicas 1 \
    --output table
else
  echo "Creating frontend Container App..."
  az containerapp create \
    --name "${FRONTEND_APP}" \
    --resource-group "${RESOURCE_GROUP}" \
    --environment "${ENVIRONMENT}" \
    --image "${ACR_LOGIN_SERVER}/${FRONTEND_IMAGE}" \
    --registry-server "${ACR_LOGIN_SERVER}" \
    --registry-username "${ACR_USERNAME}" \
    --registry-password "${ACR_PASSWORD}" \
    --target-port 80 \
    --ingress external \
    --cpu 0.25 \
    --memory 0.5Gi \
    --min-replicas 0 \
    --max-replicas 1 \
    --query properties.configuration.ingress.fqdn \
    -o tsv
fi

FRONTEND_FQDN="$(az containerapp show --name "${FRONTEND_APP}" --resource-group "${RESOURCE_GROUP}" --query properties.configuration.ingress.fqdn -o tsv)"
FRONTEND_URL="https://${FRONTEND_FQDN}"

echo "Locking backend CORS to frontend origin..."
az containerapp update \
  --name "${BACKEND_APP}" \
  --resource-group "${RESOURCE_GROUP}" \
  --set-env-vars "CORS_ALLOWED_ORIGINS=${FRONTEND_URL}" \
  --output table

cat <<SUMMARY

Deployment complete.

Backend:  ${BACKEND_URL}
Frontend: ${FRONTEND_URL}

Health check:
  curl ${BACKEND_URL}/health

Cost tip:
  Both apps are set to min replicas 0 and max replicas 1.
SUMMARY
