# Azure Container Apps Deployment

This project deploys best as two containers:

- `phishcatch-api`: FastAPI backend with the local ML artifacts.
- `phishcatch-web`: Flutter web release build served by nginx.

Use Azure Container Apps instead of App Service Free tier. The backend image includes a large `phishcatch_url_model.pkl` artifact, so start with `1 CPU / 2 GiB` and keep `min replicas = 0` while using free credit casually.

Azure's free account credit is temporary, so create a budget alert in Cost Management and delete the resource group after demos.

References:

- Azure Container Apps ingress: https://learn.microsoft.com/azure/container-apps/ingress-overview
- ACR quick build tasks: https://learn.microsoft.com/azure/container-registry/container-registry-tutorial-quick-task
- Container Apps environment variables and secrets: https://learn.microsoft.com/azure/container-apps/environment-variables

## Local Docker Smoke Test

From the repository root:

```bash
PHISHCATCH_API_BASE_URL=http://localhost:8001 scripts/build_flutter_web.sh
docker compose up --build
```

Then open:

- Frontend: http://localhost:8080
- Backend health: http://localhost:8001/health

The compose file builds Flutter with:

```text
PHISHCATCH_API_BASE_URL=http://localhost:8001
```

## Azure One-Command Deploy

Install/login first:

```bash
az login
```

Optional reputation API keys can be exported before deploy:

```bash
export VIRUSTOTAL_API_KEY="..."
export GOOGLE_SAFE_BROWSING_API_KEY="..."
export URLHAUS_AUTH_KEY="..."
```

Run from the repository root:

```bash
scripts/deploy_azure_container_apps.sh
```

Optional overrides:

```bash
AZURE_LOCATION=westeurope \
AZURE_RESOURCE_GROUP=phishcatch-rg \
AZURE_ACR_NAME=phishcatch12345 \
scripts/deploy_azure_container_apps.sh
```

The script:

1. Creates a resource group.
2. Creates a Basic Azure Container Registry.
3. Creates a Container Apps environment.
4. Builds/pushes the backend image with ACR Tasks.
5. Creates the backend Container App.
6. Reads the backend FQDN.
7. Builds Flutter web locally with `PHISHCATCH_API_BASE_URL=https://<backend-fqdn>`.
8. Builds/pushes a small nginx frontend image with ACR Tasks.
9. Creates the frontend Container App.
10. Updates backend CORS to the frontend origin.

## Manual Cost Controls

Keep both apps scaled down when idle:

```bash
az containerapp update \
  --name phishcatch-api \
  --resource-group phishcatch-rg \
  --min-replicas 0 \
  --max-replicas 1

az containerapp update \
  --name phishcatch-web \
  --resource-group phishcatch-rg \
  --min-replicas 0 \
  --max-replicas 1
```

For demos where first request latency matters, temporarily set backend min replicas to 1:

```bash
az containerapp update \
  --name phishcatch-api \
  --resource-group phishcatch-rg \
  --min-replicas 1
```

## Cleanup

Delete everything created by the script:

```bash
az group delete --name phishcatch-rg --yes --no-wait
```
