from fastapi import FastAPI

from app.core.config import settings
from app.routers.scan import router as scan_router


app = FastAPI(title=settings.app_name, version=settings.app_version)
app.include_router(scan_router)


@app.get("/health", tags=["System"])
async def health() -> dict[str, str]:
    return {"status": "ok"}
