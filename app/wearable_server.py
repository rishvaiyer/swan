"""Metadata-only review service; no OCR, model or media-upload routes."""

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.local_http import install_local_boundary
from app.wearable_api import MAX_BODY_BYTES, router

PUBLIC = Path(__file__).resolve().parents[1] / "public" / "wearables"
app = FastAPI(
    title="Swan wearable trace review", docs_url=None, redoc_url=None, openapi_url=None
)
install_local_boundary(app, MAX_BODY_BYTES)
app.include_router(router)


@app.get("/")
def index():
    return FileResponse(PUBLIC / "index.html")


app.mount("/wearables", StaticFiles(directory=PUBLIC, html=True), name="wearables")
