"""Offline wearable trace API. It never executes or stores reported actions."""

import json
import re
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse

router = APIRouter(prefix="/api/wearables", tags=["wearable trace review"])
MAX_BODY_BYTES = 2 * 1024 * 1024
ROOT = Path(__file__).resolve().parents[1]
FIXTURES_DIR = ROOT / "fixtures" / "wearables"
CASE_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")


def _auditor():
    import importlib

    try:
        return importlib.import_module("app.wearable_audit")
    except ModuleNotFoundError as exc:
        if exc.name == "app.wearable_audit":
            raise HTTPException(
                503, "The trace auditor is not available yet."
            ) from None
        raise


async def _read_body(request: Request) -> bytes:
    media_type = (
        request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    )
    if media_type != "application/json":
        raise HTTPException(415, "Send a JSON trace.")
    length = request.headers.get("content-length")
    if length is None:
        raise HTTPException(411, "A bounded request body is required.")
    if len(length) > 10 or not length.isascii() or not length.isdecimal():
        raise HTTPException(400, "Invalid request length.")
    if int(length) > MAX_BODY_BYTES:
        raise HTTPException(413, "Trace exceeds the 2 MiB limit.")
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > MAX_BODY_BYTES:
            raise HTTPException(413, "Trace exceeds the 2 MiB limit.")
        body.extend(chunk)
    return bytes(body)


def _run(raw: bytes, sarif: bool):
    engine = _auditor()
    try:
        trace = engine.load_trace(raw)
        report = engine.audit_trace(trace)
    except engine.TraceValidationError:
        raise HTTPException(422, "Trace is invalid.") from None
    return engine.as_sarif(report) if sarif else report


@router.get("/cases")
def cases():
    """Return bundled, curated traces only; clients cannot choose a filesystem path."""
    if not FIXTURES_DIR.is_dir() or FIXTURES_DIR.is_symlink():
        return {"cases": []}
    result = []
    for path in sorted(FIXTURES_DIR.glob("*.json")):
        if path.is_symlink() or not path.is_file() or not CASE_ID.fullmatch(path.stem):
            continue
        try:
            if path.stat().st_size > MAX_BODY_BYTES:
                continue
            item = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, ValueError):
            continue
        if not isinstance(item, dict) or set(item) != {
            "id",
            "title",
            "description",
            "expected_rule_ids",
            "trace",
        }:
            continue
        trace = item.get("trace")
        if (
            item.get("id") != path.stem
            or not isinstance(item.get("title"), str)
            or not isinstance(item.get("description"), str)
            or not isinstance(item.get("expected_rule_ids"), list)
            or not isinstance(trace, dict)
            or trace.get("evidence_kind") not in {"synthetic", "recorded"}
        ):
            continue
        result.append(
            {
                "id": path.stem,
                "title": item["title"],
                "description": item["description"],
                "evidence_kind": trace["evidence_kind"],
                "trace": trace,
            }
        )
    return {"cases": result}


@router.post("/audit")
async def audit(request: Request):
    return _run(await _read_body(request), sarif=False)


@router.post("/sarif")
async def sarif(request: Request):
    return _run(await _read_body(request), sarif=True)


@router.get("/schema")
def trace_schema():
    return FileResponse(
        ROOT / "schemas" / "wearable-trace.schema.json",
        media_type="application/schema+json",
    )
