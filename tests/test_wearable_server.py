"""HTTP and schema checks for the metadata-only review service."""

import json
from pathlib import Path

from fastapi.testclient import TestClient
from jsonschema import Draft202012Validator

from app.wearable_server import app

ROOT = Path(__file__).resolve().parents[1]
client = TestClient(app, base_url="http://127.0.0.1:18766")


def test_review_app_has_no_media_or_model_routes():
    assert client.get("/").status_code == 200
    assert "Wearable trace review" in client.get("/").text
    assert client.post("/api/perceive", json={}).status_code == 404
    assert client.post("/api/run", json={}).status_code == 404
    assert client.get("/native/").status_code == 404
    assert client.get("/api/health").status_code == 404


def test_review_http_boundary_and_security_headers():
    assert client.get("/", headers={"Host": "other.example"}).status_code == 403
    for origin in (
        "https://127.0.0.1:18766",
        "http://other.example",
        "null",
        "http://127.0.0.1:18766/path",
    ):
        assert (
            client.post(
                "/api/wearables/audit", json={}, headers={"Origin": origin}
            ).status_code
            == 403
        )
    response = client.get("/")
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    response = client.post(
        "/api/wearables/audit",
        content=b"{}",
        headers={"Content-Type": "application/json", "Content-Length": "9" * 5000},
    )
    assert response.status_code == 411


def test_schema_and_corpus_are_interoperable():
    response = client.get("/api/wearables/schema")
    assert response.status_code == 200
    schema = response.json()
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    validator.validate(json.loads((ROOT / "examples/wearable-safe.json").read_text()))
    for path in sorted((ROOT / "fixtures/wearables").glob("*.json")):
        validator.validate(json.loads(path.read_text())["trace"])


def test_review_real_case_corpus_and_redacted_result():
    cases = client.get("/api/wearables/cases").json()["cases"]
    assert len(cases) >= 25
    for case in cases:
        response = client.post("/api/wearables/audit", json=case["trace"])
        assert response.status_code == 200
        report = response.json()
        assert report["summary"]["events"] == len(case["trace"]["events"])
        for event in case["trace"]["events"]:
            for key in (
                "device_id",
                "capture_id",
                "session_id",
                "approval_id",
                "action_id",
                "content_sha256",
                "action_fingerprint",
            ):
                if key in event:
                    assert event[key] not in response.text


def test_review_rejects_schema_abuse_without_echoing_input():
    trace = json.loads((ROOT / "examples/wearable-safe.json").read_text())
    trace["evidence_kind"] = {"PRIVATE_TRACE_VALUE": "not-an-enum"}
    response = client.post("/api/wearables/audit", json=trace)
    assert response.status_code == 422
    assert response.json() == {"detail": "Trace is invalid."}
