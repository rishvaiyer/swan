import importlib.util
import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import app.wearable_api as api


def client_for(monkeypatch, fixture_dir):
    monkeypatch.setattr(api, "FIXTURES_DIR", fixture_dir)
    app = FastAPI()
    app.include_router(api.router)
    return TestClient(app, base_url="http://127.0.0.1")


def write_case(directory, case_id="benign-local"):
    directory.mkdir(parents=True, exist_ok=True)
    trace = {
        "schema_version": "1.0",
        "evidence_kind": "synthetic",
        "platform": "generic",
        "events": [],
    }
    fixture = {
        "id": case_id,
        "title": "Safe local note",
        "description": "Synthetic local trace.",
        "expected_rule_ids": [],
        "trace": trace,
    }
    (directory / f"{case_id}.json").write_text(json.dumps(fixture), encoding="utf-8")
    return fixture


def test_cases_return_curated_fields_without_expected_rules(tmp_path, monkeypatch):
    fixture = write_case(tmp_path / "fixtures")
    response = client_for(monkeypatch, tmp_path / "fixtures").get(
        "/api/wearables/cases"
    )
    assert response.status_code == 200
    assert response.json() == {
        "cases": [
            {
                "id": fixture["id"],
                "title": fixture["title"],
                "description": fixture["description"],
                "evidence_kind": "synthetic",
                "trace": fixture["trace"],
            }
        ]
    }


def test_cases_ignore_malformed_and_symlinked_fixtures(tmp_path, monkeypatch):
    directory = tmp_path / "fixtures"
    write_case(directory)
    (directory / "broken.json").write_text('{"untrusted":"fixture"}', encoding="utf-8")
    write_case(directory, "target")
    (directory / "linked.json").symlink_to(directory / "target.json")
    cases = (
        client_for(monkeypatch, directory).get("/api/wearables/cases").json()["cases"]
    )
    assert [item["id"] for item in cases] == ["benign-local", "target"]


def test_missing_fixture_directory_is_empty(tmp_path, monkeypatch):
    assert client_for(monkeypatch, tmp_path / "missing").get(
        "/api/wearables/cases"
    ).json() == {"cases": []}


def test_oversized_body_rejected_before_audit(tmp_path, monkeypatch):
    response = client_for(monkeypatch, tmp_path / "missing").post(
        "/api/wearables/audit",
        content=b"x" * (api.MAX_BODY_BYTES + 1),
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 413
    assert response.json() == {"detail": "Trace exceeds the 2 MiB limit."}


def test_non_json_body_rejected(tmp_path, monkeypatch):
    response = client_for(monkeypatch, tmp_path / "missing").post(
        "/api/wearables/audit",
        content=b"{}",
        headers={"Content-Type": "text/plain", "Content-Length": "2"},
    )
    assert response.status_code == 415
    assert response.json() == {"detail": "Send a JSON trace."}


def test_missing_engine_is_not_replaced_by_a_fake(tmp_path, monkeypatch):
    import importlib

    original_import = importlib.import_module

    def unavailable(name, *args, **kwargs):
        if name == "app.wearable_audit":
            raise ModuleNotFoundError(name=name)
        return original_import(name, *args, **kwargs)

    client = client_for(monkeypatch, tmp_path / "missing")
    monkeypatch.setattr(importlib, "import_module", unavailable)
    response = client.post("/api/wearables/audit", json={"events": []})
    assert response.status_code == 503
    assert response.json() == {"detail": "The trace auditor is not available yet."}


@pytest.mark.skipif(
    importlib.util.find_spec("app.wearable_audit") is None,
    reason="Separate audit-engine worktree is not integrated.",
)
def test_real_engine_audit_and_sarif(tmp_path, monkeypatch):
    from app import wearable_audit

    action = {
        "operation": "local_note",
        "destination": "local",
        "source_capture_ids": ["capture-1"],
        "content_sha256": "a" * 64,
    }
    trace = {
        "schema_version": "1.0",
        "evidence_kind": "synthetic",
        "platform": "generic",
        "events": [
            {"type": "connected", "t_ms": 0, "device_id": "device-1"},
            {
                "type": "permission",
                "t_ms": 1,
                "capability": "camera",
                "status": "granted",
            },
            {
                "type": "session_started",
                "t_ms": 2,
                "device_id": "device-1",
                "session_id": "session-1",
            },
            {
                "type": "capture",
                "t_ms": 100,
                "device_id": "device-1",
                "session_id": "session-1",
                "capture_id": "capture-1",
                "channel": "camera",
                "captured_at_ms": 100,
                "bystanders": "none",
            },
            {
                "type": "approval",
                "t_ms": 200,
                "approval_id": "approval-1",
                "action_id": "action-1",
                "action_fingerprint": wearable_audit.action_fingerprint(action),
            },
            {
                "type": "action",
                "t_ms": 300,
                "action_id": "action-1",
                "approval_id": "approval-1",
                **action,
            },
        ],
    }
    client = client_for(monkeypatch, tmp_path / "missing")
    data = json.dumps(trace)
    report = client.post(
        "/api/wearables/audit",
        content=data,
        headers={"Content-Type": "application/json"},
    )
    assert report.status_code == 200, report.text
    assert report.json()["summary"]["errors"] == 0
    assert report.json()["summary"]["findings"] == 0
    sarif = client.post(
        "/api/wearables/sarif",
        content=data,
        headers={"Content-Type": "application/json"},
    )
    assert sarif.status_code == 200, sarif.text
    assert sarif.json()["version"] == "2.1.0"


@pytest.mark.skipif(
    importlib.util.find_spec("app.wearable_audit") is None,
    reason="Separate audit-engine worktree is not integrated.",
)
def test_invalid_trace_error_does_not_echo_input(tmp_path, monkeypatch):
    marker = "PRIVATE_TRACE_MARKER_8921"
    response = client_for(monkeypatch, tmp_path / "missing").post(
        "/api/wearables/audit",
        content=json.dumps({"schema_version": "0", "secret": marker}),
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 422
    assert marker not in response.text
    assert response.json() == {"detail": "Trace is invalid."}
