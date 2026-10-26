"""Contract checks for the synthetic, metadata-only wearable trace corpus."""

import hashlib
import json
from pathlib import Path

import pytest

from app.wearable_audit import (
    TraceValidationError,
    as_sarif,
    audit_trace,
    action_fingerprint,
    load_trace,
)

FIXTURE_DIR = Path(__file__).parents[1] / "fixtures" / "wearables"


def fixtures():
    return sorted(FIXTURE_DIR.glob("*.json"))


def test_fixture_corpus_is_synthetic_and_has_expected_rules():
    paths = fixtures()
    assert len(paths) >= 16
    ids = set()
    for path in paths:
        case = json.loads(path.read_text(encoding="utf-8"))
        assert set(case) == {"id", "title", "description", "expected_rule_ids", "trace"}
        assert case["id"] not in ids
        ids.add(case["id"])
        assert case["trace"]["evidence_kind"] == "synthetic"
        assert case["trace"]["platform"] == "generic"
        assert case["expected_rule_ids"] == sorted(set(case["expected_rule_ids"]))
        assert load_trace(json.dumps(case["trace"]).encode("utf-8")) == case["trace"]


def test_fixture_findings_match_declared_expected_rule_ids():
    for path in fixtures():
        case = json.loads(path.read_text(encoding="utf-8"))
        report = audit_trace(case["trace"])
        actual = sorted({finding["rule_id"] for finding in report["findings"]})
        assert actual == case["expected_rule_ids"], case["id"]
        assert report["evidence_kind"] == "synthetic"
        assert report["platform"] == "generic"
        assert report["summary"]["findings"] == len(report["findings"])
        assert report["summary"]["errors"] == sum(
            finding["severity"] == "error" for finding in report["findings"]
        )
        assert report["summary"]["warnings"] == sum(
            finding["severity"] == "warning" for finding in report["findings"]
        )


def test_action_fingerprint_uses_the_contract_canonical_bytes():
    action = {
        "type": "action",
        "t_ms": 300,
        "action_id": "arbitrary_action_id",
        "approval_id": "arbitrary_approval_id",
        "operation": "local_note",
        "destination": "local",
        "source_capture_ids": ["capture_B", "capture_A"],
        "content_sha256": "a" * 64,
    }
    expected_payload = json.dumps(
        {
            "operation": "local_note",
            "destination": "local",
            "source_capture_ids": ["capture_B", "capture_A"],
            "content_sha256": "a" * 64,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    assert action_fingerprint(action) == hashlib.sha256(expected_payload).hexdigest()


def test_invalid_input_is_rejected_without_echoing_values():
    trace = json.loads((FIXTURE_DIR / "safe-local.json").read_text(encoding="utf-8"))[
        "trace"
    ]
    trace["private_payload_SHOULD_NOT_ECHO"] = "private-value-SHOULD-NOT-ECHO"
    with pytest.raises(TraceValidationError) as caught:
        load_trace(json.dumps(trace))
    assert "private-value-SHOULD-NOT-ECHO" not in str(caught.value)


def test_duplicate_json_keys_and_nonfinite_numbers_are_rejected():
    with pytest.raises(TraceValidationError):
        load_trace(b'{"schema_version":"1.0","schema_version":"1.0"}')

    trace = json.loads((FIXTURE_DIR / "safe-local.json").read_text(encoding="utf-8"))[
        "trace"
    ]
    trace["events"][0]["t_ms"] = float("nan")
    with pytest.raises(TraceValidationError):
        load_trace(json.dumps(trace).encode("utf-8"))


def test_sarif_uses_logical_event_locations_without_fake_files():
    case = json.loads(
        (FIXTURE_DIR / "camera-revoked-late-frame.json").read_text(encoding="utf-8")
    )
    sarif = as_sarif(audit_trace(case["trace"]))
    assert sarif["version"] == "2.1.0"
    results = sarif["runs"][0]["results"]
    assert results
    for result in results:
        location = result["locations"][0]
        assert "logicalLocations" in location
        assert "physicalLocation" not in location
