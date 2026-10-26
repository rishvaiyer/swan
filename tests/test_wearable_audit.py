import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from app.wearable_audit import (
    MAX_TRACE_BYTES,
    TraceValidationError,
    action_fingerprint,
    as_sarif,
    audit_trace,
    load_trace,
)

ROOT = Path(__file__).resolve().parents[1]
DIGEST = "a" * 64


def action_event(**changes):
    event = {
        "type": "action",
        "t_ms": 300,
        "action_id": "act_1",
        "approval_id": "appr_1",
        "operation": "local_note",
        "destination": "local",
        "source_capture_ids": ["cap_1"],
        "content_sha256": DIGEST,
    }
    event.update(changes)
    return event


def approval_for(action=None, **changes):
    action = action or action_event()
    event = {
        "type": "approval",
        "t_ms": 200,
        "approval_id": action["approval_id"],
        "action_id": action["action_id"],
        "action_fingerprint": action_fingerprint(action),
    }
    event.update(changes)
    return event


def safe_events(action=None, **changes):
    action = action or action_event(**changes)
    return [
        {"type": "connected", "t_ms": 0, "device_id": "dev_1"},
        {
            "type": "session_started",
            "t_ms": 1,
            "device_id": "dev_1",
            "session_id": "sess_1",
        },
        {"type": "permission", "t_ms": 2, "capability": "camera", "status": "granted"},
        {
            "type": "capture",
            "t_ms": 100,
            "device_id": "dev_1",
            "session_id": "sess_1",
            "capture_id": "cap_1",
            "channel": "camera",
            "captured_at_ms": 100,
            "bystanders": "none",
        },
        approval_for(action),
        action,
    ]


def trace(events=None, **extra):
    value = {
        "schema_version": "1.0",
        "evidence_kind": "synthetic",
        "platform": "generic",
        "events": safe_events() if events is None else events,
    }
    value.update(extra)
    return value


def rules(report):
    return {item["rule_id"] for item in report["findings"]}


def test_safe_exact_local_trace_is_clean_and_stable():
    report = audit_trace(trace())
    assert report["summary"] == {"events": 6, "findings": 0, "errors": 0, "warnings": 0}
    assert list(report) == [
        "schema_version",
        "evidence_kind",
        "platform",
        "summary",
        "findings",
        "limitations",
    ]
    assert audit_trace(trace()) == report


def test_safe_external_action_requires_consented_bystanders_and_matching_destination():
    action = action_event(operation="external_send", destination="external")
    events = safe_events(action)
    events[3]["bystanders"] = "consented"
    assert audit_trace(trace(events))["summary"]["errors"] == 0


@pytest.mark.parametrize(
    "field,value,expected",
    [
        ("device_id", "missing_device", "SW001"),
        ("session_id", "missing_session", "SW002"),
    ],
)
def test_capture_without_device_or_session_is_invalid_forever(field, value, expected):
    events = safe_events()
    events[3][field] = value
    report = audit_trace(trace(events))
    assert expected in rules(report)
    assert "SW005" in rules(report)


def test_capture_without_permission_and_permission_revoked_before_action():
    events = safe_events()
    events[2]["status"] = "revoked"
    assert {"SW003", "SW005"} <= rules(audit_trace(trace(events)))

    events = safe_events()
    events.insert(
        4,
        {
            "type": "permission",
            "t_ms": 150,
            "capability": "camera",
            "status": "revoked",
        },
    )
    report = audit_trace(trace(events))
    assert {"SW003", "SW011"} <= rules(report)


def test_ocr_and_qr_require_camera_permission():
    events = safe_events()
    events[3]["channel"] = "ocr"
    events[2]["capability"] = "microphone"
    assert {"SW003", "SW005"} <= rules(audit_trace(trace(events)))


def test_future_and_stale_capture_timestamps_are_findings():
    events = safe_events()
    events[3]["captured_at_ms"] = 101
    assert "SW004" in rules(audit_trace(trace(events)))

    events = safe_events()
    events[3]["captured_at_ms"] = 1
    events[3]["t_ms"] = 10000
    events[4]["t_ms"] = 10001
    events[5]["t_ms"] = 10002
    assert "SW004" in rules(audit_trace(trace(events)))


def test_capture_timestamp_must_follow_device_session_and_permission_boundary():
    events = safe_events()
    events[3]["captured_at_ms"] = 0
    report = audit_trace(trace(events))
    assert {"SW006", "SW003", "SW005"} <= rules(report)


def test_permission_granted_before_connect_does_not_authorize_a_new_device():
    action = action_event()
    events = [
        {"type": "permission", "t_ms": 0, "capability": "camera", "status": "granted"},
        {"type": "connected", "t_ms": 1, "device_id": "dev_1"},
        {
            "type": "session_started",
            "t_ms": 2,
            "device_id": "dev_1",
            "session_id": "sess_1",
        },
        {
            "type": "capture",
            "t_ms": 100,
            "device_id": "dev_1",
            "session_id": "sess_1",
            "capture_id": "cap_1",
            "channel": "camera",
            "captured_at_ms": 100,
            "bystanders": "none",
        },
        approval_for(action),
        action,
    ]
    report = audit_trace(trace(events))
    assert {"SW003", "SW005"} <= rules(report)


def test_device_switch_clears_global_permission_grant_and_invalidates_old_capture():
    action = action_event()
    events = safe_events(action)[:4]
    events += [
        {"type": "connected", "t_ms": 120, "device_id": "dev_2"},
        {
            "type": "session_started",
            "t_ms": 121,
            "device_id": "dev_2",
            "session_id": "sess_2",
        },
        {
            "type": "permission",
            "t_ms": 122,
            "capability": "camera",
            "status": "granted",
        },
        approval_for(action, t_ms=200),
        action,
    ]
    report = audit_trace(trace(events))
    assert {"SW016", "SW005", "SW006", "SW011"} <= rules(report)


def test_missing_unknown_and_duplicate_source_capture_fail_closed():
    events = safe_events()
    events[-1]["source_capture_ids"] = ["no_capture"]
    assert "SW005" in rules(audit_trace(trace(events)))

    events = safe_events()
    duplicate = dict(events[3], t_ms=110, captured_at_ms=110)
    events.insert(4, duplicate)
    events[4]["capture_id"] = events[3]["capture_id"]
    events[5]["t_ms"] = 200
    events[6]["t_ms"] = 300
    report = audit_trace(trace(events))
    assert {"SW014", "SW005"} <= rules(report)


def test_reconnect_and_new_session_do_not_revive_old_capture():
    action = action_event()
    events = safe_events(action)[:4]
    events += [
        {"type": "disconnected", "t_ms": 150, "device_id": "dev_1"},
        {"type": "connected", "t_ms": 160, "device_id": "dev_1"},
        {
            "type": "session_started",
            "t_ms": 170,
            "device_id": "dev_1",
            "session_id": "sess_2",
        },
        approval_for(action, t_ms=200),
        action,
    ]
    assert {"SW002", "SW006", "SW005"} <= rules(audit_trace(trace(events)))


def test_wrong_action_id_changed_fingerprint_and_missing_approval_are_reported():
    events = safe_events()
    events[-1]["action_id"] = "act_2"
    report = audit_trace(trace(events))
    assert "SW007" in rules(report)
    assert "SW008" not in rules(report)

    events = safe_events()
    events[4]["action_fingerprint"] = "b" * 64
    assert "SW008" in rules(audit_trace(trace(events)))

    events = safe_events()
    del events[4]
    assert "SW007" in rules(audit_trace(trace(events)))


def test_expiry_uses_greater_than_or_equal_boundary():
    action = action_event(t_ms=15200)
    events = safe_events(action)
    assert "SW009" in rules(audit_trace(trace(events)))


def test_approval_and_action_replays_poison_rejected_attempts():
    events = safe_events()
    replay = dict(events[-1], t_ms=400, action_id="act_2")
    events.append(replay)
    assert "SW010" in rules(audit_trace(trace(events)))

    events = safe_events()
    first_attempt = action_event(t_ms=150, approval_id="later")
    later_approval = approval_for(first_attempt, t_ms=200, approval_id="later")
    later_action = action_event(t_ms=300, action_id="act_2", approval_id="later")
    later_approval["action_id"] = "act_2"
    later_approval["action_fingerprint"] = action_fingerprint(later_action)
    events = events[:4] + [first_attempt, later_approval, later_action]
    report = audit_trace(trace(events))
    assert "SW010" in rules(report)


def test_permission_and_session_changes_after_approval_invalidate_it():
    action = action_event()
    events = safe_events(action)
    events.insert(
        5,
        {
            "type": "permission",
            "t_ms": 250,
            "capability": "camera",
            "status": "revoked",
        },
    )
    events[-1]["t_ms"] = 300
    assert "SW011" in rules(audit_trace(trace(events)))

    events = safe_events(action)
    events.insert(5, {"type": "session_stopped", "t_ms": 250, "session_id": "sess_1"})
    events[-1]["t_ms"] = 300
    assert {"SW011", "SW002", "SW006"} <= rules(audit_trace(trace(events)))


def test_destination_policy_and_bystander_restrictions():
    action = action_event(operation="external_send", destination="local")
    report = audit_trace(trace(safe_events(action)))
    assert "SW012" in rules(report)

    for status in ("unknown", "unconsented"):
        action = action_event(operation="external_send", destination="external")
        events = safe_events(action)
        events[3]["bystanders"] = status
        assert "SW013" in rules(audit_trace(trace(events)))

        action = action_event(operation="persist_memory", destination="local")
        events = safe_events(action)
        events[3]["bystanders"] = status
        assert "SW013" in rules(audit_trace(trace(events)))


def test_raw_ocr_qr_persist_memory_is_warning_even_with_approval():
    for channel in ("ocr", "qr"):
        action = action_event(operation="persist_memory", destination="local")
        events = safe_events(action)
        events[3]["channel"] = channel
        report = audit_trace(trace(events))
        finding = next(
            item for item in report["findings"] if item["rule_id"] == "SW015"
        )
        assert finding["severity"] == "warning"
        assert report["summary"]["errors"] == 0


def test_session_reuse_and_lifecycle_anomalies():
    events = safe_events()[:3]
    events.append(
        {
            "type": "session_started",
            "t_ms": 3,
            "device_id": "dev_1",
            "session_id": "sess_1",
        }
    )
    assert "SW014" in rules(audit_trace(trace(events)))

    events = [
        {
            "type": "session_started",
            "t_ms": 0,
            "device_id": "dev_1",
            "session_id": "sess_1",
        },
        {"type": "disconnected", "t_ms": 1, "device_id": "dev_1"},
        {"type": "session_stopped", "t_ms": 2, "session_id": "unknown"},
    ]
    assert "SW016" in rules(audit_trace(trace(events)))


def test_findings_are_sorted_and_never_echo_trace_identifiers_or_digests():
    events = safe_events()
    events[3]["capture_id"] = "PERSONAL_ID_MUST_NOT_LEAK"
    events[-1]["source_capture_ids"] = ["unknown_personal_id"]
    report = audit_trace(trace(events))
    assert report["findings"] == sorted(
        report["findings"], key=lambda f: (f["event_index"], f["rule_id"])
    )
    serialized = json.dumps(report)
    assert "PERSONAL_ID_MUST_NOT_LEAK" not in serialized
    assert "unknown_personal_id" not in serialized
    assert DIGEST not in serialized
    assert report["limitations"][0].startswith(
        "Evidence kind and platform are declared"
    )


def test_fingerprint_is_canonical_and_order_sensitive_for_source_ids():
    first = action_event()
    reordered = dict(first)
    reordered["type"] = "something ignored"
    assert action_fingerprint(first) == action_fingerprint(reordered)
    changed = dict(first, source_capture_ids=["cap_2", "cap_1"])
    assert action_fingerprint(first) != action_fingerprint(changed)


def test_sarif_uses_only_logical_locations_and_static_rule_messages():
    events = safe_events()
    events[-1]["source_capture_ids"] = ["private_capture_name"]
    report = audit_trace(trace(events))
    report["findings"][0]["message"] = "PRIVATE_RAW_CONTENT"
    sarif = as_sarif(report)
    serialized = json.dumps(sarif)
    assert sarif["version"] == "2.1.0"
    assert "private_capture_name" not in serialized
    assert "PRIVATE_RAW_CONTENT" not in serialized
    assert "physicalLocation" not in serialized
    assert "uri" not in serialized
    assert "events[5]" in serialized


def _mutated_trace(mutator):
    value = trace()
    mutator(value)
    return value


@pytest.mark.parametrize(
    "mutator",
    [
        lambda x: x.update(extra="not allowed"),
        lambda x: x.update(schema_version=True),
        lambda x: x.update(evidence_kind=[]),
        lambda x: x.update(platform={}),
        lambda x: x["events"][0].update(extra=1),
        lambda x: x["events"][0].update(type=[]),
        lambda x: x["events"][0].update(t_ms=True),
        lambda x: x["events"][2].update(capability=[]),
        lambda x: x["events"][2].update(status={}),
        lambda x: x["events"][3].update(channel=[]),
        lambda x: x["events"][3].update(bystanders={}),
        lambda x: x["events"][3].update(captured_at_ms=False),
        lambda x: x["events"][-1].update(operation=[]),
        lambda x: x["events"][-1].update(destination={}),
        lambda x: x["events"][-1].update(source_capture_ids=["bad id"]),
        lambda x: x.update(policy={"max_capture_age_ms": True}),
    ],
)
def test_direct_dict_validation_fails_closed_without_type_errors(mutator):
    value = _mutated_trace(mutator)
    with pytest.raises(TraceValidationError):
        audit_trace(value)


@pytest.mark.parametrize("value", [[], {}, None, True])
@pytest.mark.parametrize(
    "location",
    [
        "schema_version",
        "evidence_kind",
        "platform",
        "event_type",
        "permission_capability",
        "permission_status",
        "capture_channel",
        "capture_bystanders",
        "action_operation",
        "action_destination",
    ],
)
def test_every_enum_rejects_nonstring_direct_values(location, value):
    candidate = trace()
    if location == "schema_version":
        candidate["schema_version"] = value
    elif location == "evidence_kind":
        candidate["evidence_kind"] = value
    elif location == "platform":
        candidate["platform"] = value
    elif location == "event_type":
        candidate["events"][0]["type"] = value
    elif location == "permission_capability":
        candidate["events"][2]["capability"] = value
    elif location == "permission_status":
        candidate["events"][2]["status"] = value
    elif location == "capture_channel":
        candidate["events"][3]["channel"] = value
    elif location == "capture_bystanders":
        candidate["events"][3]["bystanders"] = value
    elif location == "action_operation":
        candidate["events"][-1]["operation"] = value
    else:
        candidate["events"][-1]["destination"] = value
    with pytest.raises(TraceValidationError):
        audit_trace(candidate)


def test_loader_rejects_duplicate_keys_nan_bad_utf8_oversize_and_bad_unicode():
    valid = json.dumps(trace(), separators=(",", ":"))
    with pytest.raises(TraceValidationError):
        load_trace(
            valid.replace(
                '"schema_version":"1.0"',
                '"schema_version":"1.0","schema_version":"1.0"',
            )
        )
    with pytest.raises(TraceValidationError):
        load_trace(valid.replace('"t_ms":0', '"t_ms":NaN'))
    with pytest.raises(TraceValidationError):
        load_trace(b"\xff")
    with pytest.raises(TraceValidationError):
        load_trace(b" " * (MAX_TRACE_BYTES + 1))
    with pytest.raises(TraceValidationError):
        load_trace("\ud800")


def test_loader_rejects_deeply_nested_json_generically():
    deeply_nested = "[" * 1500 + "0" + "]" * 1500
    with pytest.raises(TraceValidationError) as error:
        load_trace(deeply_nested)
    assert str(error.value) == "Invalid trace input."


def test_direct_trace_size_is_bounded_after_schema_validation():
    long_ids = ["cap_" + format(i, "03d") + "x" * 57 for i in range(64)]
    events = []
    for i in range(520):
        events.append(
            {
                "type": "action",
                "t_ms": i,
                "action_id": f"a{i}",
                "approval_id": f"p{i}",
                "operation": "local_note",
                "destination": "local",
                "source_capture_ids": long_ids,
                "content_sha256": DIGEST,
            }
        )
    with pytest.raises(TraceValidationError):
        audit_trace(trace(events))


def test_sarif_rejects_untrusted_rule_metadata_without_echo():
    report = audit_trace(trace())
    report["findings"] = [{"rule_id": [], "event_index": 0, "message": "secret"}]
    with pytest.raises(TraceValidationError):
        as_sarif(report)


def _run_cli(*args, input_bytes=None):
    return subprocess.run(
        [sys.executable, "-m", "app.wearable_cli", *map(str, args)],
        cwd=ROOT,
        input=input_bytes,
        capture_output=True,
        check=False,
    )


def _write_trace(path, value=None):
    path.write_text(json.dumps(trace() if value is None else value), encoding="utf-8")
    return path


def test_cli_exit_codes_json_sarif_and_generic_invalid_input(tmp_path):
    good = _write_trace(tmp_path / "good.json")
    result = _run_cli(good)
    assert result.returncode == 0
    assert json.loads(result.stdout)["summary"]["errors"] == 0

    bad_value = trace()
    bad_value["events"][-1]["source_capture_ids"] = ["missing"]
    bad = _write_trace(tmp_path / "bad.json", bad_value)
    result = _run_cli(bad, "--format", "sarif")
    assert result.returncode == 1
    assert json.loads(result.stdout)["version"] == "2.1.0"

    secret = tmp_path / "do-not-echo-secret.json"
    secret.write_text('{"private_trace":"RAW_SECRET"}', encoding="utf-8")
    result = _run_cli(secret)
    assert result.returncode == 2
    assert b"RAW_SECRET" not in result.stderr
    assert str(secret).encode() not in result.stderr


def test_cli_output_never_clobbers_input_through_path_symlink_or_hardlink(tmp_path):
    input_path = _write_trace(tmp_path / "input.json")
    original = input_path.read_bytes()
    assert _run_cli(input_path, "--output", input_path).returncode == 2
    assert input_path.read_bytes() == original

    hard = tmp_path / "hard.json"
    os.link(input_path, hard)
    assert _run_cli(input_path, "--output", hard).returncode == 2
    assert input_path.read_bytes() == original

    sym = tmp_path / "sym.json"
    sym.symlink_to(input_path)
    assert _run_cli(input_path, "--output", sym).returncode == 2
    assert input_path.read_bytes() == original


def test_cli_bounded_stdin_and_output_file(tmp_path):
    raw = json.dumps(trace()).encode()
    result = _run_cli("-", input_bytes=raw)
    assert (
        result.returncode == 0 and json.loads(result.stdout)["summary"]["errors"] == 0
    )

    source = _write_trace(tmp_path / "input.json")
    output = tmp_path / "report.json"
    result = _run_cli(source, "--output", output)
    assert result.returncode == 0
    assert json.loads(output.read_text())["schema_version"] == "1.0"


def test_cli_io_errors_are_generic_and_return_two(tmp_path):
    missing = tmp_path / "missing-secret-path.json"
    result = _run_cli(missing)
    assert result.returncode == 2
    assert b"missing-secret-path" not in result.stderr
    assert b"Traceback" not in result.stderr


@pytest.mark.parametrize(
    "field,value",
    [
        ("evidence_kind", "PRIVATE_METADATA"),
        ("platform", {}),
        ("evidence_kind", []),
        ("platform", "unknown"),
    ],
)
def test_sarif_rejects_untrusted_report_metadata(field, value):
    report = audit_trace(
        {
            "schema_version": "1.0",
            "evidence_kind": "synthetic",
            "platform": "generic",
            "events": [{"type": "connected", "t_ms": 0, "device_id": "device"}],
        }
    )
    report[field] = value
    with pytest.raises(TraceValidationError) as caught:
        as_sarif(report)
    assert "PRIVATE_METADATA" not in str(caught.value)
