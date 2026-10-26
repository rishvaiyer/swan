"""Offline metadata-only wearable trace auditing."""

from __future__ import annotations
import hashlib
import json
import re
from typing import Any

MAX_TRACE_BYTES = 2 * 1024 * 1024
MAX_EVENTS = 5000
MAX_SAFE_INTEGER = 2**53 - 1
DEFAULT_MAX_CAPTURE_AGE_MS = 5000
DEFAULT_MAX_APPROVAL_AGE_MS = 15000
_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_HASH = re.compile(r"^[a-f0-9]{64}$")
_REQUIRED = {"schema_version", "evidence_kind", "platform", "events"}
_ALLOWED = _REQUIRED | {"policy"}
_DEFAULTS = {"max_capture_age_ms": 5000, "max_approval_age_ms": 15000}
_FIELDS = {
    "connected": {"device_id"},
    "disconnected": {"device_id"},
    "permission": {"capability", "status"},
    "session_started": {"device_id", "session_id"},
    "session_stopped": {"session_id"},
    "capture": {
        "device_id",
        "session_id",
        "capture_id",
        "channel",
        "captured_at_ms",
        "bystanders",
    },
    "approval": {"approval_id", "action_id", "action_fingerprint"},
    "action": {
        "action_id",
        "approval_id",
        "operation",
        "destination",
        "source_capture_ids",
        "content_sha256",
    },
}
_RULES = {
    "SW001": (
        "error",
        "Capture or action lacks a connected matching device.",
        "Require the source device to be connected in the trace.",
    ),
    "SW002": (
        "error",
        "Capture or action lacks a matching active session.",
        "Require a live session for the source device.",
    ),
    "SW003": (
        "error",
        "The required sensor permission is not granted.",
        "Require the relevant permission before capture and action.",
    ),
    "SW004": (
        "error",
        "Capture time is in the future or the source is too old.",
        "Reject future captures and enforce the configured capture age.",
    ),
    "SW005": (
        "error",
        "An action references a missing or invalid source capture.",
        "Use only unique, valid captures present earlier in the trace.",
    ),
    "SW006": (
        "error",
        "A source belongs to a prior device or session epoch.",
        "Start a new capture after reconnecting or starting a new session.",
    ),
    "SW007": (
        "error",
        "Approval is missing, unseen, or bound to another action.",
        "Require a prior approval for this exact action identifier.",
    ),
    "SW008": (
        "error",
        "Action fields differ from the approved fingerprint.",
        "Request fresh approval for the exact action fields.",
    ),
    "SW009": (
        "error",
        "Approval has expired at or beyond its allowed age.",
        "Request fresh approval; equality with the TTL is expired.",
    ),
    "SW010": (
        "error",
        "An approval or action identifier was already attempted.",
        "Use unique identifiers and do not replay rejected attempts.",
    ),
    "SW011": (
        "error",
        "Permission or device/session state changed after capture or approval.",
        "Re-capture and re-approve after any relevant state change.",
    ),
    "SW012": (
        "error",
        "Operation and destination do not match the local/external policy.",
        "Use external only for external_send; keep other operations local.",
    ),
    "SW013": (
        "error",
        "Bystander status is unknown or unconsented for this operation.",
        "Do not retain or send when bystander status is unknown or unconsented.",
    ),
    "SW014": (
        "error",
        "An identifier is duplicated or session history is ambiguous.",
        "Use unique identifiers and an unambiguous lifecycle.",
    ),
    "SW015": (
        "warning",
        "OCR or QR source is retained through persist_memory.",
        "Review whether raw visual text should be retained.",
    ),
    "SW016": (
        "error",
        "Device or session lifecycle is inconsistent.",
        "Record matching connect, session start, stop, and disconnect events.",
    ),
}
_LIMITATIONS = [
    "Evidence kind and platform are declared metadata, not independently attested.",
    "Digests are metadata claims; source bytes and their authenticity are not verified.",
    "This is an offline trace audit, not a device interceptor or runtime enforcement.",
    "A clean report does not prove safety, policy compliance, or actual device behavior.",
]


class TraceValidationError(ValueError):
    """The input cannot be safely interpreted under the trace schema."""


def _fail() -> None:
    raise TraceValidationError("Invalid trace input.")


def _obj(value: Any) -> bool:
    return type(value) is dict


def _int(value: Any, lo: int = 0, hi: int = MAX_SAFE_INTEGER) -> bool:
    return type(value) is int and lo <= value <= hi


def _id(value: Any) -> bool:
    return isinstance(value, str) and _ID.fullmatch(value) is not None


def _hash(value: Any) -> bool:
    return isinstance(value, str) and _HASH.fullmatch(value) is not None


def _keys(value: Any, expected: set[str]) -> None:
    if not _obj(value) or set(value) != expected:
        _fail()


def _validate(trace: Any) -> tuple[int, int]:
    if not _obj(trace) or not _REQUIRED <= set(trace) or set(trace) - _ALLOWED:
        _fail()
    if trace["schema_version"] != "1.0":
        _fail()
    if type(trace["evidence_kind"]) is not str or trace["evidence_kind"] not in {
        "synthetic",
        "recorded",
    }:
        _fail()
    if type(trace["platform"]) is not str or trace["platform"] not in {
        "meta-dat-ios",
        "meta-dat-android",
        "generic",
    }:
        _fail()
    policy = trace.get("policy", {})
    if not _obj(policy) or set(policy) - set(_DEFAULTS):
        _fail()
    settings = dict(_DEFAULTS)
    for key, value in policy.items():
        hi = 60000 if key == "max_capture_age_ms" else 15000
        if not _int(value, 1, hi):
            _fail()
        settings[key] = value
    events = trace["events"]
    if type(events) is not list or not 1 <= len(events) <= MAX_EVENTS:
        _fail()
    prior = -1
    for e in events:
        if (
            not _obj(e)
            or type(e.get("type")) is not str
            or e.get("type") not in _FIELDS
        ):
            _fail()
        kind = e["type"]
        _keys(e, {"type", "t_ms"} | _FIELDS[kind])
        if not _int(e["t_ms"]) or e["t_ms"] < prior:
            _fail()
        prior = e["t_ms"]
        if kind in {"connected", "disconnected"} and not _id(e["device_id"]):
            _fail()
        elif kind == "permission":
            if (
                type(e["capability"]) is not str
                or e["capability"] not in {"camera", "microphone"}
                or type(e["status"]) is not str
                or e["status"] not in {"granted", "revoked"}
            ):
                _fail()
        elif kind == "session_started":
            if not _id(e["device_id"]) or not _id(e["session_id"]):
                _fail()
        elif kind == "session_stopped" and not _id(e["session_id"]):
            _fail()
        elif kind == "capture":
            if not all(_id(e[k]) for k in ("device_id", "session_id", "capture_id")):
                _fail()
            if type(e["channel"]) is not str or e["channel"] not in {
                "camera",
                "microphone",
                "ocr",
                "qr",
            }:
                _fail()
            if type(e["bystanders"]) is not str or e["bystanders"] not in {
                "none",
                "consented",
                "unconsented",
                "unknown",
            }:
                _fail()
            if not _int(e["captured_at_ms"]):
                _fail()
        elif kind == "approval":
            if (
                not _id(e["approval_id"])
                or not _id(e["action_id"])
                or not _hash(e["action_fingerprint"])
            ):
                _fail()
        elif kind == "action":
            if not _id(e["action_id"]) or not _id(e["approval_id"]):
                _fail()
            if type(e["operation"]) is not str or e["operation"] not in {
                "local_note",
                "external_send",
                "persist_memory",
            }:
                _fail()
            if (
                type(e["destination"]) is not str
                or e["destination"] not in {"local", "external"}
                or not _hash(e["content_sha256"])
            ):
                _fail()
            refs = e["source_capture_ids"]
            if type(refs) is not list or not 1 <= len(refs) <= 64:
                _fail()
            if any(not _id(x) for x in refs) or len(set(refs)) != len(refs):
                _fail()
    try:
        encoded = json.dumps(
            trace, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
    except (TypeError, ValueError, RecursionError):
        _fail()
    if len(encoded) > MAX_TRACE_BYTES:
        _fail()
    return settings["max_capture_age_ms"], settings["max_approval_age_ms"]


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj = {}
    for key, value in pairs:
        if key in obj:
            _fail()
        obj[key] = value
    return obj


def _constant(_value: str) -> None:
    _fail()


def load_trace(data: bytes | str) -> dict[str, Any]:
    if isinstance(data, bytes):
        if len(data) > MAX_TRACE_BYTES:
            _fail()
        try:
            text = data.decode("utf-8", "strict")
        except UnicodeDecodeError:
            _fail()
    elif isinstance(data, str):
        try:
            if len(data.encode("utf-8", "strict")) > MAX_TRACE_BYTES:
                _fail()
        except UnicodeEncodeError:
            _fail()
        text = data
    else:
        _fail()
    try:
        trace = json.loads(text, object_pairs_hook=_pairs, parse_constant=_constant)
    except TraceValidationError:
        raise
    except (json.JSONDecodeError, TypeError, ValueError, RecursionError):
        _fail()
    _validate(trace)
    return trace


def action_fingerprint(action: dict[str, Any]) -> str:
    if not _obj(action):
        _fail()
    fields = ("operation", "destination", "source_capture_ids", "content_sha256")
    if any(k not in action for k in fields):
        _fail()
    if (
        type(action["operation"]) is not str
        or action["operation"] not in {"local_note", "external_send", "persist_memory"}
        or type(action["destination"]) is not str
        or action["destination"] not in {"local", "external"}
        or type(action["source_capture_ids"]) is not list
        or not action["source_capture_ids"]
        or any(not _id(x) for x in action["source_capture_ids"])
        or len(set(action["source_capture_ids"])) != len(action["source_capture_ids"])
        or not _hash(action["content_sha256"])
    ):
        _fail()
    canonical = json.dumps(
        {k: action[k] for k in fields},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def audit_trace(trace: dict[str, Any]) -> dict[str, Any]:
    max_capture_age, max_approval_age = _validate(trace)
    findings = []
    emitted = set()

    def add(rule, index):
        key = (index, rule)
        if key not in emitted:
            emitted.add(key)
            severity, message, recommendation = _RULES[rule]
            findings.append(
                {
                    "rule_id": rule,
                    "severity": severity,
                    "event_index": index,
                    "message": message,
                    "recommendation": recommendation,
                }
            )

    device_epochs = {}
    connected = {}
    connected_at = {}
    sessions = {}
    seen_sessions = set()
    active_by_device = {}
    permissions = {"camera": False, "microphone": False}
    permission_epochs = {"camera": 0, "microphone": 0}
    permission_granted_at = {"camera": None, "microphone": None}
    state_epoch = 0

    def clear_permissions():
        for capability in permissions:
            if permissions[capability]:
                permissions[capability] = False
                permission_epochs[capability] += 1
                permission_granted_at[capability] = None

    captures = {}
    seen_captures = set()
    ambiguous_captures = set()
    approvals = {}
    seen_approvals = set()
    ambiguous_approvals = set()
    attempted_approvals = set()
    attempted_actions = set()

    for i, e in enumerate(trace["events"]):
        kind = e["type"]
        now = e["t_ms"]
        if kind == "connected":
            d = e["device_id"]
            if connected:
                add("SW016", i)
                for old_device in list(connected):
                    old_session = active_by_device.pop(old_device, None)
                    if old_session is not None:
                        sessions[old_session]["active"] = False
                    device_epochs[old_device] = device_epochs.get(old_device, 0) + 1
                connected.clear()
            clear_permissions()
            device_epochs[d] = device_epochs.get(d, 0) + 1
            connected[d] = device_epochs[d]
            connected_at[d] = now
            state_epoch += 1
        elif kind == "disconnected":
            d = e["device_id"]
            if d not in connected:
                add("SW016", i)
            else:
                connected.pop(d)
                device_epochs[d] = device_epochs.get(d, 0) + 1
                old = active_by_device.pop(d, None)
                if old is not None:
                    sessions[old]["active"] = False
                clear_permissions()
                state_epoch += 1
        elif kind == "permission":
            c = e["capability"]
            granted = e["status"] == "granted"
            if permissions[c] != granted:
                permissions[c] = granted
                permission_epochs[c] += 1
                permission_granted_at[c] = now if granted else None
                state_epoch += 1
        elif kind == "session_started":
            d, s = e["device_id"], e["session_id"]
            if s in seen_sessions:
                add("SW014", i)
                continue
            seen_sessions.add(s)
            if d not in connected or d in active_by_device:
                add("SW016", i)
                continue
            sessions[s] = {
                "device": d,
                "device_epoch": connected[d],
                "active": True,
                "generation": len(seen_sessions),
                "stopped": False,
                "started_at": now,
            }
            active_by_device[d] = s
            state_epoch += 1
        elif kind == "session_stopped":
            s = e["session_id"]
            session = sessions.get(s)
            if session is None or session["stopped"]:
                add("SW016", i)
                continue
            d = session["device"]
            if session["active"]:
                session["active"] = False
                if active_by_device.get(d) == s:
                    active_by_device.pop(d, None)
                state_epoch += 1
            session["stopped"] = True
        elif kind == "capture":
            cid = e["capture_id"]
            if cid in seen_captures:
                add("SW014", i)
                ambiguous_captures.add(cid)
                continue
            seen_captures.add(cid)
            d, s = e["device_id"], e["session_id"]
            session = sessions.get(s)
            is_conn = d in connected
            if not is_conn:
                add("SW001", i)
            if (
                session is None
                or not session["active"]
                or session["device"] != d
                or not is_conn
                or session["device_epoch"] != connected.get(d)
            ):
                add("SW002", i)
            sensor = (
                "camera" if e["channel"] in {"camera", "ocr", "qr"} else "microphone"
            )
            if not permissions[sensor]:
                add("SW003", i)
            captured = e["captured_at_ms"]
            future = captured > now
            stale = now - captured > max_capture_age
            before_epoch = captured < connected_at.get(d, 0) or (
                session is not None and captured < session.get("started_at", 0)
            )
            before_permission = (
                permission_granted_at[sensor] is None
                or captured < permission_granted_at[sensor]
            )
            if future or stale:
                add("SW004", i)
            if before_epoch:
                add("SW006", i)
            if before_permission:
                add("SW003", i)
            valid = (
                is_conn
                and session is not None
                and session["active"]
                and session["device"] == d
                and session["device_epoch"] == connected.get(d)
                and permissions[sensor]
                and not future
                and not stale
                and not before_epoch
                and not before_permission
            )
            captures[cid] = {
                "device": d,
                "device_epoch": connected.get(d, device_epochs.get(d, 0)),
                "session_id": s,
                "session_generation": session["generation"] if session else None,
                "captured_at": captured,
                "channel": e["channel"],
                "bystanders": e["bystanders"],
                "sensor": sensor,
                "permission_epoch": permission_epochs[sensor],
                "valid": valid,
            }
        elif kind == "approval":
            aid = e["approval_id"]
            if aid in seen_approvals:
                add("SW014", i)
                ambiguous_approvals.add(aid)
                continue
            seen_approvals.add(aid)
            attempted = aid in attempted_approvals
            approvals[aid] = {
                "action_id": e["action_id"],
                "fingerprint": e["action_fingerprint"],
                "time": now,
                "state_epoch": state_epoch,
                "used": attempted,
            }
            if attempted:
                add("SW010", i)
        elif kind == "action":
            action_id, aid = e["action_id"], e["approval_id"]
            if action_id in attempted_actions:
                add("SW010", i)
            attempted_actions.add(action_id)
            reused = aid in attempted_approvals
            if reused:
                add("SW010", i)
            attempted_approvals.add(aid)
            approval = approvals.get(aid)
            if approval is None or aid in ambiguous_approvals:
                add("SW007", i)
            elif approval["action_id"] != action_id:
                add("SW007", i)
            if approval is not None:
                if approval["used"] or reused:
                    add("SW010", i)
                approval["used"] = True
                if now >= approval["time"] + max_approval_age:
                    add("SW009", i)
                if approval["state_epoch"] != state_epoch:
                    add("SW011", i)
                if approval["fingerprint"] != action_fingerprint(e):
                    add("SW008", i)
            if (e["operation"] == "external_send") != (e["destination"] == "external"):
                add("SW012", i)
            source_records = []
            for cid in e["source_capture_ids"]:
                cap = captures.get(cid)
                if cap is None or cid in ambiguous_captures or not cap["valid"]:
                    add("SW005", i)
                    if cap is None or cid in ambiguous_captures:
                        continue
                source_records.append(cap)
            source_sessions = set()
            for cap in source_records:
                d = cap["device"]
                if d not in connected:
                    add("SW001", i)
                elif cap["device_epoch"] != connected[d]:
                    add("SW006", i)
                session = sessions.get(cap["session_id"])
                if (
                    session is None
                    or not session["active"]
                    or session["device"] != d
                    or session["device_epoch"] != connected.get(d)
                ):
                    add("SW002", i)
                    if cap["valid"]:
                        add("SW006", i)
                        add("SW005", i)
                elif session["generation"] != cap["session_generation"]:
                    add("SW006", i)
                    add("SW005", i)
                source_sessions.add((d, cap["session_id"]))
                if not permissions[cap["sensor"]]:
                    add("SW003", i)
                if permission_epochs[cap["sensor"]] != cap["permission_epoch"]:
                    add("SW011", i)
                    if cap["valid"]:
                        add("SW005", i)
                if (
                    cap["captured_at"] > now
                    or now - cap["captured_at"] > max_capture_age
                ):
                    add("SW004", i)
                    add("SW005", i)
                if e["operation"] in {"external_send", "persist_memory"} and cap[
                    "bystanders"
                ] in {"unknown", "unconsented"}:
                    add("SW013", i)
                if e["operation"] == "persist_memory" and cap["channel"] in {
                    "ocr",
                    "qr",
                }:
                    add("SW015", i)
            if len(source_sessions) > 1:
                add("SW002", i)

    findings.sort(key=lambda f: (f["event_index"], f["rule_id"]))
    errors = sum(f["severity"] == "error" for f in findings)
    warnings = sum(f["severity"] == "warning" for f in findings)
    return {
        "schema_version": "1.0",
        "evidence_kind": trace["evidence_kind"],
        "platform": trace["platform"],
        "summary": {
            "events": len(trace["events"]),
            "findings": len(findings),
            "errors": errors,
            "warnings": warnings,
        },
        "findings": findings,
        "limitations": list(_LIMITATIONS),
    }


def as_sarif(report: dict[str, Any]) -> dict[str, Any]:
    if not _obj(report) or set(report) != {
        "schema_version",
        "evidence_kind",
        "platform",
        "summary",
        "findings",
        "limitations",
    }:
        _fail()
    if (
        report["schema_version"] != "1.0"
        or type(report["evidence_kind"]) is not str
        or report["evidence_kind"] not in {"synthetic", "recorded"}
        or type(report["platform"]) is not str
        or report["platform"] not in {"meta-dat-ios", "meta-dat-android", "generic"}
        or type(report["findings"]) is not list
    ):
        _fail()
    results = []
    for f in report["findings"]:
        if (
            not _obj(f)
            or type(f.get("rule_id")) is not str
            or f.get("rule_id") not in _RULES
        ):
            _fail()
        rule = f["rule_id"]
        severity, message, _ = _RULES[rule]
        index = f.get("event_index")
        if type(index) is not int or index < 0:
            _fail()
        results.append(
            {
                "ruleId": rule,
                "level": "error" if severity == "error" else "warning",
                "message": {"text": message},
                "locations": [
                    {
                        "logicalLocations": [
                            {"name": f"events[{index}]", "kind": "member"}
                        ]
                    }
                ],
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Swan wearable trace auditor",
                        "version": "0.2.0",
                        "rules": [
                            {
                                "id": r,
                                "name": r,
                                "shortDescription": {"text": v[1]},
                                "fullDescription": {"text": v[1]},
                            }
                            for r, v in sorted(_RULES.items())
                        ],
                    }
                },
                "properties": {
                    "evidenceKind": report["evidence_kind"],
                    "platform": report["platform"],
                    "scope": "Offline metadata policy audit; no device attestation or runtime enforcement.",
                    "limitations": list(_LIMITATIONS),
                },
                "results": results,
            }
        ],
    }
