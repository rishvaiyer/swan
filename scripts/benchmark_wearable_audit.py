"""Measure local parser/auditor cost on one synthetic maximum-length trace."""

import json
from pathlib import Path
import statistics
import sys
import time
import tracemalloc

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.wearable_audit import audit_trace, load_trace


def main():
    root = Path(__file__).resolve().parents[1]
    trace = json.loads((root / "examples/wearable-safe.json").read_text())
    trace["events"] = trace["events"][:3]
    for i in range(4997):
        trace["events"].append(
            {
                "type": "capture",
                "t_ms": 100 + i,
                "device_id": "device-1",
                "session_id": "session-1",
                "capture_id": f"frame-{i}",
                "channel": "camera",
                "captured_at_ms": 100 + i,
                "bystanders": "none",
            }
        )
    raw = json.dumps(trace, separators=(",", ":")).encode()
    timings = []
    for _ in range(7):
        started = time.perf_counter()
        report = audit_trace(load_trace(raw))
        timings.append((time.perf_counter() - started) * 1000)
    assert report["summary"]["events"] == 5000 and report["summary"]["errors"] == 0
    tracemalloc.start()
    audit_trace(load_trace(raw))
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    print(
        json.dumps(
            {
                "events": 5000,
                "input_bytes": len(raw),
                "median_ms": round(statistics.median(timings), 2),
                "runs": 7,
                "peak_traced_python_bytes": peak,
                "scope": "Synthetic all-capture trace; parsing, validation and audit in one local process. Not a hardware or competitor benchmark.",
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
