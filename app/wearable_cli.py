"""Command-line interface for the offline wearable trace auditor."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from typing import Sequence

from app.wearable_audit import (
    MAX_TRACE_BYTES,
    TraceValidationError,
    as_sarif,
    audit_trace,
    load_trace,
)


class _SafeParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise ValueError("Invalid command line.")


def _read_trace(path: str) -> bytes:
    if path == "-":
        data = sys.stdin.buffer.read(MAX_TRACE_BYTES + 1)
    else:
        with open(path, "rb") as handle:
            data = handle.read(MAX_TRACE_BYTES + 1)
    if len(data) > MAX_TRACE_BYTES:
        raise TraceValidationError("Invalid trace input.")
    return data


def _same_file(input_path: str, output_path: str) -> bool:
    if input_path == "-":
        return False
    source = Path(input_path)
    destination = Path(output_path)
    try:
        if destination.exists() and os.path.samefile(source, destination):
            return True
    except (OSError, RuntimeError):
        return True
    try:
        return source.resolve() == destination.resolve()
    except (OSError, RuntimeError):
        return True


def main(argv: Sequence[str] | None = None) -> int:
    parser = _SafeParser(prog="swan-wearable-audit", add_help=True)
    parser.add_argument("trace", help="trace JSON file, or - for standard input")
    parser.add_argument("--format", choices=("json", "sarif"), default="json")
    parser.add_argument("--output", help="write report to this file")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code)
    except ValueError:
        print("Invalid command line.", file=sys.stderr)
        return 2

    if args.output and _same_file(args.trace, args.output):
        print("Input and output must be different files.", file=sys.stderr)
        return 2
    try:
        trace = load_trace(_read_trace(args.trace))
        report = audit_trace(trace)
        result = report if args.format == "json" else as_sarif(report)
        text = json.dumps(result, ensure_ascii=True, indent=2) + "\n"
        if args.output:
            Path(args.output).write_text(text, encoding="utf-8")
        else:
            sys.stdout.write(text)
    except TraceValidationError:
        print("Invalid trace input.", file=sys.stderr)
        return 2
    except (OSError, UnicodeError, ValueError):
        print("Unable to process trace.", file=sys.stderr)
        return 2
    return 1 if report["summary"]["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
