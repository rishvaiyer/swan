"""Local hash-linked evidence, with atomic writes and explicit integrity failures.

Hashes detect inconsistent local edits. They are not signatures, and cannot detect
an entirely recomputed history or a deleted tail without an external checkpoint.
"""
import copy
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from threading import Lock

LOCK = Lock()
RUNS_DIR = Path(__file__).resolve().parents[1] / "evidence" / "runs"
RUNS_DIR.mkdir(parents=True, exist_ok=True)
GENESIS = "0" * 64
SCHEME = "sha256(previous_hash + canonical_json_without_integrity)"
LIMITATION = "Local edit detection only. This is not a signature, external attestation, or proof of hardware execution."


class ReceiptIntegrityError(ValueError):
    """An invalid evidence file or chain must not be silently omitted."""


def valid_id(value):
    return isinstance(value, str) and re.fullmatch(r"[a-f0-9]{32}", value) is not None


def valid_hash(value):
    return isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value) is not None


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def seal_receipt(receipt, previous_hash=None):
    if not isinstance(receipt, dict):
        raise ValueError("Receipt must be an object.")
    previous = GENESIS if previous_hash is None else previous_hash
    if not valid_hash(previous):
        raise ValueError("Previous hash must be exactly 64 lowercase hexadecimal characters.")
    sealed = copy.deepcopy(receipt)
    sealed.pop("integrity", None)
    digest = hashlib.sha256(previous.encode() + canonical(sealed)).hexdigest()
    sealed["integrity"] = {"previous_hash": previous, "hash": digest, "scheme": SCHEME, "limitation": LIMITATION}
    return sealed


def verify_receipt(receipt):
    if not isinstance(receipt, dict) or not isinstance(receipt.get("integrity"), dict):
        return False
    integrity = receipt["integrity"]
    if not valid_hash(integrity.get("hash")) or not valid_hash(integrity.get("previous_hash")):
        return False
    if integrity.get("scheme") != SCHEME or integrity.get("limitation") != LIMITATION:
        return False
    try:
        return seal_receipt(receipt, integrity["previous_hash"])["integrity"]["hash"] == integrity["hash"]
    except (KeyError, TypeError, ValueError, AttributeError, OverflowError):
        return False


def _chain_order(records):
    """Order by authenticated links, never by potentially regressing wall time."""
    if not records:
        return []
    by_previous = {}
    hashes = set()
    for receipt in records:
        integrity = receipt.get("integrity")
        if not isinstance(integrity, dict):
            raise ReceiptIntegrityError("A receipt has no valid integrity object.")
        previous, digest = integrity.get("previous_hash"), integrity.get("hash")
        if not valid_hash(previous) or not valid_hash(digest):
            raise ReceiptIntegrityError("A receipt contains malformed chain hashes.")
        if digest in hashes:
            raise ReceiptIntegrityError("Duplicate receipt hash in history.")
        hashes.add(digest)
        if previous in by_previous:
            raise ReceiptIntegrityError("Receipt history contains a fork.")
        by_previous[previous] = receipt
    ordered, head = [], GENESIS
    while head in by_previous:
        receipt = by_previous[head]
        ordered.append(receipt)
        head = receipt["integrity"]["hash"]
        if len(ordered) > len(records):
            raise ReceiptIntegrityError("Receipt history contains a cycle.")
    if len(ordered) != len(records):
        raise ReceiptIntegrityError("Receipt history has a missing predecessor or disconnected chain.")
    return ordered


def verify_chain(records):
    content_valid = all(verify_receipt(receipt) for receipt in records)
    errors = []
    if not content_valid:
        errors.append("At least one receipt content hash or integrity format is invalid.")
    try:
        ordered = _chain_order(records)
        links_valid = True
    except (ReceiptIntegrityError, AttributeError, TypeError) as exc:
        ordered, links_valid = [], False
        errors.append(str(exc))
    return {"valid": content_valid and links_valid, "content_valid": content_valid,
            "links_valid": links_valid, "count": len(records),
            "head_hash": ordered[-1]["integrity"]["hash"] if ordered else GENESIS,
            "errors": errors, "attested": False,
            "limitation": "Local chain consistency only. A recomputed history or deleted tail cannot be detected without a trusted external checkpoint."}


def list_receipts():
    result = []
    for path in RUNS_DIR.glob("*.json"):
        if path.is_symlink() or not path.is_file() or not valid_id(path.stem):
            raise ReceiptIntegrityError("Unexpected receipt filename or file type: " + path.name)
        try:
            receipt = json.loads(path.read_text())
        except (ValueError, OSError, UnicodeError) as exc:
            raise ReceiptIntegrityError("Unreadable receipt: " + path.name) from exc
        if not isinstance(receipt, dict) or receipt.get("id") != path.stem:
            raise ReceiptIntegrityError("Receipt identity does not match filename: " + path.name)
        timestamp = receipt.get("recorded_at") or receipt.get("created_at")
        if not isinstance(timestamp, str) or not timestamp:
            raise ReceiptIntegrityError("Receipt has no valid recording timestamp: " + path.name)
        result.append(receipt)
    return _chain_order(result)


def store_receipt(receipt):
    if not isinstance(receipt, dict) or not valid_id(receipt.get("id")):
        raise ValueError("Receipt id must be exactly 32 lowercase hexadecimal characters.")
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    with LOCK, (RUNS_DIR / ".receipt.lock").open("a") as file_lock:
        fcntl.flock(file_lock.fileno(), fcntl.LOCK_EX)
        existing = list_receipts()
        report = verify_chain(existing)
        if not report["valid"]:
            raise ReceiptIntegrityError("Cannot append to invalid receipt history: " + "; ".join(report["errors"]))
        path = RUNS_DIR / (receipt["id"] + ".json")
        if path.exists() or path.is_symlink():
            raise ReceiptIntegrityError("Receipt id already exists; history will not be overwritten.")
        prepared = copy.deepcopy(receipt)
        prepared["recorded_at"] = datetime.now(timezone.utc).isoformat()
        sealed = seal_receipt(prepared, report["head_hash"])
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=RUNS_DIR,
                                             prefix=".pending-", suffix=".tmp", delete=False) as handle:
                temporary = Path(handle.name)
                handle.write(json.dumps(sealed, indent=2, ensure_ascii=False) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            # The shared process/file lock plus duplicate check prevents application
            # writers from replacing an existing id. Replace publishes complete bytes.
            os.replace(temporary, path)
            directory = os.open(RUNS_DIR, os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
        return sealed
