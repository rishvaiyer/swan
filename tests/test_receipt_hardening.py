"""Regression checks for the evidence failures identified by the Claude review."""
from copy import deepcopy
import json
import multiprocessing
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor
import pytest
import app.receipts as receipts


def record(number, **extra):
    return {"id": f"{number:032x}", "created_at": "2026-10-21T00:00:00+00:00", **extra}


@pytest.fixture()
def receipt_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(receipts, "RUNS_DIR", tmp_path)
    return tmp_path


@pytest.mark.parametrize("run_id", [None, 8, [], "../outside", "/tmp/outside", "a"*31, "A"*32])
def test_invalid_id_never_becomes_a_filename(receipt_dir, run_id):
    with pytest.raises(ValueError):
        receipts.store_receipt({"id": run_id})
    assert not list(receipt_dir.glob("*.json"))


def test_duplicate_id_cannot_overwrite_history(receipt_dir):
    first = receipts.store_receipt(record(1, proposal={"action": "none"}))
    original = (receipt_dir / (first["id"] + ".json")).read_bytes()
    with pytest.raises(receipts.ReceiptIntegrityError, match="already exists"):
        receipts.store_receipt(record(1, proposal={"action": "changed"}))
    assert (receipt_dir / (first["id"] + ".json")).read_bytes() == original


def test_corrupt_file_is_not_silently_omitted_or_extended(receipt_dir):
    first = receipts.store_receipt(record(1))
    (receipt_dir / (first["id"] + ".json")).write_text("{")
    with pytest.raises(receipts.ReceiptIntegrityError, match="Unreadable"):
        receipts.list_receipts()
    with pytest.raises(receipts.ReceiptIntegrityError):
        receipts.store_receipt(record(2))
    assert not (receipt_dir / ("0"*31 + "2.json")).exists()


def test_tampered_predecessor_invalidates_whole_chain_and_prevents_append(receipt_dir):
    first = receipts.store_receipt(record(1, value="original"))
    second = receipts.store_receipt(record(2))
    first["value"] = "modified"
    (receipt_dir / (first["id"] + ".json")).write_text(json.dumps(first))
    history = receipts.list_receipts()
    assert receipts.verify_receipt(second)
    assert not receipts.verify_chain(history)["valid"]
    with pytest.raises(receipts.ReceiptIntegrityError, match="Cannot append"):
        receipts.store_receipt(record(3))


def test_missing_middle_is_detected(receipt_dir):
    first = receipts.store_receipt(record(1))
    second = receipts.store_receipt(record(2))
    third = receipts.store_receipt(record(3))
    (receipt_dir / (second["id"] + ".json")).unlink()
    with pytest.raises(receipts.ReceiptIntegrityError, match="missing predecessor"):
        receipts.list_receipts()


def test_hash_link_order_ignores_wall_clock_regression(receipt_dir):
    first = receipts.seal_receipt(record(1, recorded_at="2030-01-01T00:00:00Z"))
    second = receipts.seal_receipt(record(2, recorded_at="2020-01-01T00:00:00Z"), first["integrity"]["hash"])
    for item in [first, second]:
        (receipt_dir / (item["id"] + ".json")).write_text(json.dumps(item))
    assert [item["id"] for item in receipts.list_receipts()] == [first["id"], second["id"]]
    assert receipts.verify_chain(receipts.list_receipts())["valid"]


def test_recorded_at_does_not_eagerly_require_created_at(receipt_dir):
    sealed = receipts.seal_receipt({"id": "a"*32, "recorded_at": "2026-10-21T00:00:00Z"})
    (receipt_dir / (sealed["id"] + ".json")).write_text(json.dumps(sealed))
    assert receipts.list_receipts() == [sealed]


@pytest.mark.parametrize("previous", ["", 0, [], {}, "x"*64])
def test_malformed_previous_hash_is_not_genesis_alias(previous):
    with pytest.raises(ValueError):
        receipts.seal_receipt(record(1), previous)
    sealed = receipts.seal_receipt(record(1))
    sealed["integrity"]["previous_hash"] = previous
    assert receipts.verify_receipt(sealed) is False


def test_failed_atomic_publish_does_not_leave_partial_json(receipt_dir, monkeypatch):
    def fail_publish(*args):
        raise OSError("simulated atomic publish failure")
    monkeypatch.setattr(receipts.os, "replace", fail_publish)
    with pytest.raises(OSError):
        receipts.store_receipt(record(1))
    assert not list(receipt_dir.glob("*.json"))
    assert not list(receipt_dir.glob(".pending-*"))


def _process_write(directory, number):
    import app.receipts as worker_receipts
    worker_receipts.RUNS_DIR = Path(directory)
    return worker_receipts.store_receipt(record(number))["id"]


def test_multiple_processes_append_one_unforked_chain(receipt_dir):
    with ProcessPoolExecutor(max_workers=3, mp_context=multiprocessing.get_context("spawn")) as pool:
        futures = [pool.submit(_process_write, str(receipt_dir), number) for number in range(1, 7)]
        assert len({future.result() for future in futures}) == 6
    history = receipts.list_receipts()
    assert len(history) == 6
    assert receipts.verify_chain(history)["valid"]


def test_deleted_tail_is_honestly_not_attested(receipt_dir):
    receipts.store_receipt(record(1))
    tail = receipts.store_receipt(record(2))
    (receipt_dir / (tail["id"] + ".json")).unlink()
    result = receipts.verify_chain(receipts.list_receipts())
    assert result["valid"] is True
    assert result["attested"] is False
    assert "deleted tail" in result["limitation"]


def test_verification_endpoint_reports_invalid_ancestor(receipt_dir, monkeypatch):
    from fastapi.testclient import TestClient
    import app.main as service
    monkeypatch.setattr(service, "RUNS_DIR", receipt_dir)
    ancestor = receipts.store_receipt(record(1, value="original"))
    child = receipts.store_receipt(record(2))
    ancestor["value"] = "modified"
    (receipt_dir / (ancestor["id"] + ".json")).write_text(json.dumps(ancestor))
    with TestClient(service.app, base_url="http://127.0.0.1:8766") as client:
        result = client.get("/api/runs/" + child["id"] + "/verify")
        assert result.status_code == 200
        assert result.json()["content_valid"] is True
        assert result.json()["chain_valid"] is False
        assert client.get("/api/runs").status_code == 409
        assert client.get("/api/runs/" + child["id"]).status_code == 409


def test_nonobject_integrity_file_fails_explicitly(receipt_dir):
    item = record(1, integrity=[])
    (receipt_dir / (item["id"] + ".json")).write_text(json.dumps(item))
    with pytest.raises(receipts.ReceiptIntegrityError):
        receipts.list_receipts()
