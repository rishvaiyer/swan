"""Tamper evidence is checked against receipt content, not a UI status string."""
from copy import deepcopy
from app.receipts import seal_receipt, verify_receipt


def test_sealed_receipt_verifies_and_modified_model_proposal_does_not():
    raw = {"id": "receipt-test", "trial": "live", "model": {"name": "local-test"}, "proposal": {"action": "none"}, "effects": {"executed": False}}
    sealed = seal_receipt(deepcopy(raw), "0" * 64)
    assert verify_receipt(sealed) is True
    tampered = deepcopy(sealed)
    tampered["proposal"]["action"] = "send_message"
    assert verify_receipt(tampered) is False


def test_changed_effect_or_origin_invalidates_receipt():
    sealed = seal_receipt({"id": "r2", "trial": "gate", "effects": {"executed": False}}, "a" * 64)
    for field, value in [("trial", "live"), ("effects", {"executed": True})]:
        tampered = deepcopy(sealed)
        tampered[field] = value
        assert verify_receipt(tampered) is False
