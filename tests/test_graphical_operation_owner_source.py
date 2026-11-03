"""Offline independent graphical operation-owner contract tests.

The synthetic owner/ledger are NOT production RPC, durable external storage,
AWS access or permission to send a compiler request. No native installer.
"""
import base64
import copy
import json
import threading
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from zog.root_control import graphical_operation_owner_source as owner


def request():
    return {
        "schema": owner.SCHEMA,
        "host_id": "a"*64, "installation_id": "b"*64,
        "state_volume_id": "c"*64, "lane": "graphical-lane",
        "task": "graphics-x11-core-image-v1",
        "catalogue_sha256": "sha256:"+"1"*64,
        "source_revision": "2"*40, "monthly_pin_identity": "sha256:"+"3"*64,
        "base_generation_id": "4"*64,
        "predecessor_receipt_sha256": "sha256:"+"5"*64,
        "request_id": "6"*32, "original_request_sha256": "sha256:"+"7"*64,
        "stage_once_receipt_sha256": "sha256:"+"8"*64,
        "operation_id": "9"*32, "stage": "submit", "ordinal": 0,
        "remote_request_sha256": "sha256:"+"d"*64,
        "authority_epoch": 2, "authority_pin_sha256": "sha256:"+"e"*64,
        "approval_sha256": "sha256:"+"f"*64,
    }


def setup(sender=None):
    row = request()
    ledger = owner.SyntheticExternalLedger(
        owner.scope_from_request(row),
        independently_approved_operations={
            row["operation_id"]: owner.digest(row),
        },
    )
    calls = []
    if sender is None:
        def sender(x):
            calls.append(copy.deepcopy(x))
            return "ssm-original-command-1"
    signer = Ed25519PrivateKey.generate()
    return ledger, owner.SourceOnlyProtectedOwner(
        ledger, test_sender=sender, test_signer=signer), calls, signer


def denied(fn):
    with pytest.raises(owner.OperationDenied):
        fn()


def test_original_sent_once_and_reboot_with_entire_gateway_journal_rollback():
    ledger, first, calls, signer = setup()
    result = first.submit_once(request())
    assert result["outcome"] == "SENT_ORIGINAL"
    assert len(calls) == 1
    # Entire gateway store is "restored" from an old pristine snapshot. The
    # *separate external owner* survives, is reconstructed and never resends.
    restarted = owner.SourceOnlyProtectedOwner(
        ledger, test_sender=lambda _: pytest.fail("reissued after reboot"),
        test_signer=signer)
    denied(lambda: restarted.submit_once(request()))
    assert len(calls) == 1


def test_lost_ack_preserves_irrevocable_claim_and_original_request():
    calls = []
    def lost_ack(row):
        calls.append(row)
        raise TimeoutError("original SSM response unknown")
    ledger, first, _, signer = setup(lost_ack)
    with pytest.raises(TimeoutError):
        first.submit_once(request())
    assert ledger.claims[request()["operation_id"]]["outcome"] == "CLAIMED_UNCERTAIN"
    assert len(calls) == 1
    restarted = owner.SourceOnlyProtectedOwner(
        ledger, test_sender=lambda _: pytest.fail("lost ACK replay"),
        test_signer=signer)
    denied(lambda: restarted.submit_once(request()))
    signed = restarted.read_signed(request=request(), nonce="c"*48)
    row = json.loads(signed)
    assert row["operation"]["command_id"] is None
    assert row["operation"]["outcome"] == "CLAIMED_UNCERTAIN"
    assert row["sequence"] == 1


def test_concurrent_duplicates_only_one_send_even_during_inflight():
    gate = threading.Event()
    release = threading.Event()
    calls = []
    def sender(row):
        calls.append(row)
        gate.set()
        assert release.wait(3)
        return "original"
    ledger, first, _, signer = setup(sender)
    values = []
    def run():
        try:
            values.append(first.submit_once(request()))
        except owner.OperationDenied:
            values.append("DENIED")
    a = threading.Thread(target=run)
    b = threading.Thread(target=run)
    a.start()
    assert gate.wait(3)
    b.start()
    release.set()
    a.join(3); b.join(3)
    assert sorted([v if type(v) is str else v["outcome"] for v in values]) == [
        "DENIED", "SENT_ORIGINAL"]
    assert len(calls) == 1
    assert ledger.sequence == 1


def test_revocation_before_first_send_blocks_and_survives_reboot():
    ledger, first, calls, signer = setup()
    assert first.revoke(owner.scope_from_request(request())) == 1
    assert first.revoke(owner.scope_from_request(request())) == 1
    denied(lambda: first.submit_once(request()))
    reboot = owner.SourceOnlyProtectedOwner(
        ledger, test_sender=lambda _: pytest.fail("revoked authority used"),
        test_signer=signer)
    denied(lambda: reboot.submit_once(request()))
    assert calls == []


def test_revocation_during_inflight_serializes_before_next_attempt():
    entered = threading.Event()
    release = threading.Event()
    send_calls = []
    def sender(req):
        send_calls.append(req)
        entered.set()
        assert release.wait(3)
        return "ssm-accepted"
    ledger, first, _, _ = setup(sender)
    result = []
    a = threading.Thread(target=lambda: result.append(first.submit_once(request())))
    a.start()
    assert entered.wait(3)
    revoke_finished = threading.Event()
    def revoker():
        first.revoke(owner.scope_from_request(request()))
        revoke_finished.set()
    r = threading.Thread(target=revoker)
    r.start()
    assert not revoke_finished.wait(.05)
    release.set()
    a.join(3); r.join(3)
    assert revoke_finished.is_set()
    assert result[0]["outcome"] == "SENT_ORIGINAL"
    denied(lambda: first.submit_once(request()))
    assert len(send_calls) == 1
    assert ledger.revoked


@pytest.mark.parametrize("field,value", (
    ("host_id","0"*64), ("installation_id","0"*64),
    ("state_volume_id","0"*64), ("lane","different-lane"),
    ("task","graphics-mesa-image-v1"), ("catalogue_sha256","sha256:"+"0"*64),
    ("source_revision","0"*40), ("monthly_pin_identity","sha256:"+"0"*64),
    ("base_generation_id","0"*64),
    ("predecessor_receipt_sha256","sha256:"+"0"*64),
    ("authority_epoch",1), ("authority_pin_sha256","sha256:"+"0"*64),
    ("approval_sha256","sha256:"+"0"*64),
))
def test_scope_substitutions_rejected_before_send(field,value):
    _, first, calls, _ = setup()
    attempted = request()
    attempted[field] = value
    denied(lambda: first.submit_once(attempted))
    assert calls == []


@pytest.mark.parametrize("field,value", (
    ("operation_id","0"*32), ("remote_request_sha256","sha256:"+"0"*64),
    ("original_request_sha256","sha256:"+"0"*64),
    ("stage_once_receipt_sha256","sha256:"+"0"*64),
    ("request_id","0"*32),
    ("stage","inspect"), ("ordinal",1),
))
def test_new_operation_is_distinct_but_never_selected_by_caller_receipt(field,value):
    ledger, first, calls, signer = setup()
    first.submit_once(request())
    changed = request()
    changed[field] = value
    # Even a valid-looking *new* operation ID has no original root-approved
    # request grant in the independently protected ledger. No first-seen
    # operation selection is allowed.
    denied(lambda: first.submit_once(changed))
    assert len(calls) == 1


def test_nonce_bound_signed_observation_does_not_grant_second_send():
    _, first, calls, _ = setup()
    first.submit_once(request())
    message = first.read_signed(request=request(), nonce="f"*48)
    row = json.loads(message)
    signature = base64.b64decode(row.pop("signature_ed25519"), validate=True)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    Ed25519PublicKey.from_public_bytes(first.public_key).verify(
        signature, owner.DOMAIN + owner.canonical(row))
    assert row["nonce"] == "f"*48
    assert row["scope"]["state_volume_id"] == "c"*64
    denied(lambda: first.submit_once(request()))
    with pytest.raises(Exception):
        Ed25519PublicKey.from_public_bytes(first.public_key).verify(
            signature, owner.DOMAIN +
            owner.canonical({**row, "nonce":"0"*48}))
    assert len(calls) == 1


def test_no_approval_or_operation_can_be_expanded_by_signed_observation():
    _, first, _, _ = setup()
    denied(lambda: first.read_signed(request=request(), nonce="f"*48))
    denied(lambda: first.submit_once({**request(), "task":"mesa-final"}))
    denied(lambda: first.submit_once({**request(), "sender":"invoke-arbitrary"}))
