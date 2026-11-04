"""Independent signed GitHub origin evidence is required before native owner.

All events and keys are synthetic; no real GitHub approval or AWS principal is
fabricated by these source tests.
"""
import base64
import copy
from pathlib import Path
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import pytest

from zog.root_control import graphical_operation_owner_source as source
from zog.root_control.graphical_task_c_origin import (
    SCHEMA, DOMAIN, verify_installed_evidence)

sys.path.insert(0,str(Path(__file__).resolve().parent))
from test_graphical_task_c_owner import _fixture


def provision():
    registry, _, _, operator_public = _fixture()
    issuer = Ed25519PrivateKey.generate()
    issuer_public = issuer.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    assert issuer_public != operator_public
    stages = {
        op: item for op, item in registry.entries.items()
        if op == item["stage_operation_id"]
    }
    item = next(iter(stages.values()))
    body = {
        "schema": SCHEMA,
        "scope_sha256":source.digest(
            source.scope_from_request(item["owner_request"])),
        "issued_at": 300, "expires_at": 500,
        "records": {
            op: {"original":value["original"],
                 "github_event_sha256": "sha256:"+"b"*64,
                 "github_delivery_id": "synthetic-event-123",
                 "original_commit_sha": "c"*40}
            for op, value in stages.items()
        }
    }
    def sign(data):
        signed = {**data, "signature_ed25519":
                  base64.b64encode(issuer.sign(
                      DOMAIN + source.canonical(data))).decode("ascii")}
        return signed
    return registry, issuer_public, body, sign


def test_original_github_evidence_separately_signed_and_bound():
    registry, pub, body, sign = provision()
    outcome = verify_installed_evidence(
        sign(body), registry=registry,
        pinned_issuer_key=pub, now=400)
    assert outcome["status"] == "independently-signed-original-evidence-verified"
    assert len(outcome["stage_operations"]) == 1


@pytest.mark.parametrize("changed", ("actor", "request_sha", "delivery", "expired",
                                    "wrong_scope", "missing", "wrong_key"))
def test_forged_or_stale_original_evidence_refuses_installation(changed):
    registry, pub, body, sign = provision()
    changed_body = copy.deepcopy(body)
    stage_id = next(iter(changed_body["records"]))
    if changed == "actor":
        changed_body["records"][stage_id]["original"]["origin_trigger_actor"]="wrong"
    elif changed == "request_sha":
        changed_body["records"][stage_id]["original"]["original_request_sha256"]="f"*64
    elif changed == "delivery":
        changed_body["records"][stage_id]["github_delivery_id"]="invalid id !"
    elif changed == "expired":
        changed_body["expires_at"]=350
    elif changed == "wrong_scope":
        changed_body["scope_sha256"]="sha256:"+"f"*64
    elif changed == "missing":
        changed_body["records"]={}
    elif changed == "wrong_key":
        pub = Ed25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    with pytest.raises(source.OperationDenied):
        verify_installed_evidence(
            sign(changed_body), registry=registry,
            pinned_issuer_key=pub, now=400)
