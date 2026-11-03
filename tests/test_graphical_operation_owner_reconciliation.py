"""PR28 signed operator approval + PR29 selected protected sender reconciliation."""
import base64
import hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import pytest

from zog.root_control import graphical_operation_owner_source as owner
from test_graphical_operation_owner_source import request, setup

def approved(req=None, *, key=None, expires=600):
    req=req or request()
    key=key or Ed25519PrivateKey.generate()
    body={"schema":owner.APPROVAL_SCHEMA,"approval_id":"7"*32,
          "request_sha256":owner.digest(req),
          "scope_sha256":owner.digest(owner.scope_from_request(req)),
          "expires_at":expires}
    signature=key.sign(owner.APPROVAL_DOMAIN+owner.canonical(body))
    return key,{**body,"signature_ed25519":base64.b64encode(signature).decode("ascii")}

def rawkey(key):
    return key.public_key().public_bytes(
        serialization.Encoding.Raw,serialization.PublicFormat.Raw)

def test_signed_original_approval_admits_only_exact_preapproved_operation():
    key,grant=approved()
    result=owner.verify_original_operator_approval(
        request(),grant,externally_pinned_operator_key=rawkey(key),
        expected_approval_id="7"*32,now=400)
    assert result["operation_id"]==request()["operation_id"]
    assert result["status"]=="signed-original-grant-verified-not-installed"
    ledger,svc,calls,_=setup()
    assert ledger.approved_operations[request()["operation_id"]]==result["request_sha256"]
    assert svc.submit_once(request())["outcome"]=="SENT_ORIGINAL"
    with pytest.raises(owner.OperationDenied):
        svc.submit_once(request())
    assert len(calls)==1

@pytest.mark.parametrize("mutate",[
    lambda x:x.update(source_revision="0"*40),
    lambda x:x.update(state_volume_id="0"*64),
    lambda x:x.update(installation_id="0"*64),
    lambda x:x.update(authority_epoch=3),
    lambda x:x.update(remote_request_sha256="sha256:"+"0"*64),
    lambda x:x.update(operation_id="0"*32),
    lambda x:x.update(original_request_sha256="sha256:"+"0"*64),
])
def test_operator_approval_rejects_coherent_local_rollback_and_substitution(mutate):
    key,grant=approved()
    altered=request()
    mutate(altered)
    with pytest.raises(owner.OperationDenied):
        owner.verify_original_operator_approval(
            altered,grant,externally_pinned_operator_key=rawkey(key),
            expected_approval_id="7"*32,now=400)

def test_wrong_signer_stale_expired_approval_and_signature_tamper():
    key,grant=approved()
    other=Ed25519PrivateKey.generate()
    with pytest.raises(owner.OperationDenied):
        owner.verify_original_operator_approval(
            request(),grant,externally_pinned_operator_key=rawkey(other),
            expected_approval_id="7"*32,now=400)
    with pytest.raises(owner.OperationDenied):
        owner.verify_original_operator_approval(
            request(),grant,externally_pinned_operator_key=rawkey(key),
            expected_approval_id="8"*32,now=400)
    with pytest.raises(owner.OperationDenied):
        owner.verify_original_operator_approval(
            request(),grant,externally_pinned_operator_key=rawkey(key),
            expected_approval_id="7"*32,now=601)
    altered=dict(grant)
    altered["expires_at"]=100000
    with pytest.raises(owner.OperationDenied):
        owner.verify_original_operator_approval(
            request(),altered,externally_pinned_operator_key=rawkey(key),
            expected_approval_id="7"*32,now=400)
    altered=dict(grant);altered["signature_ed25519"]="!"*88
    with pytest.raises(owner.OperationDenied):
        owner.verify_original_operator_approval(
            request(),altered,externally_pinned_operator_key=rawkey(key),
            expected_approval_id="7"*32,now=400)

def test_signed_observation_never_enables_new_send_after_revoke_and_reboot():
    ledger,svc,calls,signer=setup()
    svc.submit_once(request())
    svc.revoke(owner.scope_from_request(request()))
    restarted=owner.SourceOnlyProtectedOwner(
        ledger,test_sender=lambda _:pytest.fail("must not send after revocation"),
        test_signer=signer)
    body=restarted.read_signed(request=request(),nonce="1"*48)
    assert body
    with pytest.raises(owner.OperationDenied):
        restarted.submit_once(request())
    assert len(calls)==1
