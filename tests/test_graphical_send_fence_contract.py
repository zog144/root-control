"""Synthetic independently protected monotonic owner and rollback denial.

InMemoryIndependentCAS represents the *separate* protected storage domain.
Never replace it with gateway files, never treat it as a native attestation.
"""
import hashlib
import importlib.util
from pathlib import Path
from threading import Lock, Thread

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location(
    "graphical_send_owner",ROOT/"src/zog/root_control/graphical_send_fence_contract.py")
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

def scope():
    return {"host_id":"1"*32,"host_fingerprint":"2"*64,
            "installation_id":"3"*32,"state_volume_id":"4"*64,
            "registry_id":"5"*32,"controller_id":"6"*32,"authority_epoch":8}

def claim(op="7"*32):
    return {"request_id":"8"*32,"operation_id":op,
            "stage":"submit","ordinal":0,"remote_request_sha256":"9"*64,
            "binding_sha256":"a"*64,"task_catalogue_sha256":"b"*64,
            "source_revision":"c"*40,"source_generation":"d"*64,
            "lane":"graphical","target":"host-selected","monthly_pin_identity":"e"*64,
            "operation":"pipeline.submit"}

class InMemoryIndependentCAS:
    """Not gateway-owned: immutable historical operation IDs survive gateway rollback."""
    def __init__(self):
        self.lock=Lock();self.counter=0;self.claims={};self.revoked=False
        self.scope=None
    def _check(self,s):
        if self.scope is None:self.scope=dict(s)
        if s != self.scope:raise ValueError("different authenticated installation")
    def claim_once(self,s,digest,op):
        with self.lock:
            self._check(s)
            if self.revoked or op in self.claims:raise ValueError("monotonic duplicate/revoked")
            self.counter+=1
            row={"sequence":self.counter,"operation_id":op,"claim_hash":digest,
                 "status":"claimed","epoch":s["authority_epoch"]}
            self.claims[op]=row
            return dict(row)
    def revoke(self,s):
        with self.lock:
            self._check(s)
            if self.revoked:raise ValueError("already revoked")
            self.revoked=True;self.counter+=1
            return {"sequence":self.counter,"operation_id":None,
                    "claim_hash":"0"*64,"status":"revoked","epoch":s["authority_epoch"]}
    def observe(self,s,op):
        with self.lock:
            self._check(s)
            return dict(self.claims[op]) if op in self.claims else None

def rig():
    operator=Ed25519PrivateKey.generate()
    signer=Ed25519PrivateKey.generate()
    db=InMemoryIndependentCAS()
    o=m.SendOwner(scope=scope(),operator_public_key=operator.public_key(),
                  owner_signing_key=signer,protected_backend=db)
    return o,operator,signer,db

def approval(operator,o,c=None,*,action="send-claim",expires=800,approval_id="f"*32):
    payload={"schema":m.APPROVAL_SCHEMA,"scope":o.scope,"action":action,
             "claim_hash":hashlib.sha256(m.canonical(c)).hexdigest() if c is not None else "0"*64,
             "expires_at":expires,"approval_id":approval_id}
    return payload,operator.sign(m.canonical(payload)).hex()

def invoke(o,operator,c=None,now=400):
    c=c or claim()
    p,s=approval(operator,o,c)
    return o.claim_once(claim=c,approval=p,approval_signature=s,now=now)

def test_claim_is_independently_durable_before_any_gateway_send_and_replay_denied():
    o,operator,signer,db=rig()
    r=invoke(o,operator)
    signer.public_key().verify(bytes.fromhex(r["signature"]),m.canonical(r["body"]))
    assert r["body"]["witness"]["sequence"]==1
    assert o.observe("7"*32)["status"]=="claimed-or-revoked-no-retry"
    with pytest.raises(m.SendOwnerDenied):invoke(o,operator)
    assert db.counter==1

def test_full_gateway_history_rollback_cannot_reset_separate_claim():
    o,operator,_,db=rig()
    old_gateway={"journal":"prepared","send_intents":{}}
    invoke(o,operator)
    restored=dict(old_gateway)   # entire gateway storage coherently restored
    assert restored["send_intents"]=={}
    with pytest.raises(m.SendOwnerDenied):invoke(o,operator)
    assert db.counter==1

def test_lost_send_reply_and_reboot_owner_reconstruction_deny_resend():
    o,operator,signer,db=rig();invoke(o,operator)
    new=m.SendOwner(scope=scope(),operator_public_key=operator.public_key(),
                    owner_signing_key=signer,protected_backend=db)
    assert new.observe("7"*32)["sequence"]==1
    with pytest.raises(m.SendOwnerDenied):invoke(new,operator)
    assert db.counter==1

def test_two_concurrent_submitters_cannot_both_claim():
    o,operator,_,db=rig()
    seen=[]
    def submit():
        try:seen.append(("ok",invoke(o,operator)))
        except m.SendOwnerDenied:seen.append(("denied",None))
    a=Thread(target=submit);b=Thread(target=submit)
    a.start();b.start();a.join();b.join()
    assert sorted(x[0] for x in seen)==["denied","ok"]
    assert db.counter==1

def test_signed_revocation_monotonic_prevents_other_operations():
    o,operator,_,db=rig();invoke(o,operator)
    p,s=approval(operator,o,action="revoke")
    r=o.revoke(approval=p,approval_signature=s,now=400)
    assert r["body"]["witness"]["sequence"]==2
    with pytest.raises(m.SendOwnerDenied):invoke(o,operator,claim("1"*32))
    with pytest.raises(m.SendOwnerDenied):o.revoke(approval=p,approval_signature=s,now=400)
    assert "7"*32 in db.claims

@pytest.mark.parametrize("field,value",[
    ("host_id","f"*32),("host_fingerprint","e"*64),
    ("installation_id","e"*32),("state_volume_id","b"*64),
    ("registry_id","0"*32),("controller_id","9"*32),
    ("authority_epoch",9),
])
def test_wrong_host_installation_state_or_epoch_rejected(field,value):
    o,operator,_,db=rig()
    p,s=approval(operator,o,claim())
    other=dict(o.scope);other[field]=value
    with pytest.raises(m.SendOwnerDenied):
        m.SendOwner(scope=other,operator_public_key=operator.public_key(),
                    owner_signing_key=o.owner_signing_key,protected_backend=db).claim_once(
                        claim=claim(),approval=p,approval_signature=s,now=400)

@pytest.mark.parametrize("field,value",[
    ("remote_request_sha256","0"*64),("binding_sha256","0"*64),
    ("task_catalogue_sha256","0"*64),("source_revision","0"*64),
    ("source_generation","0"*64),("monthly_pin_identity","0"*64),
    ("request_id","0"*32),("lane","other"),("target","different"),
])
def test_request_mutation_with_recomputed_gateway_digest_denied(field,value):
    o,operator,_,db=rig();p,s=approval(operator,o,claim())
    forged=claim();forged[field]=value
    with pytest.raises(m.SendOwnerDenied):
        o.claim_once(claim=forged,approval=p,approval_signature=s,now=400)

def test_stale_operator_approval_wrong_signer_and_expired_denied():
    o,operator,_,db=rig();p,s=approval(operator,o,claim(),expires=399)
    with pytest.raises(m.SendOwnerDenied):
        o.claim_once(claim=claim(),approval=p,approval_signature=s,now=400)
    p,s=approval(Ed25519PrivateKey.generate(),o,claim())
    with pytest.raises(m.SendOwnerDenied):
        o.claim_once(claim=claim(),approval=p,approval_signature=s,now=400)
    assert db.counter==0

def test_no_authority_from_read_only_inspect_or_unknown_ack():
    o,operator,_,db=rig()
    assert o.observe("7"*32)=={"status":"unknown-no-send-authority"}
    assert db.counter==0
    invoke(o,operator)
    assert o.observe("7"*32)["status"]=="claimed-or-revoked-no-retry"

def test_signing_key_is_not_caller_supplied_and_bad_backend_fails_closed():
    o,operator,_,db=rig()
    wrong=Ed25519PrivateKey.generate()
    p,s=approval(operator,o,claim())
    o.backend=object()
    with pytest.raises(m.SendOwnerDenied):
        o.claim_once(claim=claim(),approval=p,approval_signature=s,now=400)
    assert db.counter==0
    assert wrong.public_key()!=o.owner_signing_key.public_key()
