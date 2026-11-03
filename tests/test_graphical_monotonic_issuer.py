"""Synthetic independently operated monotonic checkpoint issuer source tests."""
import json
import os
from concurrent.futures import ThreadPoolExecutor
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from zog.root_control.graphical_monotonic_issuer import (
    Issuer,CheckpointDenied,canonical,DOMAIN,LOCK,sha)

@pytest.fixture
def storage(tmp_path):
    d=tmp_path/"separate-admin"
    d.mkdir(mode=0o700)
    os.chmod(d,0o700)
    signer=Ed25519PrivateKey.generate()
    fd=os.open(d,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
    yield d,fd,signer,Issuer(fd,signer=signer)
    os.close(fd)

def args(epoch,seq=1,prior=None,op="operation-1"):
    return {"host_id":"host-A","installation_id":"installation-A",
        "expected_epoch":epoch-1,"expected_sequence":seq,
        "expected_pin_sha256":prior,"next_epoch":epoch,
        "next_pin_sha256":("%064x"%epoch),
        "next_approval_sha256":("%064x"%(100+epoch)),
        "operation_id":op}

def test_exact_cas_signed_challenge_restart_and_lost_ack(storage):
    d,fd,key,issuer=storage
    first=issuer.compare_and_advance(**args(1))
    assert first["epoch"]==1 and first["sequence"]==2
    assert issuer.compare_and_advance(**args(1))==first
    challenge="a"*48
    signed=json.loads(issuer.read_signed(host_id="host-A",
                installation_id="installation-A",nonce=challenge))
    signature=__import__("base64").b64decode(signed.pop("signature_ed25519"))
    key.public_key().verify(signature,DOMAIN+canonical(signed))
    assert signed["pin_sha256"]=="%064x"%1
    assert signed["nonce"]==challenge
    assert "private_key" not in signed
    after=Issuer(fd,signer=key)
    second=after.compare_and_advance(**args(
        2,seq=2,prior="%064x"%1,op="operation-2"))
    assert second["epoch"]==2 and second["sequence"]==3
    assert after.compare_and_advance(**args(2,seq=2,prior="%064x"%1,
        op="operation-2"))==second
    with pytest.raises(CheckpointDenied):
        issuer.compare_and_advance(**args(1))


def test_concurrent_cas_only_one_authority(storage):
    d,fd,key,issuer=storage
    results=[]
    def run(i):
        try:
            results.append(("ok",issuer.compare_and_advance(
                **args(1,op="operator-"+str(i)))))
        except CheckpointDenied:
            results.append(("denied",i))
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(run,range(8)))
    assert [x[0] for x in results].count("ok")==1
    assert json.loads(next(d.glob("*.json")).read_text())["sequence"]==2


def test_coherent_host_rollback_cannot_lower_remote(storage):
    d,fd,key,issuer=storage
    issuer.compare_and_advance(**args(1))
    issuer.compare_and_advance(**args(2,seq=2,prior="%064x"%1,
                               op="operation-2"))
    with pytest.raises(CheckpointDenied):
        issuer.compare_and_advance(**args(2,seq=2,prior="%064x"%1,
                                  op="substitute-key"))
    with pytest.raises(CheckpointDenied):
        issuer.compare_and_advance(**args(1,op="operation-1"))
    # Current record is not rolled back even after an attempted replay.
    assert json.loads(next(d.glob("*.json")).read_text())["epoch"]==2


def test_replacement_key_missing_ledger_and_foreign_host(storage):
    d,fd,key,issuer=storage
    issuer.compare_and_advance(**args(1))
    with pytest.raises(CheckpointDenied):
        issuer.compare_and_advance(**{**args(1),"next_pin_sha256":"f"*64})
    newkey=Ed25519PrivateKey.generate()
    proof=issuer.read_signed(host_id="host-A",installation_id="installation-A",nonce="b"*48)
    doc=json.loads(proof)
    from base64 import b64decode
    with pytest.raises(InvalidSignature):
        newkey.public_key().verify(b64decode(doc["signature_ed25519"]),
           DOMAIN+canonical({k:v for k,v in doc.items() if k!="signature_ed25519"}))
    assert json.loads(issuer.read_signed(host_id="host-A",installation_id="other",nonce="a"*48))["epoch"]==0
    # The source backend alone cannot distinguish a deliberate rollback of
    # its own storage; this MUST be delegated to external non-rollbackable
    # service storage before any native deployment.


def test_symlinked_state_and_replaced_lock_fail_closed(storage):
    d,fd,key,issuer=storage
    issuer.compare_and_advance(**args(1))
    state=next(d.glob("*.json"))
    state.rename(d/"retained-original")
    state.symlink_to(d/"retained-original")
    with pytest.raises(OSError):
        issuer.read_signed(host_id="host-A",installation_id="installation-A",nonce="a"*48)
    state.unlink()
    old=(d/LOCK)
    old.rename(d/"retained-lock")
    old.write_bytes(b"")
    old.chmod(0o600)
    with pytest.raises(CheckpointDenied):
        issuer.read_signed(host_id="host-A",installation_id="installation-A",nonce="a"*48)
