"""No-secret tests for the selected HTTPS credential receiver.

No network, active certificate authority, retained Host, or issuer execution.
"""
import base64
import hashlib
import json
import os
import time
from pathlib import Path

import pytest

from zog.box_control.project import Project
from zog.root_control import issuer_https_receiver as receiver
from zog.root_control.issuer_receipt_common import CredentialReceiptDenied
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def profile(project="/approved/project"):
    return dict(schema=receiver.PROFILE_SCHEMA, project=project,
        https_origin="https://command.example.org",
        tls_authority_pin_sha256="a"*64, station_signer_pin_sha256="b"*64,
        owner_authority_sha256="c"*64, host_id="73c77e1f-53b8-4a73-92a1-e610814db521",
        installation_id="73c77e1f-53b8-4a73-92a1-e610814db522",
        state_volume_id="73c77e1f-53b8-4a73-92a1-e610814db523",
        host_fingerprint="d"*64, registry_id="command-center",
        authorization_id="e"*64, assignment_id="73c77e1f-53b8-4a73-92a1-e610814db524",
        assignment_revision=8, receipt_sha256="f"*64, purpose=receiver.PURPOSE,
        credential_id="73c77e1f-53b8-4a73-92a1-e610814db525",
        credential_revision=5,
        grant_id="73c77e1f-53b8-4a73-92a1-e610814db526",
        storage_id="73c77e1f-53b8-4a73-92a1-e610814db527",
        policy_sha256="1"*64, consumer_uid=24321)


def signed_reply(p, request, wire, key, *, token=b"private-token-placeholder-ABCDEFGHIJKLMNOP"):
    names=("host_id", "installation_id", "state_volume_id", "registry_id",
           "host_fingerprint", "authorization_id", "assignment_id",
           "assignment_revision", "receipt_sha256", "credential_id",
           "credential_revision", "storage_id", "grant_id", "policy_sha256", "consumer_uid")
    signed={n:p[n] for n in names}
    now=int(time.time())
    signed.update(schema=receiver.RESPONSE_SCHEMA, purpose=receiver.PURPOSE,
        consumer=receiver.CONSUMER, request_sha256=hashlib.sha256(wire).hexdigest(),
        nonce=request["nonce"], issued_at=now, expires_at=now+30,
        token_base64=base64.b64encode(token).decode())
    signed["signature"]=base64.b64encode(
        key.sign(receiver._SIGNING_DOMAIN+receiver.canonical(signed))).decode()
    return receiver.canonical(signed)


def test_https_request_carries_exact_authority_purpose_and_one_nonce():
    p=profile()
    request, wire=receiver._request(p)
    assert request["purpose"]=="issuer-cloudflare-dns01"
    assert request["consumer"]=="certify-manage"
    assert request["consumer_uid"]==24321
    assert len(wire)<=receiver._MAX_REQUEST
    assert json.loads(wire)==request
    assert request["credential_revision"]==5


@pytest.mark.parametrize("changed", [
    "host_id", "installation_id", "state_volume_id", "registry_id",
    "host_fingerprint", "authorization_id", "assignment_id",
    "assignment_revision", "receipt_sha256", "credential_id",
    "credential_revision", "storage_id", "grant_id", "policy_sha256",
    "consumer_uid", "purpose", "consumer", "nonce", "request_sha256",
])
def test_station_signed_response_rejects_cross_identity_and_revision_substitution(changed):
    p=profile()
    req,wire=receiver._request(p)
    key=Ed25519PrivateKey.generate()
    response=json.loads(signed_reply(p,req,wire,key))
    response[changed] = response[changed]+1 if type(response[changed]) is int else "other"
    # Even an independently valid station signature cannot authorize a
    # different Host/consumer/revision/request.
    signature=response.pop("signature")
    response["signature"]=base64.b64encode(
        key.sign(receiver._SIGNING_DOMAIN+receiver.canonical(response))).decode()
    with pytest.raises(CredentialReceiptDenied):
        receiver._signed_response(receiver.canonical(response),request=req,
            request_bytes=wire,profile=p,authority_key=key.public_key())


def test_accepted_response_and_wrong_signer_expiry_partial_trailing_and_dup_fields():
    p=profile()
    req,wire=receiver._request(p)
    key=Ed25519PrivateKey.generate()
    signed=signed_reply(p,req,wire,key)
    assert receiver._signed_response(signed,request=req,request_bytes=wire,
           profile=p,authority_key=key.public_key()).startswith(b"private-token")
    other=Ed25519PrivateKey.generate()
    with pytest.raises(CredentialReceiptDenied):
        receiver._signed_response(signed,request=req,request_bytes=wire,
            profile=p,authority_key=other.public_key())
    for bad in (signed[:-2], signed+b"extra", b"{}", b" "*8193):
        with pytest.raises(CredentialReceiptDenied):
            receiver._signed_response(bad,request=req,request_bytes=wire,
                profile=p,authority_key=key.public_key())
    response=json.loads(signed)
    response["expires_at"]=int(time.time())-1
    response.pop("signature")
    response["signature"]=base64.b64encode(
        key.sign(receiver._SIGNING_DOMAIN+receiver.canonical(response))).decode()
    with pytest.raises(CredentialReceiptDenied):
        receiver._signed_response(receiver.canonical(response),request=req,
            request_bytes=wire,profile=p,authority_key=key.public_key())


def test_installed_profile_refuses_changed_tls_ca_owner_and_signer(monkeypatch):
    p=profile()
    project=Project(Path(p["project"]))
    owner=b"approved owner"
    signer=b'{"registry_id":"command-center","authority_public_key":"AQ=="}'
    ca=b"-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----"
    p["owner_authority_sha256"]=hashlib.sha256(owner).hexdigest()
    p["station_signer_pin_sha256"]=hashlib.sha256(signer).hexdigest()
    p["tls_authority_pin_sha256"]=hashlib.sha256(ca).hexdigest()
    sources={
      "/state/host-install/certificate-owner-authority/authority.json":owner,
      "/etc/zog/host-install/certificate-assignment-authority.json":signer,
      str(receiver._TLS_CA):ca,
    }
    monkeypatch.setattr(receiver,"_root_regular",lambda path,**kwargs:sources[str(path)])
    monkeypatch.setattr(receiver,"_profile_path",lambda project:"profile")
    monkeypatch.setattr(receiver,"_pairs",lambda pairs:dict(pairs))
    # This local test injects the parsed protected profile; real production
    # path still opens checked root:root file and rejects duplicate fields.
    pinned = {k:v for k,v in p.items() if k not in ("credential_id","policy_sha256")}
    sources["profile"]=receiver.canonical(pinned)
    assert receiver._profile(project)==pinned
    for name in (str(receiver._TLS_CA),
                 "/state/host-install/certificate-owner-authority/authority.json",
                 "/etc/zog/host-install/certificate-assignment-authority.json"):
        previous=sources[name]
        sources[name]=previous+b"modified"
        with pytest.raises(CredentialReceiptDenied):
            receiver._profile(project)
        sources[name]=previous
    p["https_origin"]="https://command.example.org:8443"
    sources["profile"]=receiver.canonical({k:v for k,v in p.items()
                                            if k not in ("credential_id","policy_sha256")})
    with pytest.raises(CredentialReceiptDenied):
        receiver._profile(project)


def test_root_operation_denies_without_native_authorization_before_remote(monkeypatch):
    p=profile("/safe/project")
    seen=[]
    monkeypatch.setattr(receiver.credentials,"_require_root",lambda:None)
    monkeypatch.setattr(receiver,"_profile",lambda project:p)
    monkeypatch.setattr(receiver,"_approval",lambda *a:seen.append("approval"))
    monkeypatch.setattr(receiver,"_https_post",lambda *a,**kw:seen.append("network"))
    with pytest.raises(CredentialReceiptDenied):
        receiver.receive_and_install(p["project"],private_identity=None,
            admission={"status":"protected-source-preflight-only"})
    assert seen==[]


def test_one_time_request_is_fsynced_before_network_and_never_reused(tmp_path, monkeypatch):
    p=profile("/safe/project")
    project=Project(Path(p["project"]))
    directory=tmp_path/"https-receipts"
    directory.mkdir()
    monkeypatch.setattr(receiver.credentials,"AUTH_ROOT",tmp_path)
    monkeypatch.setattr(receiver.credentials,"_check_root_directory",lambda path:None)
    receiver._consume_request(project,"f"*32,profile=p)
    saved=list(directory.iterdir())
    assert len(saved)==1 and saved[0].read_bytes()==b"consumed\n"
    with pytest.raises(CredentialReceiptDenied):
        receiver._consume_request(project,"f"*32,profile=p)


def test_verified_token_uses_only_fd_installer_and_second_authority_check(monkeypatch):
    p=profile("/safe/project")
    key=Ed25519PrivateKey.generate()
    seen=[]
    monkeypatch.setattr(receiver.credentials,"_require_root",lambda:None)
    monkeypatch.setattr(receiver,"_profile",lambda project:p)
    monkeypatch.setattr(receiver,"_approval",lambda *a:seen.append("approved") or (p["authorization_id"], {"credential_id":p["credential_id"],"policy_sha256":p["policy_sha256"]}))
    monkeypatch.setattr(receiver,"_pin_key",lambda profile:key.public_key())
    monkeypatch.setattr(receiver,"_consume_request",lambda *a,**kw:seen.append("nonce"))
    def fake_transport(pr,request,identity,*,transport):
        seen.append("network")
        return signed_reply(p,request,receiver.canonical(request),key)
    monkeypatch.setattr(receiver,"_https_post",fake_transport)
    def fake_installer(project,fd,*,expected_authorization_id):
        seen.append("installed")
        assert expected_authorization_id==p["authorization_id"]
        assert os.read(fd,4096).startswith(b"private-token")
        return {"status":"installed"}
    monkeypatch.setattr(receiver.credentials,"install_from_fd",fake_installer)
    result=receiver.receive_and_install(p["project"],private_identity=object(),
         admission={"status":"protected-source-preflight-only",
                    "native_https_accepted":True,"owner":{"status":"retained"}})
    assert result["status"]=="installed"
    assert seen==["approved","nonce","network","approved","installed"]
