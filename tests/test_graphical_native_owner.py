"""Durable selected owner, external checkpoint and Unix IPC source regressions.

Disposable source tests use local files plus fake sender, never AWS, root,
canonical STATE, real installation or privileged deployment.
"""
import base64
import copy
import json
import os
from pathlib import Path
import socket
import threading
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import pytest

from zog.root_control import graphical_operation_owner_source as base
from zog.root_control.graphical_native_owner import (
    ProtectedLedger, SelectedOwner, serve_one, RPC_SCHEMA,
)
from zog.root_control.graphical_owner_checkpoint import SeparateDurableCheckpoint
from test_graphical_operation_owner_source import request


def storage(tmp_path, *, external=True):
    local=tmp_path/"owner";remote=tmp_path/"external"
    for parent in (local, remote):
        parent.mkdir(mode=0o700)
        (parent/".selected-graphical-owner.lock").write_bytes(b"identity")
        (parent/".selected-graphical-owner.lock").chmod(0o600)
        (parent/"claims").mkdir(mode=0o700)
    (local/"results").mkdir(mode=0o700)
    checkpoint=SeparateDurableCheckpoint(remote)
    return local, remote, checkpoint, ProtectedLedger(
        local,external_checkpoint=checkpoint)


class Sender:
    def __init__(self, *, lost=False):
        self.calls=[]
        self.lost=lost
    def send_fixed(self, operation_id, command):
        self.calls.append((operation_id,dict(command)))
        if self.lost:
            raise TimeoutError("lost SSM acknowledgement")
        return "selected-original-ssm"


def setup(tmp_path, *, lost=False):
    local,remote,checkpoint,ledger=storage(tmp_path)
    req=request()
    operator=Ed25519PrivateKey.generate()
    signer=Ed25519PrivateKey.generate()
    fixed=Sender(lost=lost)
    selection={
        "scope":base.scope_from_request(req),
        "approved":{req["operation_id"]:base.digest(req)},
        "identity":base.digest(base.scope_from_request(req)),
        "commands":{req["operation_id"]:{
            "approval_id":"c"*32, "script_sha256":"sha256:"+"a"*64,
            "timeout_seconds":120}},
    }
    pub=operator.public_key().public_bytes(
        serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    service=SelectedOwner(ledger,installed=selection,
                          pinned_operator_key=pub,
                          observation_signer=signer,sender=fixed)
    body={"schema":base.APPROVAL_SCHEMA,"approval_id":"c"*32,
          "request_sha256":base.digest(req),
          "scope_sha256":base.digest(selection["scope"]),
          "expires_at":550}
    sig=operator.sign(base.APPROVAL_DOMAIN+base.canonical(body))
    approval={**body,"signature_ed25519":base64.b64encode(sig).decode("ascii")}
    return req,selection,operator,signer,pub,approval,service,fixed,local,remote


def test_durable_claim_and_result_survive_full_owner_restart(tmp_path):
    req,selection,operator,signer,pub,grant,owner,sender,local,remote=setup(tmp_path)
    assert owner.submit(req,grant,now=400)["outcome"]=="SENT_ORIGINAL"
    assert len(sender.calls)==1
    # Drop service and open both protected volumes as a separate process would.
    checkpoint=SeparateDurableCheckpoint(remote)
    ledger=ProtectedLedger(local,external_checkpoint=checkpoint)
    retry=SelectedOwner(ledger,installed=selection,pinned_operator_key=pub,
                        observation_signer=signer,
                        sender=Sender())
    with pytest.raises(base.OperationDenied):
        retry.submit(copy.deepcopy(req),grant,now=400)
    observed=retry.observe(req, "a"*48)
    assert observed["outcome"]=="SENT_ORIGINAL"
    assert observed["command_id"]=="selected-original-ssm"
    assert len(sender.calls)==1


def test_claim_lost_ack_is_irrevocable_even_after_storage_restart(tmp_path):
    req,selection,operator,signer,pub,grant,first,sender,local,remote=setup(
        tmp_path,lost=True)
    with pytest.raises(TimeoutError):
        first.submit(req,grant,now=400)
    assert len(sender.calls)==1
    assert (remote/"claims"/(req["operation_id"]+".json")).exists()
    assert (local/"claims"/(req["operation_id"]+".json")).exists()
    assert not (local/"results"/(req["operation_id"]+".json")).exists()
    second=SelectedOwner(
        ProtectedLedger(local,external_checkpoint=SeparateDurableCheckpoint(remote)),
        installed=selection,pinned_operator_key=pub,
        observation_signer=signer,sender=Sender())
    with pytest.raises(base.OperationDenied):
        second.submit(req,grant,now=400)
    assert second.observe(req,"c"*48)["outcome"]=="CLAIMED_UNCERTAIN"


def test_checkpoint_first_crash_does_not_resend_with_missing_local_file(tmp_path):
    req,selection,operator,signer,pub,grant,first,sender,local,remote=setup(tmp_path)
    checkpoint=first.ledger.checkpoint
    checkpoint.claim_once(selection["identity"],req["operation_id"],base.digest(req))
    # Crash before the local claim file was installed; gateway journal rolled back.
    assert not list((local/"claims").iterdir())
    reboot=SelectedOwner(
        ProtectedLedger(local,external_checkpoint=SeparateDurableCheckpoint(remote)),
        installed=selection,pinned_operator_key=pub,
        observation_signer=signer,sender=Sender())
    with pytest.raises(base.OperationDenied):
        reboot.submit(req,grant,now=400)
    assert sender.calls==[]


def test_gateway_rollback_cannot_rewind_checkpoint_and_owner_claim(tmp_path):
    req,selection,operator,signer,pub,grant,first,sender,local,remote=setup(tmp_path)
    first.submit(req,grant,now=400)
    # Corrupt protected *local* ledger separately. External checkpoint should
    # still deny duplicate; this does not prove resistance to rollback of both.
    (local/"claims"/(req["operation_id"]+".json")).unlink()
    with pytest.raises(base.OperationDenied):
        first.submit(req,grant,now=400)
    assert len(sender.calls)==1


def test_signed_revoke_same_protected_lock_denies_send(tmp_path):
    req,selection,operator,signer,pub,grant,first,sender,local,remote=setup(tmp_path)
    body={"schema":base.REVOCATION_APPROVAL_SCHEMA,
          "approval_id":selection["identity"][:32],
          "scope_sha256":base.digest(selection["scope"]),
          "action":"revoke","expires_at":600}
    signed={**body,"signature_ed25519":base64.b64encode(
        operator.sign(base.REVOCATION_APPROVAL_DOMAIN+base.canonical(body))
        ).decode("ascii")}
    assert first.revoke(signed,now=400)=={"status":"revoked"}
    with pytest.raises(base.OperationDenied):
        first.submit(req,grant,now=400)
    assert sender.calls==[]
    # Both local state and external checkpoint record revocation.
    assert (local/"revoked.json").exists()
    assert (remote/"revoked.json").exists()


def test_lock_inode_replacement_fails_closed(tmp_path):
    req,selection,operator,signer,pub,grant,first,sender,local,remote=setup(tmp_path)
    lock=local/".selected-graphical-owner.lock"
    lock.unlink()
    lock.write_bytes(b"replacement")
    lock.chmod(0o600)
    with pytest.raises(base.OperationDenied):
        first.submit(req,grant,now=400)
    assert sender.calls==[]


def test_installed_operator_key_and_scope_cannot_be_replaced_by_ipc(tmp_path):
    req,selection,operator,signer,pub,grant,first,sender,local,remote=setup(tmp_path)
    altered=copy.deepcopy(req)
    altered["state_volume_id"]="e"*64
    with pytest.raises(base.OperationDenied):
        first.submit(altered,grant,now=400)
    bad=copy.deepcopy(grant)
    bad["signature_ed25519"]="!"*88
    with pytest.raises(base.OperationDenied):
        first.submit(req,bad,now=400)
    assert sender.calls==[]


def test_kernel_unix_peer_and_strict_ipc_one_time_send(tmp_path):
    req,selection,operator,signer,pub,grant,first,sender,local,remote=setup(tmp_path)
    a,b=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
    try:
        msg={"schema":RPC_SCHEMA,"action":"submit","request":req,
             "approval":grant,"nonce":None}
        b.send(base.canonical(msg))
        response=serve_one(a,first,expected_uid=os.getuid(),
                           expected_gid=os.getgid(),now=400)
        assert response["outcome"]=="SENT_ORIGINAL"
        assert json.loads(b.recv(8192))["command_id"]=="selected-original-ssm"
        assert len(sender.calls)==1
    finally:
        a.close();b.close()


def test_untrusted_peer_and_arbitrary_command_fields_denied(tmp_path):
    req,selection,operator,signer,pub,grant,first,sender,local,remote=setup(tmp_path)
    a,b=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
    try:
        b.send(base.canonical({"schema":RPC_SCHEMA,"action":"submit",
                               "request":req,"approval":grant,"nonce":None}))
        with pytest.raises(base.OperationDenied):
            serve_one(a,first,expected_uid=os.getuid()+1,
                      expected_gid=os.getgid(),now=400)
        assert sender.calls==[]
    finally:a.close();b.close()
    a,b=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
    try:
        b.send(base.canonical({"schema":RPC_SCHEMA,"action":"submit",
                               "request":req,"approval":grant,"nonce":None,
                               "script":"rm -rf /"}))
        with pytest.raises(base.OperationDenied):
            serve_one(a,first,expected_uid=os.getuid(),
                      expected_gid=os.getgid(),now=400)
        assert sender.calls==[]
    finally:a.close();b.close()


def test_compiled_native_sender_has_no_default_aws_credentials_or_gateway_script():
    from zog.root_control import graphical_owner_service as native
    import inspect
    code=inspect.getsource(native.FixedSSMSender._session)
    assert "aws_access_key_id=" in code
    assert "aws_secret_access_key=" in code
    assert "aws_session_token=" in code
    assert "boto3.client(" not in code
    code=inspect.getsource(native.FixedSSMSender.send_fixed)
    assert "InstanceIds=[self.install[\"instance_id\"]]" in code
    assert "DocumentName=\"AWS-RunShellScript\"" in code
    assert "script_sha256" in code
