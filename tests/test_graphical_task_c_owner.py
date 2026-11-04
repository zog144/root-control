"""Exact Task C original GitHub IPC and independent operation mapping.

All owners and sockets here are disposable fixtures. This source-only test
NEVER enables an SSM sender, installs root credentials or supplies native GO.
"""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import socket
import sys
import threading

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import pytest

from zog.root_control import graphical_operation_owner_source as owner
from zog.root_control import graphical_task_c_owner as taskc
from zog.root_control.graphical_native_owner import ProtectedLedger
from zog.root_control.graphical_owner_checkpoint import SeparateDurableCheckpoint

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_graphical_operation_owner_source import request


def _signed_record(operator, req, hint, stage_id, approval):
    body = {"schema": taskc.MAPPING_SCHEMA,
            "original": taskc.original(hint),
            "stage_operation_id": stage_id,
            "owner_request_sha256": owner.digest(req),
            "approval_sha256": owner.digest(approval)}
    signature = operator.sign(taskc.MAPPING_DOMAIN + owner.canonical(body))
    return {"mapping":{**body,"signature_ed25519":
                       base64.b64encode(signature).decode("ascii")},
            "owner_request":req,
            "original_operator_approval":approval}


def _fixture():
    stage_id="9"*32
    orig=request()
    orig["operation_id"]=stage_id
    gateway_origin={"request_id":orig["request_id"],
                    "original_request_sha256":"a"*64,
                    "origin_repository":"zog144/host-deploy",
                    "origin_issue_number":17,
                    "origin_trigger_actor":"zog144",
                    "stage":"submit","ordinal":0,
                    "binding_sha256":"b"*64,
                    "remote_request_sha256":"c"*64}
    operation_id=taskc.preflight_id(orig["request_id"],stage_id)
    assert operation_id != stage_id
    operator=Ed25519PrivateKey.generate()
    public=operator.public_key().public_bytes(
        serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    records={}
    frames={}
    for action,op in (("submit-original",stage_id),
                      ("preflight-original",operation_id)):
        req={**orig,"operation_id":op}
        raw={"schema":taskc.IPC_SCHEMA,"nonce":"f"*48,
             "action":action,**gateway_origin,"operation_id":op}
        body={"schema":owner.APPROVAL_SCHEMA,"approval_id":"d"*32,
              "request_sha256":owner.digest(req),
              "scope_sha256":owner.digest(owner.scope_from_request(req)),
              "expires_at":550}
        grant={**body,"signature_ed25519":base64.b64encode(
            operator.sign(owner.APPROVAL_DOMAIN+owner.canonical(body))).decode("ascii")}
        records[op]=_signed_record(operator,req,raw,stage_id,grant)
        frames[action]=raw
    return taskc.ProtectedOriginalRegistry(
        records,pinned_operator_public_key=public),records,frames,public


def test_distinct_preflight_and_stage_are_independently_approved():
    registry,records,frames,key=_fixture()
    a=registry.select(taskc.parse_frame(taskc.canonical(frames["preflight-original"])+b"\n"))
    b=registry.select(taskc.parse_frame(taskc.canonical(frames["submit-original"])+b"\n"))
    assert a["owner_request"]["operation_id"] != b["owner_request"]["operation_id"]
    assert a["approval"] != b["approval"]
    assert registry.entries[a["owner_request"]["operation_id"]]["stage_operation_id"] == (
        b["owner_request"]["operation_id"])


@pytest.mark.parametrize("field,value",(
    ("origin_issue_number",18),
    ("origin_trigger_actor","unexpected"),
    ("origin_repository","another/repo"),
    ("request_id","0"*32),
    ("original_request_sha256","0"*64),
    ("remote_request_sha256","0"*64),
    ("binding_sha256","0"*64),
    ("stage","inspect"),("ordinal",1),("operation_id","0"*32),
))
def test_gateway_cannot_replace_original_git_identity_or_preflight(field,value):
    registry,records,frames,key=_fixture()
    forged={**frames["preflight-original"],field:value}
    if field=="origin_repository":
        with pytest.raises(owner.OperationDenied):
            taskc.parse_frame(taskc.canonical(forged)+b"\n")
    else:
        with pytest.raises(owner.OperationDenied):
            registry.select(taskc.parse_frame(taskc.canonical(forged)+b"\n"))


def test_preflight_mapping_must_be_derived_and_operator_signed():
    _,records,frames,pub=_fixture()
    x=copy.deepcopy(records)
    pre=frames["preflight-original"]["operation_id"]
    x[pre]["mapping"]["stage_operation_id"]="0"*32
    with pytest.raises(owner.OperationDenied):
        taskc.ProtectedOriginalRegistry(x,pinned_operator_public_key=pub)
    x=copy.deepcopy(records)
    x[pre]["mapping"]["original"]["origin_trigger_actor"]="attacker"
    with pytest.raises(owner.OperationDenied):
        taskc.ProtectedOriginalRegistry(x,pinned_operator_public_key=pub)
    x=copy.deepcopy(records)
    x[pre]["owner_request"]["authority_epoch"]=3
    with pytest.raises(owner.OperationDenied):
        taskc.ProtectedOriginalRegistry(x,pinned_operator_public_key=pub)
    x=copy.deepcopy(records);x.pop(frames["submit-original"]["operation_id"])
    registry=taskc.ProtectedOriginalRegistry(x,pinned_operator_public_key=pub)
    with pytest.raises(owner.OperationDenied):
        registry.select(frames["preflight-original"])


def test_noncanonical_duplicate_or_script_bearing_task_c_frames_denied():
    _,_,frames,_=_fixture()
    frame=frames["submit-original"]
    good=taskc.canonical(frame)+b"\n"
    assert taskc.parse_frame(good)==frame
    for bad in (
        good[:-1], good+b"\n",
        good+b"{}", good[:-1]+b" {}\n",
        good.replace(b'"nonce":',b'"nonce":"x","nonce":'),
        taskc.canonical({**frame,"commands":"echo send"})+b"\n",
        good.replace(b":",b": ",1),
        good[:-1]+b"\x00\n",
    ):
        with pytest.raises(owner.OperationDenied):
            taskc.parse_frame(bad)


def test_stream_peer_auth_and_source_only_no_send(tmp_path):
    registry,_,frames,_=_fixture()
    a,b=socket.socketpair(socket.AF_UNIX,socket.SOCK_STREAM)
    try:
        b.sendall(taskc.canonical(frames["preflight-original"])+b"\n")
        result=taskc.inspect_one(a,registry=registry,
                                 gateway_uid=os.getuid(),
                                 gateway_gid=os.getgid())
        assert result["native_ssm_sent"] is False
        assert result["status"]=="selected-source-only-native-held"
    finally:
        a.close();b.close()


def test_bad_unix_peer_cannot_inspect_mapping():
    registry,_,frames,_=_fixture()
    a,b=socket.socketpair(socket.AF_UNIX,socket.SOCK_STREAM)
    try:
        b.sendall(taskc.canonical(frames["submit-original"])+b"\n")
        with pytest.raises(owner.OperationDenied):
            taskc.inspect_one(a,registry=registry,
                              gateway_uid=os.getuid()+1,
                              gateway_gid=os.getgid())
    finally:
        a.close();b.close()


@pytest.mark.parametrize("which",("ledger","checkpoint"))
def test_independent_open_file_flock_serializes_real_thread_contention(tmp_path,which):
    local=tmp_path/"owner";external=tmp_path/"checkpoint"
    for path in (local,external):
        path.mkdir(mode=0o700)
        (path/".selected-graphical-owner.lock").write_bytes(b"original")
        (path/".selected-graphical-owner.lock").chmod(0o600)
        (path/"claims").mkdir(mode=0o700)
    (local/"results").mkdir(mode=0o700)
    checkpoint=SeparateDurableCheckpoint(external)
    ledger=ProtectedLedger(local,external_checkpoint=checkpoint)
    target=ledger if which=="ledger" else checkpoint
    hold=threading.Event()
    release=threading.Event()
    entered=threading.Event()
    def first():
        with target.locked():
            entered.set()
            assert release.wait(3)
    def second():
        with target.locked():
            hold.set()
    t=threading.Thread(target=first)
    u=threading.Thread(target=second)
    t.start()
    assert entered.wait(3)
    u.start()
    assert not hold.wait(.08), "two owners must not hold the same lock"
    release.set()
    t.join(3);u.join(3)
    assert not t.is_alive() and not u.is_alive()
    assert hold.is_set()


def test_task_c_native_service_keeps_hard_send_admission_hold(monkeypatch):
    from zog.root_control import graphical_task_c_service as executable
    assert executable.SOCKET == "/run/zog/graphical-operation-owner.sock"
    assert executable.NATIVE_TASK_C_SEND_ADMISSION_IMPLEMENTED is False
    monkeypatch.setattr(executable.os, "geteuid", lambda:0)
    monkeypatch.setattr(executable.sys, "argv", ["graphical_task_c_service"])
    monkeypatch.setattr(executable,"selected_original_registry",
                        lambda: pytest.fail("installer source must not be reached"))
    monkeypatch.setattr(executable,"_socket_from_systemd",
                        lambda: pytest.fail("systemd socket must not be reached"))
    with pytest.raises(owner.OperationDenied):
        executable.main()


def test_graphical_native_sender_dependencies_are_explicit_optional_source_inputs():
    import tomllib
    p=Path(__file__).resolve().parents[1]/"pyproject.toml"
    row=tomllib.loads(p.read_text())
    extras=row["project"]["optional-dependencies"]["graphical-native-owner"]
    assert any(x.startswith("cryptography") for x in extras)
    assert any(x.startswith("boto3") for x in extras)
    assert "graphical-native-owner" not in row["project"].get("dependencies", [])
