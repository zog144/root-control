import json
import os
import socket
import pytest
from zog.root_control import graphical_operation_owner_ipc_admission as ipc
from zog.root_control import graphical_operation_owner_source as owner
from test_graphical_operation_owner_source import request

def values():
    req=request()
    frame={"schema":ipc.SCHEMA,"action":"submit-original",
           "request_id":req["request_id"],"operation_id":req["operation_id"],
           "original_request_sha256":req["original_request_sha256"][7:],
           "origin_repository":"zog144/host-deploy",
           "origin_issue_number":17,"origin_trigger_actor":"zog144",
           "stage":req["stage"],"ordinal":req["ordinal"],
           "binding_sha256":"1"*64,
           "remote_request_sha256":req["remote_request_sha256"][7:],
           "nonce":"b"*48}
    selected={"schema":"zog-graphical-owner-original-github-map-v1",
              "selected":True,"approved_request_sha256":owner.digest(req),
              "selected_original":ipc.original_identity(frame),
              "host_installation_state_sha256":"sha256:"+"e"*64}
    return req,frame,selected

def test_original_github_metadata_and_real_kernel_peer_source_predicates():
    req,frame,selected=values()
    left,right=socket.socketpair(socket.AF_UNIX,socket.SOCK_STREAM)
    try:
        result=ipc.admit_source_only(owner.canonical(frame),right,
            installed_gateway_uid=os.getuid(),installed_gateway_gid=os.getgid(),
            protected_original_map=selected,protected_owner_request=req)
        assert result["ssm_send_authorized"] is False
        assert result["native_preflight_authenticated"] is False
        assert result["nonce"]==frame["nonce"]
    finally:left.close();right.close()

@pytest.mark.parametrize("field,value",[
    ("origin_repository","evil/repo"),("origin_issue_number",18),
    ("origin_trigger_actor","another"),("operation_id","0"*32),
    ("action","preflight-original"),("remote_request_sha256","f"*64),
    ("binding_sha256","0"*64),
])
def test_changed_original_request_never_uses_an_installed_preapproval(field,value):
    req,frame,selected=values()
    left,right=socket.socketpair(socket.AF_UNIX,socket.SOCK_STREAM)
    try:
        frame[field]=value
        with pytest.raises(owner.OperationDenied):
            ipc.admit_source_only(owner.canonical(frame),right,
                installed_gateway_uid=os.getuid(),installed_gateway_gid=os.getgid(),
                protected_original_map=selected,protected_owner_request=req)
    finally:left.close();right.close()

def test_wrong_uid_gid_or_client_chosen_map_rejected():
    req,frame,selected=values()
    left,right=socket.socketpair(socket.AF_UNIX,socket.SOCK_STREAM)
    try:
        with pytest.raises(owner.OperationDenied):
            ipc.admit_source_only(owner.canonical(frame),right,
                installed_gateway_uid=os.getuid()+1,installed_gateway_gid=os.getgid(),
                protected_original_map=selected,protected_owner_request=req)
        bad={**selected,"approved_request_sha256":"sha256:"+"0"*64}
        with pytest.raises(owner.OperationDenied):
            ipc.admit_source_only(owner.canonical(frame),right,
                installed_gateway_uid=os.getuid(),installed_gateway_gid=os.getgid(),
                protected_original_map=bad,protected_owner_request=req)
    finally:left.close();right.close()

def test_noncanonical_duplicate_or_trailing_frames_rejected():
    req,frame,selected=values()
    assert ipc.parse(owner.canonical(frame))==frame
    for data in (owner.canonical(frame)+b"\n",owner.canonical(frame)+b" ",
                 owner.canonical(frame).replace(b'"nonce":',b'"nonce":"0","nonce":'),
                 b'{"schema":"irrelevant"}',b"x"*9000):
        with pytest.raises(owner.OperationDenied):
            ipc.parse(data)

def test_fresh_nonce_is_not_frozen_authority_but_never_grants_send():
    req,frame,selected=values()
    left,right=socket.socketpair(socket.AF_UNIX,socket.SOCK_STREAM)
    try:
        frame["nonce"]="0"*48
        observed=ipc.admit_source_only(owner.canonical(frame),right,
            installed_gateway_uid=os.getuid(),installed_gateway_gid=os.getgid(),
            protected_original_map=selected,protected_owner_request=req)
        assert observed["nonce"]=="0"*48
        assert observed["ssm_send_authorized"] is False
    finally:left.close();right.close()
