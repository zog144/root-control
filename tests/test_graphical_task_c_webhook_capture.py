"""Keyless source-only capture of authentic GitHub issue-opened deliveries."""
import io
import json
from pathlib import Path
import sys
import pytest

from zog.root_control import graphical_task_c_webhook_capture as capture
from zog.root_control import graphical_task_c_issuance as issue

sys.path.insert(0,str(Path(__file__).resolve().parent))
from test_graphical_task_c_issuance import sample


def environ(args):
    return {
        "REQUEST_METHOD":"POST",
        "PATH_INFO":"/zog/task-c/original",
        "HTTP_X_GITHUB_EVENT":"issues",
        "CONTENT_TYPE":"application/json",
        "CONTENT_LENGTH":str(len(args["event_raw"])),
        "HTTP_X_HUB_SIGNATURE_256":args["signature_header"],
        "HTTP_X_GITHUB_DELIVERY":args["delivery_id"],
        "wsgi.input":io.BytesIO(args["event_raw"]),
    }


def receive(args, archive, *, changes=None):
    incoming=environ(args)
    if changes:
        incoming.update(changes)
    statuses=[]
    result=capture.capture_wsgi(
        incoming,lambda status, headers:statuses.append(status),
        policy={"repository_id":98123,"actor_id":3456,"actor":"zog144"},
        secret=args["secret"],directory=archive,now=400)
    return statuses[0],b"".join(result)


def test_capture_verifies_original_hmac_and_durable_once_only(tmp_path):
    _,_,_,_,_,args=sample()
    root=tmp_path/"spool"
    root.mkdir(mode=0o700)
    assert receive(args,root)[0]=="202 Accepted"
    receipt=root/(args["delivery_id"]+".json")
    assert receipt.is_file()
    value=json.loads(receipt.read_text())
    assert value["schema"]=="zog-task-c-original-github-webhook-capture-v1"
    assert value["event_sha256"]==issue.sha(args["event_raw"])
    assert value["original_request_sha256"]==args["registry"].entries[
        next(op for op,e in args["registry"].entries.items()
             if op==e["stage_operation_id"])]["original"]["original_request_sha256"]
    assert receive(args,root)[0]=="403 Forbidden"
    assert len(list(root.iterdir()))==1


@pytest.mark.parametrize("change",[
    {"HTTP_X_HUB_SIGNATURE_256":"sha256="+"0"*64},
    {"HTTP_X_GITHUB_EVENT":"issue_comment"},
    {"REQUEST_METHOD":"GET"},
    {"PATH_INFO":"/not-original"},
    {"CONTENT_TYPE":"text/plain"},
    {"CONTENT_LENGTH":"9999999"},
    {"CONTENT_LENGTH":"2"},
    {"HTTP_X_GITHUB_DELIVERY":"../attacker"},
])
def test_invalid_requests_do_not_capture(tmp_path,change):
    _,_,_,_,_,args=sample()
    root=tmp_path/"spool"
    root.mkdir(mode=0o700)
    status,_=receive(args,root,changes=change)
    assert status=="403 Forbidden"
    assert list(root.iterdir())==[]


def test_capture_does_not_sign_event_or_expose_keys(tmp_path):
    _,_,_,_,_,args=sample()
    root=tmp_path/"spool"
    root.mkdir(mode=0o700)
    assert receive(args,root)[0]=="202 Accepted"
    assert "signature_ed25519" not in json.loads(
        (root/(args["delivery_id"]+".json")).read_text())
    assert "sign_issuer" not in capture.publish_capture.__code__.co_varnames
