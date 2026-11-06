"""Integrated prospective HMAC capture -> signed v1 issuer proof.

All secrets/keys here are synthetic. No GitHub delivery or native signer exists.
"""
import base64
import io
import json

from zog.root_control import graphical_task_c_capture_app as capture_app
from zog.root_control import graphical_task_c_issuance as issuer
from test_graphical_task_c_issuance import sample, pub


def test_original_raw_delivery_survives_capture_and_verifies_for_issuer(tmp_path):
    operator, event_signer, _, _, registry, args = sample()
    tmp_path.chmod(0o700)
    app=capture_app.CaptureApplication(
        {"repository_id":args["expected_repository_id"],
         "actor_id":args["expected_actor_id"],
         "actor":args["authorized_actor"]},args["secret"],tmp_path)
    request={
        "REQUEST_METHOD":"POST","PATH_INFO":"/zog/task-c/original",
        "CONTENT_TYPE":"application/json",
        "CONTENT_LENGTH":str(len(args["event_raw"])),
        "HTTP_X_GITHUB_EVENT":"issues",
        "HTTP_X_HUB_SIGNATURE_256":args["signature_header"],
        "HTTP_X_GITHUB_DELIVERY":args["delivery_id"],
        "wsgi.input":io.BytesIO(args["event_raw"])}
    statuses=[]
    # Fixture timestamp is the actual timestamp of the synthetic opened issue.
    original_now=capture_app.time.time
    try:
        capture_app.time.time=lambda:400
        assert b"".join(app(request,lambda status,headers: statuses.append(status)))
    finally:
        capture_app.time.time=original_now
    assert statuses==["202 Accepted"]
    record=json.loads((tmp_path/(args["delivery_id"]+".json")).read_text())
    raw=base64.b64decode(record["raw_event_base64"],validate=True)
    assert raw==args["event_raw"]
    assert record["signature_header"]==args["signature_header"]
    assert record["original_request_sha256"]==registry[
        next(i for i,r in registry.items() if i==r["mapping"]["original"]["operation_id"])
    ]["mapping"]["original"]["original_request_sha256"]
    signed=issuer.attest_original_github_event(
        **{**args,"event_raw":raw,"signature_header":record["signature_header"],
           "delivery_id":record["delivery_id"]})
    assert issuer.verify_public_receipt(
        registry=registry,event=signed,
        operator_public=pub(operator),issuer_public=pub(event_signer),now=400)[
            "status"]=="signed-issuance-source-verified-not-installed"
    second=[]
    assert b"".join(app({
        **request,"wsgi.input":io.BytesIO(args["event_raw"])},
        lambda status,headers:second.append(status)))
    assert second==["403 Forbidden"]
    assert sorted(p.name for p in tmp_path.iterdir())==[
        ".capture.lock",args["delivery_id"]+".json"]
