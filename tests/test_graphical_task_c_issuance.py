"""Task C prospective issuer: exact protocol interoperability, synthetic only."""
import hashlib
import hmac
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import pytest

from zog.root_control import graphical_task_c_issuance as issuer
from zog.root_control import graphical_operation_owner_source as owner
from zog.root_control import graphical_task_c_owner as taskc
from zog.root_control import graphical_task_c_trust_authority as trust

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_graphical_operation_owner_source import request as source_request
from test_graphical_task_c_trust_authority import setup as purpose_setup
from zog.host_deploy.gateway.github_dispatch import ISSUE_MARKER
from zog.host_deploy.gateway.protocol import request_digest


def pub(private):
    return private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def sample():
    operator, event_signer = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    stage = source_request()
    pre = {**stage, "operation_id": taskc.preflight_id(
        stage["request_id"], stage["operation_id"])}
    intent = {
        "schema": 1, "request_id": stage["request_id"],
        "workspace_id":"fedcba9876543210fedcba9876543210",
        "operation":"build.submit",
        "source":{"repository":"zog144/image-build", "commit": stage["source_revision"]},
        "parameters":{"lane":"graphical-lane", "task":"graphics-x11-core-image-v1"}}
    github_request = {**intent, "origin":{
        "repository":"zog144/host-deploy", "issue_number":17,
        "trigger_actor":"zog144"}}
    orig = {"request_id":stage["request_id"],
            "original_request_sha256":request_digest(github_request),
            "origin_repository":"zog144/host-deploy", "origin_issue_number":17,
            "origin_trigger_actor":"zog144", "operation_id":stage["operation_id"],
            "stage":"submit", "ordinal":0,
            "binding_sha256":"a"*64, "remote_request_sha256":"b"*64}
    checkpoint = {
        "schema":trust.ORIGINAL_SCHEMA,
        "host_id":stage["host_id"],
        "installation_id":stage["installation_id"],
        "state_volume_id":stage["state_volume_id"],
        "checkpoint_account_id":"123456789012",
        "checkpoint_region":"us-east-1",
        "checkpoint_bucket":"synthetic-original-bucket",
        "checkpoint_prefix":"synthetic/original/",
        "checkpoint_scope_sha256":owner.digest(owner.scope_from_request(stage)),
        "checkpoint_genesis_sha256":"sha256:"+"e"*64,
        "checkpoint_role_arn":"arn:aws:iam::123456789012:role/SyntheticOriginalWriter",
        "root_source_revision":trust.OWNER_SOURCE,
    }
    records = issuer.issue_original_registry(
        stage_request=stage, preflight_request=pre, stage_original=orig,
        original_checkpoint=checkpoint,
        approval_ids={stage["operation_id"]:"c"*32, pre["operation_id"]:"d"*32},
        expires_at=480, now=400,
        sign_operator=operator.sign, pinned_operator_public=pub(operator))
    webhook = {"action":"opened",
               "repository":{"full_name":"zog144/host-deploy", "id":98123},
               "sender":{"login":"zog144", "id":3456},
               "issue":{"number":17, "state":"open",
                        "body":ISSUE_MARKER + "\n" + "\x60\x60\x60json\n" + json.dumps(intent) + "\n\x60\x60\x60",
                        "created_at":"1970-01-01T00:06:30Z",
                        "user":{"login":"zog144", "id":3456}}}
    secret = b"synthetic-not-production-key-"+b"q"*32
    raw = json.dumps(webhook).encode()
    args = {"event_raw":raw,
            "signature_header":"sha256="+hmac.new(secret,raw,hashlib.sha256).hexdigest(),
            "delivery_id":"synthetic-delivery", "secret":secret,
            "registry":taskc.ProtectedOriginalRegistry(
                records,pinned_operator_public_key=pub(operator)),
            "authorized_actor":"zog144",
            "expected_repository_id":98123, "expected_actor_id":3456,
            "original_commit_sha":"a"*40,
            "issued_at":400,"expires_at":450,
            "pinned_issuer_public":pub(event_signer), "sign_issuer":event_signer.sign}
    return operator,event_signer,stage,pre,records,args


def test_exact_v1_issuer_registry_webhook_and_verifier_roundtrip():
    op, ev, stage, pre, registry, args = sample()
    evidence = issuer.attest_original_github_event(**args)
    verified = issuer.verify_public_receipt(
        registry=registry, event=evidence, operator_public=pub(op),
        issuer_public=pub(ev), now=400)
    assert verified["status"] == "signed-issuance-source-verified-not-installed"
    assert set(registry) == {stage["operation_id"], pre["operation_id"]}
    assert evidence["records"][stage["operation_id"]]["github_event_sha256"] == issuer.sha(args["event_raw"])


@pytest.mark.parametrize("fault", [
    "wrong_hmac","altered_raw","wrong_repo_id","wrong_actor_id",
    "wrong_actor","wrong_issue","wrong_action","expired",
    "wrong_issuer","duplicate_json","stale_event","unsafe_delivery"])
def test_forged_or_stale_webhook_does_not_issue(fault):
    _,_,_,_,_,base = sample()
    args = base.copy()
    if fault == "wrong_hmac":
        args["signature_header"] = "sha256=" + "0"*64
    elif fault == "altered_raw":
        args["event_raw"] += b" "
    elif fault == "wrong_repo_id":
        args["expected_repository_id"] += 1
    elif fault == "wrong_actor_id":
        args["expected_actor_id"] += 1
    elif fault == "wrong_actor":
        args["authorized_actor"] = "intruder"
    elif fault == "expired":
        args["expires_at"] = 100000
    elif fault == "wrong_issuer":
        args["pinned_issuer_public"] = pub(Ed25519PrivateKey.generate())
    elif fault == "stale_event":
        args["issued_at"] = 1400
    elif fault == "unsafe_delivery":
        args["delivery_id"] = "../a"
    else:
        event = json.loads(args["event_raw"])
        if fault == "wrong_issue":
            event["issue"]["number"] = 999
        elif fault == "wrong_action":
            event["action"] = "edited"
        args["event_raw"] = json.dumps(event).encode()
        if fault == "duplicate_json":
            args["event_raw"] = args["event_raw"].replace(
                b'"action": "opened"',
                b'"action": "opened", "action": "opened"')
        args["signature_header"] = "sha256="+hmac.new(
            args["secret"],args["event_raw"],hashlib.sha256).hexdigest()
    with pytest.raises((issuer.IssuanceDenied, owner.OperationDenied)):
        issuer.attest_original_github_event(**args)


@pytest.mark.parametrize("fault", [
    "preflight_mismatch","same_approval_id","expired","bad_uuid","wrong_public"])
def test_operator_mapping_rejects_wrong_selected_authority(fault):
    operator,_,stage,pre,registry,_ = sample()
    original = registry[stage["operation_id"]]["mapping"]["original"]
    checkpoint = {
        "schema":trust.ORIGINAL_SCHEMA,
        "host_id":stage["host_id"],
        "installation_id":stage["installation_id"],
        "state_volume_id":stage["state_volume_id"],
        "checkpoint_account_id":"123456789012",
        "checkpoint_region":"us-east-1",
        "checkpoint_bucket":"synthetic-original-bucket",
        "checkpoint_prefix":"synthetic/original/",
        "checkpoint_scope_sha256":owner.digest(owner.scope_from_request(stage)),
        "checkpoint_genesis_sha256":"sha256:"+"e"*64,
        "checkpoint_role_arn":"arn:aws:iam::123456789012:role/SyntheticOriginalWriter",
        "root_source_revision":trust.OWNER_SOURCE,
    }
    args = {"stage_request":stage, "preflight_request":pre,
            "stage_original":original, "original_checkpoint":checkpoint, "approval_ids":{
                stage["operation_id"]:"c"*32, pre["operation_id"]:"d"*32},
            "expires_at":480,"now":400,
            "sign_operator":operator.sign,
            "pinned_operator_public":pub(operator)}
    if fault == "preflight_mismatch":
        args["preflight_request"] = {**pre,"authority_epoch":3}
    if fault == "same_approval_id":
        args["approval_ids"][pre["operation_id"]] = "c"*32
    if fault == "expired":
        args["expires_at"] = 1301
    if fault == "bad_uuid":
        args["stage_request"] = {**stage,"request_id":"BAD"}
    if fault == "wrong_public":
        args["pinned_operator_public"] = pub(Ed25519PrivateKey.generate())
    with pytest.raises((issuer.IssuanceDenied, owner.OperationDenied)):
        issuer.issue_original_registry(**args)


def test_operator_purpose_exact_existing_v1_body():
    fixture = purpose_setup()
    body = issuer.prepare_broker_purpose(
        record=fixture["record"], registry=fixture["registry"],
        origin_evidence=fixture["evidence"],
        operator_public=fixture["operator_key"],
        issuer_public=fixture["issuer_key"],
        pin=fixture["pin"], broker_config=fixture["broker_config"],
        root_row=fixture["root_row"],
        readonly_role_arn=fixture["approval"]["readonly_role_arn"],
        expires_at=450,now=400)
    assert body == {k:v for k,v in fixture["approval"].items()
                    if k != "signature_ed25519"}


def test_signed_revocation_is_not_an_s3_mutation():
    f = purpose_setup()
    operator = Ed25519PrivateKey.generate()
    scope = owner.scope_from_request(
        next(iter(f["registry"].entries.values()))["owner_request"])
    result = issuer.issue_revocation(
        approved_scope=scope, approval_id="a"*32,expires_at=430,now=400,
        sign_operator=operator.sign,pinned_operator_public=pub(operator))
    assert result["action"] == "revoke"
    assert "signature_ed25519" in result


def test_manual_cli_does_not_generate_keys_or_enable_sender():
    from zog.root_control import graphical_task_c_issuance_cli as cli
    import inspect
    code = inspect.getsource(cli)
    assert "generate()" not in code
    assert "put_object" not in code
    assert "os.O_EXCL" in code
    assert cli.ROLE_NAMES["operator"] != cli.ROLE_NAMES["event"]
    assert cli.ROOT != cli.OUTPUT


@pytest.mark.parametrize("field,value",(
    ("host_id","f"*64),
    ("state_volume_id","d"*64),
    ("checkpoint_scope_sha256","sha256:"+"0"*64),
    ("checkpoint_genesis_sha256","missing"),
    ("checkpoint_role_arn","arn:aws:iam::999999999999:role/ForgedWriter"),
    ("root_source_revision","0"*40),
))
def test_operator_rejects_forged_checkpoint_before_signing(field,value):
    op,_,stage,pre,registry,_=sample()
    original=registry[stage["operation_id"]]["mapping"]["original"]
    record={
        "schema":trust.ORIGINAL_SCHEMA,
        "host_id":stage["host_id"],"installation_id":stage["installation_id"],
        "state_volume_id":stage["state_volume_id"],
        "checkpoint_account_id":"123456789012",
        "checkpoint_region":"us-east-1",
        "checkpoint_bucket":"synthetic-original-bucket",
        "checkpoint_prefix":"synthetic/original/",
        "checkpoint_scope_sha256":owner.digest(owner.scope_from_request(stage)),
        "checkpoint_genesis_sha256":"sha256:"+"e"*64,
        "checkpoint_role_arn":"arn:aws:iam::123456789012:role/SyntheticOriginalWriter",
        "root_source_revision":trust.OWNER_SOURCE,
    }
    record[field]=value
    with pytest.raises((issuer.IssuanceDenied,owner.OperationDenied)):
        issuer.issue_original_registry(
            stage_request=stage,preflight_request=pre,stage_original=original,
            original_checkpoint=record,
            approval_ids={stage["operation_id"]:"c"*32,pre["operation_id"]:"d"*32},
            expires_at=480,now=400,sign_operator=op.sign,
            pinned_operator_public=pub(op))
