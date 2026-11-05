"""Read-only broker: independently signed original selection and no credential fallback.

All keys, operation IDs, roles and S3 history here are disposable source fixtures.
These tests cannot establish native signer/issuer or AWS permission acceptance.
"""
import base64
import copy
from pathlib import Path
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import pytest
from botocore.exceptions import ClientError

from zog.root_control import graphical_operation_owner_source as owner
from zog.root_control import graphical_task_c_owner as taskc
from zog.root_control import graphical_task_c_origin as origin
from zog.root_control import graphical_task_c_trust_authority as authority
from zog.root_control.graphical_s3_checkpoint import S3AppendOnlyCheckpoint, SCHEMA

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_graphical_operation_owner_source import request
from test_graphical_task_c_owner import _signed_record
from test_graphical_s3_checkpoint import Remote


def public(private):
    return private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def setup():
    operator = Ed25519PrivateKey.generate()
    issuer = Ed25519PrivateKey.generate()
    broker = Ed25519PrivateKey.generate()
    original_request = request()
    stage_id = "9" * 32
    original_request["operation_id"] = stage_id
    base = {
        "request_id": original_request["request_id"],
        "original_request_sha256": "a" * 64,
        "origin_repository": "zog144/host-deploy",
        "origin_issue_number": 17, "origin_trigger_actor": "zog144",
        "stage": "submit", "ordinal": 0, "binding_sha256": "b" * 64,
        "remote_request_sha256": "c" * 64,
    }
    records = {}
    for operation_id in (
        stage_id, taskc.preflight_id(original_request["request_id"], stage_id)
    ):
        req = {**original_request, "operation_id": operation_id}
        app = {
            "schema": owner.APPROVAL_SCHEMA, "approval_id": "d" * 32,
            "request_sha256": owner.digest(req),
            "scope_sha256": owner.digest(owner.scope_from_request(req)),
            "expires_at": 500,
        }
        signed_app = {
            **app, "signature_ed25519": base64.b64encode(
                operator.sign(owner.APPROVAL_DOMAIN + owner.canonical(app))
            ).decode("ascii"),
        }
        records[operation_id] = _signed_record(
            operator, req,
            {**base, "operation_id": operation_id},
            stage_id, signed_app,
        )
    registry = taskc.ProtectedOriginalRegistry(
        records, pinned_operator_public_key=public(operator))
    scope = owner.digest(owner.scope_from_request(original_request))
    record = {
        "schema": authority.ORIGINAL_SCHEMA,
        "host_id": original_request["host_id"],
        "installation_id": original_request["installation_id"],
        "state_volume_id": original_request["state_volume_id"],
        "checkpoint_account_id": "123456789012",
        "checkpoint_region": "us-east-1",
        "checkpoint_bucket": "original-bucket",
        "checkpoint_prefix": "original/task-c/",
        "checkpoint_scope_sha256": scope,
        "checkpoint_genesis_sha256": "sha256:" + "e"*64,
        "checkpoint_role_arn":
            "arn:aws:iam::123456789012:role/OriginalCheckpointWriter",
        "root_source_revision": authority.OWNER_SOURCE,
    }
    record_sha = authority.digest_bytes(owner.canonical(record))
    evidence_body = {
        "schema": origin.SCHEMA, "scope_sha256": scope,
        "issued_at": 300, "expires_at": 500,
        "records": {
            stage_id: {
                "original": registry.entries[stage_id]["original"],
                "github_event_sha256": "sha256:"+"f"*64,
                "github_delivery_id": "original-synthetic-delivery",
                "original_commit_sha": "c"*40,
            }
        },
    }
    evidence = {
        **evidence_body, "signature_ed25519": base64.b64encode(
            issuer.sign(origin.DOMAIN + owner.canonical(evidence_body))
        ).decode("ascii"),
    }
    broker_sha = "sha256:"+"7"*64
    pin = {
        "schema": "zog-graphical-task-c-gateway-trust-pin-v1",
        "broker_public_key": public(broker).hex(),
        "owner_observation_public_key": "o".encode().hex()*32,
        "original_checkpoint_sha256": record_sha,
        "installed_owner_source": authority.OWNER_SOURCE,
        "installed_broker_source": broker_sha[7:],
        "installation_id": record["installation_id"],
        "state_volume_id": record["state_volume_id"],
        "scope_sha256": scope,
    }
    root_row = {
        "schema": "zog-protected-task-c-installed-runtime-v2",
        "host_id": record["host_id"],
        "installation_id": record["installation_id"],
        "state_volume_id": record["state_volume_id"],
        "operator_key_sha256": authority.digest_bytes(public(operator)),
        "origin_issuer_public_sha256": authority.digest_bytes(public(issuer)),
        "origin_evidence_sha256": authority.digest_bytes(owner.canonical(evidence)),
        "observation_public_sha256": authority.digest_bytes(bytes.fromhex(
            pin["owner_observation_public_key"])),
        "checkpoint": {
            "account_id": record["checkpoint_account_id"],
            "region": record["checkpoint_region"],
            "bucket": record["checkpoint_bucket"],
            "prefix": record["checkpoint_prefix"],
            "genesis_sha256": record["checkpoint_genesis_sha256"],
            "role_arn": record["checkpoint_role_arn"],
        },
        "ssm": {
            "role_arn": "arn:aws:iam::123456789012:role/OriginalSsmSender"
        },
    }
    broker_config = {
        "schema": "zog-task-c-readonly-broker-native-selection-v1",
        "broker_source_revision": authority.BROKER_SOURCE,
        "root_source_revision": authority.OWNER_SOURCE,
        "gateway_uid": 15310, "gateway_gid": 15311,
        "gateway_cgroup": "/system.slice/zog-graphical-gateway.service",
        "gateway_executable_sha256": "sha256:" + "8"*64,
        "boot_id": "synthetic-not-current-boot",
    }
    approval_body = {
        "schema": authority.PURPOSE_SCHEMA,
        "pin_sha256": authority.digest_bytes(owner.canonical(pin)),
        "original_checkpoint_sha256": record_sha,
        "original_event_sha256": authority.digest_bytes(owner.canonical(evidence)),
        "operator_public_sha256": authority.digest_bytes(public(operator)),
        "issuer_public_sha256": authority.digest_bytes(public(issuer)),
        "owner_source_revision": authority.OWNER_SOURCE,
        "broker_source_revision": authority.BROKER_SOURCE,
        "readonly_role_arn":
            "arn:aws:iam::123456789012:role/OriginalGetObjectOnly",
        "writer_role_arn": record["checkpoint_role_arn"],
        "ssm_role_arn": root_row["ssm"]["role_arn"],
        "host_id": record["host_id"],
        "installation_id": record["installation_id"],
        "state_volume_id": record["state_volume_id"],
        "scope_sha256": scope,
        "gateway_uid": broker_config["gateway_uid"],
        "gateway_gid": broker_config["gateway_gid"],
        "gateway_cgroup": broker_config["gateway_cgroup"],
        "gateway_executable_sha256": broker_config["gateway_executable_sha256"],
        "expires_at": 450,
    }
    approval = {
        **approval_body, "signature_ed25519": base64.b64encode(
            operator.sign(authority.PURPOSE_DOMAIN + owner.canonical(approval_body))
        ).decode("ascii"),
    }
    return dict(
        record=record, record_sha=record_sha, root_row=root_row,
        broker_config=broker_config,
        registry=registry, evidence=evidence, operator_key=public(operator),
        issuer_key=public(issuer),
        observation_public=bytes.fromhex(pin["owner_observation_public_key"]),
        pin=pin, pin_sha=authority.digest_bytes(owner.canonical(pin)),
        approval=approval, broker_signer=broker,
        selected_broker_sha=broker_sha, now=400,
    )


def review(rows):
    return authority.verify_original_selection(**rows)


def test_original_operator_issuer_pin_and_3_distinct_roles_selected():
    row = setup()
    readonly, scope = review(row)
    assert readonly == row["approval"]["readonly_role_arn"]
    assert scope == row["record"]["checkpoint_scope_sha256"]


@pytest.mark.parametrize("tamper", (
    "prefix", "region", "writer", "new_genesis", "issuer",
    "operator", "broker", "owner_key", "session_role",
    "same_role", "record_sha", "wrong_source", "expired", "approval_sig",
    "origin_event", "wrong_host", "pin_replacement",
    "gateway_uid", "gateway_executable", "gateway_cgroup", "mixed_scope",
))
def test_no_substitution_and_no_fabricated_authority(tamper):
    row = setup()
    if tamper == "prefix":
        row["record"]["checkpoint_prefix"] = "fresh-prefix/"
    elif tamper == "region":
        row["record"]["checkpoint_region"] = "eu-west-1"
    elif tamper == "writer":
        row["record"]["checkpoint_role_arn"] = (
            "arn:aws:iam::123456789012:role/ReplacedWriter")
    elif tamper == "new_genesis":
        row["record"]["checkpoint_genesis_sha256"] = "sha256:"+"0"*64
    elif tamper == "issuer":
        row["issuer_key"] = public(Ed25519PrivateKey.generate())
    elif tamper == "operator":
        row["operator_key"] = public(Ed25519PrivateKey.generate())
    elif tamper == "broker":
        row["broker_signer"] = Ed25519PrivateKey.generate()
    elif tamper == "owner_key":
        row["observation_public"] = b"p"*32
    elif tamper == "session_role":
        row["approval"]["readonly_role_arn"] = (
            "arn:aws:iam::123456789012:role/SubstitutedReadOnly")
    elif tamper == "same_role":
        row["approval"]["readonly_role_arn"] = row["record"]["checkpoint_role_arn"]
    elif tamper == "record_sha":
        row["record_sha"] = "sha256:"+"9"*64
    elif tamper == "wrong_source":
        row["selected_broker_sha"] = "sha256:"+"1"*64
    elif tamper == "expired":
        row["now"] = 451
    elif tamper == "approval_sig":
        row["approval"]["signature_ed25519"] = "x"
    elif tamper == "origin_event":
        row["evidence"]["records"].clear()
    elif tamper == "wrong_host":
        row["root_row"]["host_id"] = "0"*64
    elif tamper == "pin_replacement":
        row["pin"]["original_checkpoint_sha256"] = "sha256:"+"c"*64
    elif tamper == "gateway_uid":
        row["broker_config"]["gateway_uid"] += 1
    elif tamper == "gateway_executable":
        row["broker_config"]["gateway_executable_sha256"] = "sha256:"+"0"*64
    elif tamper == "gateway_cgroup":
        row["broker_config"]["gateway_cgroup"] = "/system.slice/swap.service"
    elif tamper == "mixed_scope":
        selected = next(iter(row["registry"].entries.values()))
        selected["owner_request"]["authority_epoch"] += 1
    with pytest.raises(owner.OperationDenied):
        review(row)


def test_getobject_only_exposes_no_write_or_list_capability():
    class Client:
        def __init__(self):
            self.calls = []
        def get_object(self, **kw):
            self.calls.append(kw)
            return {}
        def put_object(self, **kw):
            raise AssertionError("never accessible")
        def list_objects_v2(self, **kw):
            raise AssertionError("never accessible")
    client = Client()
    limited = authority.GetObjectOnly(client)
    assert not hasattr(limited, "put_object")
    assert not hasattr(limited, "list_objects_v2")
    assert limited.get_object(Bucket="b") == {}
    assert client.calls == [{"Bucket": "b"}]


def test_missing_next_record_access_denied_is_not_accepted_as_history_head():
    class Restricted:
        def get_object(self, **kwargs):
            raise ClientError({
                "Error":{"Code":"AccessDenied"},
                "ResponseMetadata":{"HTTPStatusCode":403},
            }, "GetObject")
    scope = "sha256:"+"a"*64
    checkpoint = S3AppendOnlyCheckpoint(
        authority.GetObjectOnly(Restricted()),
        bucket="original-bucket", prefix="original/task-c/",
        account_id="123456789012", scope_digest=scope,
        genesis_sha256="sha256:"+"b"*64)
    with pytest.raises(owner.OperationDenied):
        checkpoint.current_witness(scope)


def test_native_owner_and_broker_gates_remain_disabled():
    from zog.root_control import graphical_task_c_service
    assert graphical_task_c_service.NATIVE_TASK_C_SEND_ADMISSION_IMPLEMENTED is False
    from zog.host_deploy.gateway import graphics_owner_trust_daemon
    assert graphics_owner_trust_daemon.NATIVE_TRUST_BROKER_ADMISSION_IMPLEMENTED is False
