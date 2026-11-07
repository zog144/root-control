"""V3 installation-scope broker-purpose signature and old-v2 denial regressions.

Only synthetic keys and S3; never actual native approval, role or webhook.
"""
import base64
import copy
import sys
from pathlib import Path

import pytest

from zog.root_control import graphical_operation_owner_source as op
from zog.root_control import graphical_task_c_v3_readonly as v3
from zog.root_control import graphical_installation_storage_authority as storage
from zog.root_control import graphical_task_c_trust_authority as trust
from zog.host_deploy.gateway import graphics_owner_trust_history as history

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_graphical_task_c_trust_authority import setup as old
from test_graphical_installation_storage_authority import selected as installed


def selected():
    test = old(signing_fixture=True)
    source = installed()
    record = source["authority"]
    commit = {"schema":"synthetic-install-commit",
              "installation_scope_sha256":record["installation_scope_sha256"],
              "accepted_at":400}
    scope = test["record"]["checkpoint_scope_sha256"]
    pin = copy.deepcopy(test["pin"])
    selected_root_sha = "sha256:" + "6"*64
    selected_broker_sha = test["selected_broker_sha"]
    pin.update(schema=history.PIN_SCHEMA_V3,
               installed_owner_source=selected_root_sha[7:],
               original_checkpoint_sha256=op.digest(record))
    test["pin"] = pin
    test["pin_sha"] = op.digest(pin)
    root = test["root_row"]
    root["originals"] = test.pop("original_records")
    root["schema"] = "zog-protected-task-c-installed-runtime-v3"
    root["storage_authority"]={
        "schema":"zog-task-c-installed-storage-selection-v1",
        "storage_authority_sha256":op.digest(record),
        "storage_commit_sha256":op.digest(commit),
        "installation_scope_sha256":record["installation_scope_sha256"],
        "registry_sha256":record["registry_sha256"],
    }
    root["checkpoint"] = {
        "account_id":record["checkpoint_account_id"],
        "region":record["checkpoint_region"],
        "bucket":record["checkpoint_bucket"],
        "prefix":record["checkpoint_prefix"],
        "genesis_sha256":record["checkpoint_genesis_sha256"],
        "role_arn":record["checkpoint_writer_role_arn"],
    }
    broker=test["broker_config"]
    broker["schema"]=v3.BROKER_CONFIG_SCHEMA
    broker.pop("root_source_revision")
    broker.pop("broker_source_revision")
    broker["root_source_sha256"]=selected_root_sha
    broker["broker_source_sha256"]=selected_broker_sha
    body={
        "schema":v3.PURPOSE_SCHEMA,
        "pin_sha256":test["pin_sha"],
        "original_checkpoint_sha256":op.digest(record),
        "original_event_sha256":op.digest(test["evidence"]),
        "operator_public_sha256":trust.digest_bytes(test["operator_key"]),
        "issuer_public_sha256":trust.digest_bytes(test["issuer_key"]),
        "owner_source_sha256":selected_root_sha,
        "broker_source_sha256":selected_broker_sha,
        "readonly_role_arn":record["checkpoint_reader_role_arn"],
        "writer_role_arn":record["checkpoint_writer_role_arn"],
        "ssm_role_arn":root["ssm"]["role_arn"],
        "host_id":root["host_id"],
        "installation_id":root["installation_id"],
        "state_volume_id":root["state_volume_id"],
        "scope_sha256":scope,
        "installation_scope_sha256":record["installation_scope_sha256"],
        "installation_storage_commit_sha256":op.digest(commit),
        "gateway_uid":broker["gateway_uid"],
        "gateway_gid":broker["gateway_gid"],
        "gateway_cgroup":broker["gateway_cgroup"],
        "gateway_executable_sha256":broker["gateway_executable_sha256"],
        "expires_at":450,
    }
    test["approval"]={
        **body, "signature_ed25519":base64.b64encode(
            test["operator_private"].sign(
                v3.PURPOSE_DOMAIN + op.canonical(body))).decode("ascii"),
    }
    for key in ("record","record_sha","operator_private","issuer_private","now"):
        test.pop(key,None)
    test["selected_root_source_sha"]=selected_root_sha
    test["storage_record"]=record
    test["storage_commit"]=commit
    test["now"]=400
    return test


def verify(row):
    return v3.verify_installation_broker_selection(**row)


def test_installed_v3_binding_keeps_operation_scope_separate():
    row=selected()
    role,scope=verify(row)
    assert role==row["storage_record"]["checkpoint_reader_role_arn"]
    assert scope==row["pin"]["scope_sha256"]
    assert scope!=row["storage_record"]["installation_scope_sha256"]
    assert row["root_row"]["schema"].endswith("v3")
    assert row["pin"]["schema"]==history.PIN_SCHEMA_V3


@pytest.mark.parametrize("change", (
    "v2_pin","v2_runtime","v2_purpose","tampered_commit",
    "tampered_storage","changed_operation_scope","changed_origin",
    "changed_operator","reader_as_writer","wrong_source",
    "wrong_signer","replaced_pin","bad_gateway","wrong_root_digest","wrong_broker_digest",
))
def test_v3_separate_signed_bindings_fail_closed(change):
    row=selected()
    if change=="v2_pin":
        row["pin"]["schema"]=history.PIN_SCHEMA_V2
    elif change=="v2_runtime":
        row["root_row"]["schema"]="zog-protected-task-c-installed-runtime-v2"
    elif change=="v2_purpose":
        row["approval"]["schema"]=trust.PURPOSE_SCHEMA
    elif change=="tampered_commit":
        row["storage_commit"]["accepted_at"]=401
    elif change=="tampered_storage":
        row["storage_record"]["checkpoint_prefix"]="other/"
    elif change=="changed_operation_scope":
        row["approval"]["scope_sha256"]="sha256:"+"f"*64
    elif change=="changed_origin":
        row["evidence"]["records"].clear()
    elif change=="changed_operator":
        row["operator_key"]=b"x"*32
    elif change=="reader_as_writer":
        row["storage_record"]["checkpoint_reader_role_arn"]=row[
            "storage_record"]["checkpoint_writer_role_arn"]
    elif change=="wrong_source":
        row["broker_config"]["root_source_sha256"]="sha256:"+"0"*64
    elif change=="wrong_signer":
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        row["broker_signer"]=Ed25519PrivateKey.generate()
    elif change=="replaced_pin":
        row["pin_sha"]="sha256:"+"0"*64
    elif change=="bad_gateway":
        row["broker_config"]["gateway_uid"]=0
    elif change=="wrong_root_digest":
        row["selected_root_source_sha"]="sha256:"+"e"*64
    elif change=="wrong_broker_digest":
        row["broker_config"]["broker_source_sha256"]="sha256:"+"e"*64
    with pytest.raises(op.OperationDenied):
        verify(row)
