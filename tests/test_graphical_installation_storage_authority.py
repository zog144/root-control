"""Installation authority and per-operation authorization, synthetic source only."""
import base64
import copy
import hashlib
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from zog.root_control import graphical_installation_storage_authority as s
from zog.root_control import graphical_operation_owner_source as op

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_graphical_operation_owner_source import request


def pub(private):
    return private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def selected():
    r = request()
    registrar, operator = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    body = {"schema": s.REGISTRY_SCHEMA,
            **{k: r[k] for k in s.SCOPE_KEYS}}
    registry = {**body, "signature_ed25519": base64.b64encode(
        registrar.sign(s.REGISTRY_DOMAIN + op.canonical(body))).decode("ascii")}
    scope, scope_sha = s.installation_scope(
        registry, pinned_registry_public=pub(registrar))
    registry_sha = op.digest(registry)
    anchor = "sha256:" + "a"*64
    authority = {
        "schema": s.AUTHORITY_SCHEMA, "mode": s.SOURCE_MODE,
        "registry_sha256": registry_sha,
        "installation_scope_sha256": scope_sha,
        "checkpoint_account_id": "123456789012",
        "checkpoint_region": "us-east-1",
        "checkpoint_bucket": "synthetic-first-establishment",
        "checkpoint_prefix": "installations/accepted-prospective/",
        "checkpoint_genesis_sha256": op.digest(
            s.prospective_genesis(scope_sha, registry_sha)),
        "checkpoint_writer_role_arn":
            "arn:aws:iam::123456789012:role/ProspectiveWriter",
        "checkpoint_reader_role_arn":
            "arn:aws:iam::123456789012:role/ProspectiveReadOnly",
        "anchor_identity_sha256": anchor,
    }
    grant_body = {**{k: authority[k] for k in (
        "mode", "registry_sha256", "installation_scope_sha256",
        "checkpoint_account_id", "checkpoint_region", "checkpoint_bucket",
        "checkpoint_prefix", "checkpoint_genesis_sha256",
        "checkpoint_writer_role_arn", "checkpoint_reader_role_arn",
        "anchor_identity_sha256")},
        "schema": s.APPROVAL_SCHEMA,
        "retention_disposition_sha256": "sha256:" + "b"*64,
        "operator_public_sha256": s._sha(pub(operator)),
        "expires_at": 450,
    }
    grant = {**grant_body, "signature_ed25519": base64.b64encode(
        operator.sign(s.APPROVAL_DOMAIN + op.canonical(grant_body))
        ).decode("ascii")}
    authority["approval_sha256"] = op.digest(grant)
    return dict(request=r, registry=registry, registrar=pub(registrar),
                operator=pub(operator), authority=authority,
                grant=grant, anchor=anchor, now=400)


def verify(row):
    return s.verify_installation_storage_selection(
        registry=row["registry"], pinned_registry_public=row["registrar"],
        authority=row["authority"], signed_storage_approval=row["grant"],
        pinned_operator_public=row["operator"],
        independently_retained_anchor_sha256=row["anchor"], now=row["now"])


def test_stable_installation_scope_does_not_depend_on_catalogue_or_approval():
    row=selected()
    result=verify(row)
    assert result["status"]=="INSTALLATION_STORAGE_SOURCE_ONLY"
    assert result["native_storage_accepted"] is False
    assert result["ssm_authorized"] is False
    req=row["request"]
    changed=copy.deepcopy(req)
    changed["catalogue_sha256"]="sha256:"+"c"*64
    changed["approval_sha256"]="sha256:"+"d"*64
    changed["source_revision"]="f"*40
    changed["task"]="graphics-fonts-image-v1"
    one=s.bind_operation_to_installation(
        registry=row["registry"], pinned_registry_public=row["registrar"],
        request=req)
    two=s.bind_operation_to_installation(
        registry=row["registry"], pinned_registry_public=row["registrar"],
        request=changed)
    assert one["installation_scope_sha256"]==two["installation_scope_sha256"]
    assert one["operation_scope_sha256"]!=two["operation_scope_sha256"]
    assert one["operation_approved"] is False
    assert two["operation_approved"] is False


@pytest.mark.parametrize("change", (
    "registry_id", "controller_id", "installation_id", "state_volume_id",
    "host_id", "host_fingerprint", "target_identity_sha256",
))
def test_operation_cannot_select_another_registered_installation(change):
    row=selected()
    req=copy.deepcopy(row["request"])
    req[change] = ("0"*32 if change in ("registry_id","controller_id")
                   else "sha256:"+"0"*64 if change in
                   ("host_fingerprint","target_identity_sha256") else "0"*64)
    with pytest.raises(op.OperationDenied):
        s.bind_operation_to_installation(
            registry=row["registry"], pinned_registry_public=row["registrar"],
            request=req)


@pytest.mark.parametrize("change", (
    "wrong_registrar", "wrong_operator", "changed_registry",
    "changed_account", "changed_prefix", "changed_writer",
    "changed_reader", "same_role", "changed_genesis", "changed_anchor",
    "changed_approval", "expired", "bad_retention", "historical_mode",
))
def test_no_storage_provisioning_from_substituted_authority(change):
    row=selected()
    if change=="wrong_registrar":
        row["registrar"]=pub(Ed25519PrivateKey.generate())
    elif change=="wrong_operator":
        row["operator"]=pub(Ed25519PrivateKey.generate())
    elif change=="changed_registry":
        row["registry"]["host_id"]="f"*64
    elif change=="changed_account":
        row["authority"]["checkpoint_account_id"]="999999999999"
    elif change=="changed_prefix":
        row["authority"]["checkpoint_prefix"]="replacement/"
    elif change=="changed_writer":
        row["authority"]["checkpoint_writer_role_arn"]="arn:aws:iam::123456789012:role/Replacement"
    elif change=="changed_reader":
        row["authority"]["checkpoint_reader_role_arn"]="arn:aws:iam::123456789012:role/Replacement"
    elif change=="same_role":
        row["authority"]["checkpoint_reader_role_arn"]=row["authority"]["checkpoint_writer_role_arn"]
    elif change=="changed_genesis":
        row["authority"]["checkpoint_genesis_sha256"]="sha256:"+"f"*64
    elif change=="changed_anchor":
        row["anchor"]="sha256:"+"c"*64
    elif change=="changed_approval":
        row["grant"]["signature_ed25519"]=base64.b64encode(b"0"*64).decode()
    elif change=="expired":
        row["now"]=451
    elif change=="bad_retention":
        row["grant"]["retention_disposition_sha256"]="sha256:"+"0"*64
    elif change=="historical_mode":
        row["authority"]["mode"]="adopt-old"
    with pytest.raises(op.OperationDenied):
        verify(row)


def test_signed_storage_grant_does_not_approve_a_graphical_operation():
    row=selected()
    assert verify(row)["native_storage_accepted"] is False
    req=row["request"]
    value=s.bind_operation_to_installation(
        registry=row["registry"], pinned_registry_public=row["registrar"],
        request=req)
    assert not value["operation_approved"]
    assert not value["owner_admitted"]
    with pytest.raises(op.OperationDenied):
        s.bind_operation_to_installation(
            registry=row["registry"], pinned_registry_public=row["registrar"],
            request=req, signed_operation_approval=row["grant"],
            pinned_operator_public=row["operator"],
            expected_approval_id="a"*32, now=400)
