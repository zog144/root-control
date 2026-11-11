"""Registrar-free Task C is a separately approved *remote operation policy*.

Local /state and identity remain independent of Command Center and any
signer. Storage/SSM still require existing operator and installer signatures.
"""
import base64
import copy
from uuid import UUID

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from zog.root_control import graphical_installation_storage_authority as storage
from zog.root_control import graphical_installation_storage_commit as installed
from zog.root_control import graphical_operation_owner_source as op

from test_graphical_installation_storage_authority import selected, pub


def selected_local():
    previous=selected()
    req=previous["request"]
    record={
        "schema":storage.LOCAL_SCHEMA,
        **{k:req[k] for k in (
            "host_id","host_fingerprint","target_identity_sha256",
            "installation_id","state_volume_id")},
        "host_install_installation_uuid":"22222222-2222-4222-8222-222222222222",
        "host_install_state_uuid":"33333333-3333-4333-8333-333333333333",
    }
    _,scope=storage.installation_scope(record,allow_local=True)
    operator=Ed25519PrivateKey.generate()
    installer=Ed25519PrivateKey.generate()
    auth=copy.deepcopy(previous["authority"])
    auth.update({
        "registry_sha256":op.digest(record),
        "installation_scope_sha256":scope,
        "checkpoint_genesis_sha256":op.digest(storage.prospective_genesis(
            scope,op.digest(record))),
    })
    grant_body={
        "schema":storage.APPROVAL_SCHEMA,
        **{k:auth[k] for k in (
            "mode","registry_sha256","installation_scope_sha256",
            "checkpoint_account_id","checkpoint_region",
            "checkpoint_bucket","checkpoint_prefix",
            "checkpoint_genesis_sha256","checkpoint_writer_role_arn",
            "checkpoint_reader_role_arn","anchor_identity_sha256")},
        "retention_disposition_sha256":"sha256:"+"b"*64,
        "operator_public_sha256":storage._sha(pub(operator)),
        "expires_at":450,
    }
    grant={**grant_body,"signature_ed25519":base64.b64encode(
        operator.sign(storage.APPROVAL_DOMAIN+
                      op.canonical(grant_body))).decode("ascii")}
    auth["approval_sha256"]=op.digest(grant)
    commit_body={
        "schema":installed.SCHEMA,
        "registry_sha256":op.digest(record),
        "installation_scope_sha256":scope,
        "storage_authority_sha256":op.digest(auth),
        "signed_storage_approval_sha256":op.digest(grant),
        "anchor_identity_sha256":auth["anchor_identity_sha256"],
        "ledger_fs_uuid":"11111111-1111-4111-8111-111111111111",
        "authority_fs_uuid":"33333333-3333-4333-8333-333333333333",
        "state_fs_uuid":"c9a14c15-c513-43bc-bb4b-345fe74ce960",
        "owner_unit_sha256":"sha256:"+"c"*64,
        "broker_unit_sha256":"sha256:"+"d"*64,
        "accepted_at":410,
    }
    receipt={**commit_body,"signature_ed25519":base64.b64encode(
        installer.sign(installed.DOMAIN+op.canonical(commit_body))
        ).decode("ascii")}
    return {
        "registry":record,"authority":auth,"grant":grant,"receipt":receipt,
        "operator":pub(operator),"installer":pub(installer),
        "request":req,
    }


def verify(row):
    return installed.verify_installed_storage_commit(
        registered_installation=row["registry"],pinned_registry_public=None,
        storage_authority=row["authority"],
        signed_storage_approval=row["grant"],
        pinned_operator_public=row["operator"],
        independently_retained_anchor_sha256=row["authority"][
            "anchor_identity_sha256"],
        receipt=row["receipt"],
        pinned_installer_public=row["installer"],
        independently_retained_commit_sha256=op.digest(row["receipt"]),
        now=10000,allow_local=True)


def test_local_installation_and_existing_originals_separate():
    row=selected_local()
    accepted=verify(row)
    assert accepted["status"]=="SIGNED_INSTALLATION_STORAGE_RECEIPT_SOURCE_ONLY"
    assert accepted["ssm_authorized"] is False
    scope=storage.bind_operation_to_installation(
        registry=row["registry"],pinned_registry_public=None,
        request=row["request"],allow_local=True)
    assert not scope["operation_approved"] and not scope["owner_admitted"]
    assert scope["installation_scope_sha256"]!=scope["operation_scope_sha256"]
    assert row["grant"]["operator_public_sha256"]==storage._sha(row["operator"])
    assert "signature_ed25519" not in row["registry"]


def test_local_mode_is_explicit_no_downshift_from_invalid_signed_registry():
    row=selected_local()
    with pytest.raises(op.OperationDenied):
        storage.installation_scope(row["registry"],pinned_registry_public=None)
    with pytest.raises(op.OperationDenied):
        storage.installation_scope(row["registry"],pinned_registry_public=b"x"*32,
                                   allow_local=True)
    signed=selected()
    with pytest.raises(op.OperationDenied):
        storage.installation_scope(signed["registry"],allow_local=True)
    with pytest.raises(op.OperationDenied):
        storage.verify_installation_storage_selection(
            registry=row["registry"],pinned_registry_public=None,
            authority=row["authority"],signed_storage_approval=row["grant"],
            pinned_operator_public=row["operator"],
            independently_retained_anchor_sha256=row["authority"][
                "anchor_identity_sha256"],now=400)


@pytest.mark.parametrize("change",(
    "host","state","local_uuid","state_uuid","retention","signature",
    "reader","anchor","scope","expired","unexpected_field","unit",
))
def test_local_unsigned_metadata_cannot_substitute_for_signed_storage_grant(change):
    row=selected_local()
    if change=="host":row["registry"]["host_id"]="f"*64
    elif change=="state":row["registry"]["state_volume_id"]="f"*64
    elif change=="local_uuid":
        row["registry"]["host_install_installation_uuid"]="invalid"
    elif change=="state_uuid":
        row["registry"]["host_install_state_uuid"]="invalid"
    elif change=="retention":
        row["grant"]["retention_disposition_sha256"]="sha256:"+"e"*64
    elif change=="signature":
        row["grant"]["signature_ed25519"]="AA=="
    elif change=="reader":
        row["authority"]["checkpoint_reader_role_arn"]=row[
            "authority"]["checkpoint_writer_role_arn"]
    elif change=="anchor":
        row["authority"]["anchor_identity_sha256"]="sha256:"+"e"*64
    elif change=="scope":
        row["authority"]["installation_scope_sha256"]="sha256:"+"e"*64
    elif change=="expired":
        row["receipt"]["accepted_at"]=451
    elif change=="unexpected_field":
        row["registry"]["native_accepted"]=True
    elif change=="unit":
        row["receipt"]["owner_unit_sha256"]="sha256:"+"e"*64
    with pytest.raises(op.OperationDenied):
        verify(row)


def test_local_scope_reused_across_distinct_operator_approved_operations():
    row=selected_local()
    second=copy.deepcopy(row["request"])
    second["catalogue_sha256"]="sha256:"+"e"*64
    one=storage.bind_operation_to_installation(
        registry=row["registry"],request=row["request"],allow_local=True)
    two=storage.bind_operation_to_installation(
        registry=row["registry"],request=second,allow_local=True)
    assert one["installation_scope_sha256"]==two["installation_scope_sha256"]
    assert one["request_sha256"]!=two["request_sha256"]
    assert not one["operation_approved"] and not two["operation_approved"]
