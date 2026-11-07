"""Synthetic immutable installation commit; no real FS, signer or S3 authority."""
import base64
import copy
import sys
from pathlib import Path
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from zog.root_control import graphical_installation_storage_commit as commit
from zog.root_control import graphical_operation_owner_source as op

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_graphical_installation_storage_authority import selected, pub


def prepared():
    source=selected()
    installer=Ed25519PrivateKey.generate()
    authority=source["authority"]
    body={
        "schema":commit.SCHEMA,
        "registry_sha256":authority["registry_sha256"],
        "installation_scope_sha256":authority["installation_scope_sha256"],
        "storage_authority_sha256":op.digest(authority),
        "signed_storage_approval_sha256":op.digest(source["grant"]),
        "anchor_identity_sha256":source["anchor"],
        "ledger_fs_uuid":"11111111-1111-4111-8111-111111111111",
        "authority_fs_uuid":"33333333-3333-4333-8333-333333333333",
        "state_fs_uuid":"c9a14c15-c513-43bc-bb4b-345fe74ce960",
        "owner_unit_sha256":"sha256:"+"c"*64,
        "broker_unit_sha256":"sha256:"+"d"*64,
        "accepted_at":410,
    }
    receipt={
        **body,
        "signature_ed25519":base64.b64encode(
            installer.sign(commit.DOMAIN+op.canonical(body))).decode()}
    return dict(
        source=source,
        receipt=receipt,
        installer=pub(installer),
        retained_commit=op.digest(receipt),
        now=100000,
    )


def verify(item):
    s=item["source"]
    return commit.verify_installed_storage_commit(
        registered_installation=s["registry"],
        pinned_registry_public=s["registrar"],
        storage_authority=s["authority"],
        signed_storage_approval=s["grant"],
        pinned_operator_public=s["operator"],
        independently_retained_anchor_sha256=s["anchor"],
        receipt=item["receipt"],
        pinned_installer_public=item["installer"],
        independently_retained_commit_sha256=item["retained_commit"],
        now=item["now"])


def test_signed_install_commit_validates_once_and_survives_grant_expiry():
    item=prepared()
    result=verify(item)
    assert result["status"]=="SIGNED_INSTALLATION_STORAGE_RECEIPT_SOURCE_ONLY"
    assert result["accepted_at"]==410
    assert result["runtime_storage_accepted"] is False
    assert result["owner_ipc_accepted"] is False
    assert item["now"] > item["source"]["grant"]["expires_at"]


@pytest.mark.parametrize("corrupt",(
    "wrong_installer", "tampered_receipt", "different_anchor",
    "different_signed_grant", "modified_genesis", "different_registry",
    "future_accept", "expired_at_accept", "duplicate_fs",
    "changed_independent_commit", "unknown_field",
))
def test_installation_commit_substitution_and_replay_denied(corrupt):
    item=prepared()
    if corrupt=="wrong_installer":
        item["installer"]=pub(Ed25519PrivateKey.generate())
    elif corrupt=="tampered_receipt":
        item["receipt"]["signature_ed25519"]=base64.b64encode(b"0"*64).decode()
    elif corrupt=="different_anchor":
        item["source"]["anchor"]="sha256:"+"e"*64
    elif corrupt=="different_signed_grant":
        item["source"]["grant"]["signature_ed25519"]="changed"
    elif corrupt=="modified_genesis":
        item["source"]["authority"]["checkpoint_genesis_sha256"]="sha256:"+"f"*64
    elif corrupt=="different_registry":
        item["source"]["registry"]["host_id"]="f"*64
    elif corrupt=="future_accept":
        item["receipt"]["accepted_at"]=item["now"]+1
    elif corrupt=="expired_at_accept":
        item["receipt"]["accepted_at"]=451
    elif corrupt=="duplicate_fs":
        item["receipt"]["authority_fs_uuid"]=item["receipt"]["ledger_fs_uuid"]
    elif corrupt=="changed_independent_commit":
        item["retained_commit"]="sha256:"+"f"*64
    elif corrupt=="unknown_field":
        item["receipt"]["self_accepted"]=True
    with pytest.raises(op.OperationDenied):
        verify(item)


def test_only_explicit_v3_native_source_uses_new_checkpoint():
    from zog.root_control import graphical_task_c_native as native
    import inspect
    source=inspect.getsource(native.installed_runtime)
    assert native.RUNTIME_SCHEMA=="zog-protected-task-c-installed-runtime-v2"
    assert native.INSTALLATION_RUNTIME_SCHEMA=="zog-protected-task-c-installed-runtime-v3"
    assert "if installation_runtime:" in source
    assert "S3InstallationCheckpoint(" in source
    assert "S3AppendOnlyCheckpoint(" in source
    assert "scope_digest=selection[\"identity\"]" in source
    assert "installation_scope_sha256=stable_scope" in source
