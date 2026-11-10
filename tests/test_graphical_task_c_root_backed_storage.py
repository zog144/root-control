"""Root-backed Task C v2: new signatures, no EBS, no local-send privilege."""
import base64
import copy
import os
import stat
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from zog.root_control import graphical_task_c_root_backed_storage as root
from zog.root_control import graphical_operation_owner_source as op
from zog.root_control import graphical_installation_storage_authority as prior

sys.path.insert(0,str(Path(__file__).resolve().parent))
from test_graphical_installation_storage_authority import selected


def pub(key):
    return key.public_key().public_bytes(
        serialization.Encoding.Raw,serialization.PublicFormat.Raw)


def signed(key,domain,body):
    return {**body,"signature_ed25519":base64.b64encode(
        key.sign(domain+op.canonical(body))).decode("ascii")}


def setup():
    old=selected()
    operator=Ed25519PrivateKey.generate()
    installer=Ed25519PrivateKey.generate()
    approved=copy.deepcopy(old["authority"])
    approved.update({
        "schema":root.AUTHORITY_SCHEMA,
        "mode":root.MODE,
        "ledger_directory":root.LEDGER,
        "authority_directory":root.AUTHORITY,
        "root_filesystem_uuid":"aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa",
    })
    approval_body={**{k:approved[k] for k in (
        "mode","registry_sha256","installation_scope_sha256",
        "checkpoint_account_id","checkpoint_region","checkpoint_bucket",
        "checkpoint_prefix","checkpoint_genesis_sha256",
        "checkpoint_writer_role_arn","checkpoint_reader_role_arn",
        "anchor_identity_sha256","ledger_directory","authority_directory",
        "root_filesystem_uuid")},
        "schema":root.APPROVAL_SCHEMA,
        "retention_disposition_sha256":"sha256:"+"a"*64,
        "operator_public_sha256":prior._sha(pub(operator)),
        "expires_at":450}
    approval=signed(operator,root.APPROVAL_DOMAIN,approval_body)
    approved["approval_sha256"]=op.digest(approval)
    commit_body={
        "schema":root.COMMIT_SCHEMA,"mode":root.MODE,
        "registry_sha256":approved["registry_sha256"],
        "installation_scope_sha256":approved["installation_scope_sha256"],
        "storage_authority_sha256":op.digest(approved),
        "signed_storage_approval_sha256":op.digest(approval),
        "anchor_identity_sha256":approved["anchor_identity_sha256"],
        "root_filesystem_uuid":approved["root_filesystem_uuid"],
        "ledger_directory_identity_sha256":"sha256:"+"b"*64,
        "authority_directory_identity_sha256":"sha256:"+"c"*64,
        "owner_unit_sha256":"sha256:"+"d"*64,
        "broker_unit_sha256":"sha256:"+"e"*64,
        "accepted_at":410,
    }
    receipt=signed(installer,root.COMMIT_DOMAIN,commit_body)
    anchor={**{k:commit_body[k] for k in (
        "registry_sha256","installation_scope_sha256",
        "anchor_identity_sha256","root_filesystem_uuid",
        "ledger_directory_identity_sha256",
        "authority_directory_identity_sha256")},
        "schema":root.ANCHOR_SCHEMA,
        "commit_sha256":op.digest(receipt)}
    return dict(old=old,authority=approved,approval=approval,
                receipt=receipt,anchor=anchor,operator=pub(operator),
                installer=pub(installer),
                installer_private=installer,operator_private=operator)


def verify(row,*,verify_directories=False):
    return root.verify_root_backed_commit(
        registry=row["old"]["registry"],
        pinned_registry_public=row["old"]["registrar"],
        authority=row["authority"],
        signed_storage_approval=row["approval"],
        pinned_operator_public=row["operator"],
        independently_retained_anchor_sha256=row["old"]["anchor"],
        receipt=row["receipt"],pinned_installer_public=row["installer"],
        independently_retained_commit_sha256=op.digest(row["receipt"]),
        now=9000,verify_directories=verify_directories)


def test_new_mode_reuses_existing_operator_and_installer_not_new_registrar():
    row=setup()
    result=verify(row)
    assert result["status"]=="ROOT_BACKED_COMMIT_SOURCE_ONLY"
    assert result["native_storage_accepted"] is False
    assert result["ssm_authorized"] is False
    assert root.verify_root_backed_anchor(
        row["anchor"],row["receipt"],row["authority"]) is True
    # Immutable S3 genesis still uses exact selected installation scope.
    assert row["authority"]["checkpoint_genesis_sha256"]==op.digest(
        prior.prospective_genesis(
            row["authority"]["installation_scope_sha256"],
            row["authority"]["registry_sha256"]))


def test_legacy_two_mount_receipt_is_not_a_valid_root_backed_approval():
    row=setup()
    row["receipt"]["schema"]="zog-task-c-installation-storage-commit-v1"
    with pytest.raises(op.OperationDenied):
        verify(row)
    row=setup()
    row["approval"]["schema"]=prior.APPROVAL_SCHEMA
    with pytest.raises(op.OperationDenied):
        verify(row)
    row=setup()
    row["authority"]["schema"]=prior.AUTHORITY_SCHEMA
    with pytest.raises(op.OperationDenied):
        verify(row)


@pytest.mark.parametrize("mutation",(
    "mode","authority_path","ledger_path","root_uuid","scope",
    "approval","signature","receipt","receipt_mode","receipt_layout",
    "unit","anchor","commit","operator","installer","unexpected",
))
def test_root_backed_requires_exact_signed_mode_and_directories(mutation):
    row=setup()
    if mutation=="mode":
        row["authority"]["mode"]="two-mount-disposition"
    elif mutation=="authority_path":
        row["authority"]["authority_directory"]="/tmp/broker"
    elif mutation=="ledger_path":
        row["authority"]["ledger_directory"]="/state/ledger"
    elif mutation=="root_uuid":
        row["authority"]["root_filesystem_uuid"]="not-a-uuid"
    elif mutation=="scope":
        row["authority"]["installation_scope_sha256"]="sha256:"+"f"*64
    elif mutation=="approval":
        row["approval"]["retention_disposition_sha256"]="sha256:"+"0"*64
    elif mutation=="signature":
        row["approval"]["signature_ed25519"]=base64.b64encode(b"0"*64).decode()
    elif mutation=="receipt":
        row["receipt"]["storage_authority_sha256"]="sha256:"+"0"*64
    elif mutation=="receipt_mode":
        row["receipt"]["mode"]="two-mount-disposition"
    elif mutation=="receipt_layout":
        row["receipt"]["ledger_directory_identity_sha256"]="sha256:"+"0"*64
        # An independently retained approved expectation is mandatory:
        row["receipt"]["storage_authority_sha256"]="sha256:"+"0"*64
    elif mutation=="unit":
        row["receipt"]["owner_unit_sha256"]="sha256:"+"0"*64
    elif mutation=="anchor":
        row["old"]["anchor"]="sha256:"+"0"*64
    elif mutation=="commit":
        row["receipt"]["accepted_at"]=451
    elif mutation=="operator":
        row["operator"]=pub(Ed25519PrivateKey.generate())
    elif mutation=="installer":
        row["installer"]=pub(Ed25519PrivateKey.generate())
    elif mutation=="unexpected":
        row["receipt"]["native_accepted"]=True
    with pytest.raises(op.OperationDenied):
        verify(row)


def test_directory_digests_are_bound_to_signed_installer_receipt(monkeypatch):
    row=setup()
    monkeypatch.setattr(root,"directory_digest",
        lambda path,**kw:
            "sha256:"+("b" if path==root.LEDGER else "c")*64)
    assert verify(row,verify_directories=True)["ssm_authorized"] is False
    monkeypatch.setattr(root,"directory_digest",lambda *a,**kw:"sha256:"+"0"*64)
    with pytest.raises(op.OperationDenied):
        verify(row,verify_directories=True)


def test_root_backed_directory_identity_rejects_symlink_wrong_owner_and_mount(monkeypatch):
    class S:
        def __init__(self,dev=12,ino=23,uid=0,gid=0,mode=0o700):
            self.st_dev=dev
            self.st_ino=ino
            self.st_uid=uid
            self.st_gid=gid
            self.st_mode=stat.S_IFDIR|mode
    objects={"/":S(ino=1,mode=0o755),
             "/var":S(ino=2,mode=0o755),
             "/var/lib":S(ino=3,mode=0o755),
             root.LEDGER:S(ino=4),
             root.AUTHORITY:S(ino=5)}
    monkeypatch.setattr(root.os,"lstat",lambda path:objects[str(path)])
    monkeypatch.setattr(root.os,"stat",
                        lambda path,**kw:objects[str(path)])
    monkeypatch.setattr(root.os.path,"ismount",lambda path:False)
    base="aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa"
    assert root.directory_identity(root.LEDGER,
             expected_root_filesystem_uuid=base)["directory_inode"]==4
    objects[root.LEDGER].st_uid=1000
    with pytest.raises(op.OperationDenied):
        root.directory_identity(root.LEDGER,expected_root_filesystem_uuid=base)
    objects[root.LEDGER].st_uid=0
    objects[root.LEDGER].st_dev=13
    with pytest.raises(op.OperationDenied):
        root.directory_identity(root.LEDGER,expected_root_filesystem_uuid=base)
    objects[root.LEDGER].st_dev=12
    monkeypatch.setattr(root.os.path,"ismount",lambda path:True)
    with pytest.raises(op.OperationDenied):
        root.directory_identity(root.LEDGER,expected_root_filesystem_uuid=base)
