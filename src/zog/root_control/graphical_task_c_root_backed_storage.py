"""Task C root-backed application storage, v2 signed establishment.

This is NOT a Host installer, filesystem creator or SendCommand authority.
The same trusted Host root filesystem may contain both protected directories.
All SSM eligibility comes from the independent conditional-create S3 chain;
the local directory identities only bind the approved installation. V1
two-filesystem receipts remain a separate protocol and cannot be reinterpreted.
"""
from __future__ import annotations

import base64
import os
from pathlib import Path
import re
import stat

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import graphical_installation_storage_authority as storage
from . import graphical_operation_owner_source as op
from .graphical_native_owner import hold

AUTHORITY_SCHEMA = "zog-task-c-root-backed-storage-authority-v2"
APPROVAL_SCHEMA = "zog-task-c-root-backed-storage-approval-v2"
APPROVAL_DOMAIN = b"zog-task-c-root-backed-storage-approval-v2\0"
COMMIT_SCHEMA = "zog-task-c-root-backed-storage-commit-v2"
COMMIT_DOMAIN = b"zog-task-c-root-backed-storage-commit-v2\0"
ANCHOR_SCHEMA = "zog-task-c-root-backed-storage-external-anchor-v2"
SELECTION_SCHEMA = "zog-task-c-root-backed-installed-selection-v2"
MODE = "root-backed-application-directories"
LEDGER = "/var/lib/zog-owner-ledger"
AUTHORITY = "/var/lib/zog-owner-authority"
DIRS = (LEDGER, AUTHORITY)
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
AUTHORITY_KEYS = storage.AUTHORITY_KEYS | {
    "ledger_directory", "authority_directory", "root_filesystem_uuid"}
APPROVAL_KEYS = storage.APPROVAL_KEYS | {
    "ledger_directory", "authority_directory", "root_filesystem_uuid"}
COMMIT_FIELDS = frozenset((
    "schema", "mode", "registry_sha256", "installation_scope_sha256",
    "storage_authority_sha256", "signed_storage_approval_sha256",
    "anchor_identity_sha256", "root_filesystem_uuid",
    "ledger_directory_identity_sha256", "authority_directory_identity_sha256",
    "owner_unit_sha256", "broker_unit_sha256", "accepted_at",
    "signature_ed25519"))
ANCHOR_FIELDS = frozenset((
    "schema", "registry_sha256", "installation_scope_sha256",
    "anchor_identity_sha256", "commit_sha256", "root_filesystem_uuid",
    "ledger_directory_identity_sha256", "authority_directory_identity_sha256"))
SELECTION_FIELDS = frozenset((
    "schema", "registry_sha256", "installation_scope_sha256",
    "storage_authority_sha256", "storage_commit_sha256"))


def _signature(signed, domain, key):
    if type(key) is not bytes or len(key) != 32:
        hold()
    try:
        value = signed["signature_ed25519"]
        if type(value) is not str:
            hold()
        decoded = base64.b64decode(value, validate=True)
        if (len(decoded) != 64 or
                base64.b64encode(decoded).decode("ascii") != value):
            hold()
        Ed25519PublicKey.from_public_bytes(key).verify(
            decoded, domain + op.canonical({
                k: v for k, v in signed.items() if k != "signature_ed25519"}))
    except (ValueError, TypeError, KeyError, InvalidSignature):
        hold()


def verify_storage_authority(
    *, registry, pinned_registry_public, authority, signed_storage_approval,
    pinned_operator_public, independently_retained_anchor_sha256,
    accepted_at, allow_local=False
):
    """Exact v2 operator approval, not a replacement registrar/boot signer."""
    scope, scope_sha = storage.installation_scope(
        registry, pinned_registry_public=pinned_registry_public,
        allow_local=allow_local)
    registry_sha = op.digest(registry)
    if (type(authority) is not dict or set(authority) != AUTHORITY_KEYS
            or authority.get("schema") != AUTHORITY_SCHEMA
            or authority.get("mode") != MODE
            or authority.get("registry_sha256") != registry_sha
            or authority.get("installation_scope_sha256") != scope_sha
            or authority.get("ledger_directory") != LEDGER
            or authority.get("authority_directory") != AUTHORITY
            or type(authority.get("root_filesystem_uuid")) is not str
            or not UUID.fullmatch(authority["root_filesystem_uuid"])
            or type(signed_storage_approval) is not dict
            or set(signed_storage_approval) != APPROVAL_KEYS
            or signed_storage_approval.get("schema") != APPROVAL_SCHEMA
            or signed_storage_approval.get("mode") != MODE
            or type(accepted_at) is not int
            or type(signed_storage_approval.get("expires_at")) is not int
            or not accepted_at <= signed_storage_approval["expires_at"]
                      <= accepted_at + 900
            or not op.match(independently_retained_anchor_sha256, op.SHA)
            or authority.get("anchor_identity_sha256") !=
                independently_retained_anchor_sha256
            or type(pinned_operator_public) is not bytes
            or len(pinned_operator_public) != 32
            or (pinned_registry_public is not None and
                pinned_registry_public == pinned_operator_public)
            or signed_storage_approval.get("operator_public_sha256") !=
                storage._sha(pinned_operator_public)
            or authority.get("approval_sha256") !=
                op.digest(signed_storage_approval)):
        hold()
    for k in (
        "mode", "registry_sha256", "installation_scope_sha256",
        "checkpoint_account_id", "checkpoint_region", "checkpoint_bucket",
        "checkpoint_prefix", "checkpoint_genesis_sha256",
        "checkpoint_writer_role_arn", "checkpoint_reader_role_arn",
        "anchor_identity_sha256", "ledger_directory", "authority_directory",
        "root_filesystem_uuid"
    ):
        if signed_storage_approval.get(k) != authority.get(k):
            hold()
    if (not op.match(signed_storage_approval.get(
            "retention_disposition_sha256"), op.SHA)
            or type(authority["checkpoint_account_id"]) is not str
            or not re.fullmatch(r"[0-9]{12}", authority["checkpoint_account_id"])
            or type(authority["checkpoint_region"]) is not str
            or not storage.REGION.fullmatch(authority["checkpoint_region"])
            or type(authority["checkpoint_bucket"]) is not str
            or not storage.BUCKET.fullmatch(authority["checkpoint_bucket"])
            or type(authority["checkpoint_prefix"]) is not str
            or not storage.PREFIX.fullmatch(authority["checkpoint_prefix"])
            or not authority["checkpoint_prefix"].endswith("/")
            or "//" in authority["checkpoint_prefix"]):
        hold()
    reader = authority["checkpoint_reader_role_arn"]
    writer = authority["checkpoint_writer_role_arn"]
    if (type(reader) is not str or type(writer) is not str
            or not storage.ARN.fullmatch(reader)
            or not storage.ARN.fullmatch(writer)
            or reader == writer
            or any(storage.ARN.fullmatch(role).group(1) !=
                   authority["checkpoint_account_id"] for role in
                   (reader, writer))
            or authority["checkpoint_genesis_sha256"] !=
                op.digest(storage.prospective_genesis(scope_sha, registry_sha))):
        hold()
    _signature(signed_storage_approval, APPROVAL_DOMAIN,
               pinned_operator_public)
    return {"installation_scope_sha256": scope_sha,
            "registry_sha256": registry_sha,
            "status": "ROOT_BACKED_STORAGE_SOURCE_ONLY",
            "native_storage_accepted": False,
            "ssm_authorized": False}


def directory_identity(path, *, expected_root_filesystem_uuid):
    """Root-owned directory + ancestor inode identity, no mount requirement.

    Called in the protected runtime; the installer must independently attest
    root filesystem UUID and record the digest in its signed v2 commit.
    No caller-selected directory path, inode, or privilege boolean.
    """
    if (path not in DIRS or type(expected_root_filesystem_uuid) is not str
            or not UUID.fullmatch(expected_root_filesystem_uuid)):
        hold()
    try:
        root = os.lstat("/")
        ancestor = os.lstat("/var")
        parent = os.lstat("/var/lib")
        leaf = os.lstat(path)
        # Reject symlinked ancestors, unexpected mountpoints, untrusted
        # parents and unexpected application directory ownership/modes.
        if (any(not stat.S_ISDIR(s.st_mode) or s.st_uid != 0 or
                (stat.S_IMODE(s.st_mode) & 0o022)
                for s in (root, ancestor, parent, leaf))
                or not all(s.st_dev == root.st_dev
                           for s in (ancestor, parent, leaf))
                or os.path.ismount(path)
                or stat.S_IMODE(leaf.st_mode) != 0o700
                or leaf.st_gid != 0
                or (os.stat(path, follow_symlinks=False).st_ino != leaf.st_ino)):
            hold()
    except OSError:
        hold()
    return {"path": path,
            "root_filesystem_uuid": expected_root_filesystem_uuid,
            "root_inode": root.st_ino,
            "parent_inode": parent.st_ino,
            "directory_inode": leaf.st_ino,
            "owner_uid": leaf.st_uid,
            "owner_gid": leaf.st_gid,
            "mode": 0o700}


def directory_digest(path, *, expected_root_filesystem_uuid):
    return op.digest(directory_identity(
        path, expected_root_filesystem_uuid=expected_root_filesystem_uuid))


def verify_root_backed_commit(
    *, registry, pinned_registry_public, authority,
    signed_storage_approval, pinned_operator_public,
    independently_retained_anchor_sha256, receipt, pinned_installer_public,
    independently_retained_commit_sha256, now, allow_local=False,
    verify_directories=False
):
    """v2 commit; legacy v1 two-device receipt is *never* reinterpreted."""
    if (type(receipt) is not dict or set(receipt) != COMMIT_FIELDS
            or receipt.get("schema") != COMMIT_SCHEMA
            or receipt.get("mode") != MODE
            or type(now) is not int
            or type(receipt.get("accepted_at")) is not int
            or not 1 <= receipt["accepted_at"] <= now
            or type(pinned_installer_public) is not bytes
            or len(pinned_installer_public) != 32
            or pinned_installer_public == pinned_operator_public
            or (pinned_registry_public is not None and
                pinned_installer_public == pinned_registry_public)
            or not op.match(independently_retained_commit_sha256, op.SHA)
            or op.digest(receipt) != independently_retained_commit_sha256):
        hold()
    proof = verify_storage_authority(
        registry=registry, pinned_registry_public=pinned_registry_public,
        authority=authority, signed_storage_approval=signed_storage_approval,
        pinned_operator_public=pinned_operator_public,
        independently_retained_anchor_sha256=
            independently_retained_anchor_sha256,
        accepted_at=receipt["accepted_at"], allow_local=allow_local)
    if (receipt["registry_sha256"] != proof["registry_sha256"]
            or receipt["installation_scope_sha256"] !=
                proof["installation_scope_sha256"]
            or receipt["storage_authority_sha256"] != op.digest(authority)
            or receipt["signed_storage_approval_sha256"] !=
                op.digest(signed_storage_approval)
            or receipt["anchor_identity_sha256"] !=
                independently_retained_anchor_sha256
            or receipt["root_filesystem_uuid"] !=
                authority["root_filesystem_uuid"]
            or any(not op.match(receipt[k], op.SHA) for k in
                   ("owner_unit_sha256", "broker_unit_sha256",
                    "ledger_directory_identity_sha256",
                    "authority_directory_identity_sha256"))):
        hold()
    _signature(receipt, COMMIT_DOMAIN, pinned_installer_public)
    if verify_directories:
        for path, key in (
            (LEDGER, "ledger_directory_identity_sha256"),
            (AUTHORITY, "authority_directory_identity_sha256")
        ):
            if receipt[key] != directory_digest(
                    path, expected_root_filesystem_uuid=
                    authority["root_filesystem_uuid"]):
                hold()
    return {"status": "ROOT_BACKED_COMMIT_SOURCE_ONLY",
            "installation_scope_sha256": proof["installation_scope_sha256"],
            "registry_sha256": proof["registry_sha256"],
            "native_storage_accepted": False,
            "ssm_authorized": False}


def verify_root_backed_anchor(anchor, receipt, authority):
    """Locally retained mirror; externally enforced S3 history is mandatory."""
    if (type(anchor) is not dict or set(anchor) != ANCHOR_FIELDS
            or anchor.get("schema") != ANCHOR_SCHEMA
            or any(anchor.get(k) != receipt.get(k) for k in (
                "registry_sha256", "installation_scope_sha256",
                "anchor_identity_sha256", "root_filesystem_uuid",
                "ledger_directory_identity_sha256",
                "authority_directory_identity_sha256"))
            or anchor.get("commit_sha256") != op.digest(receipt)
            or receipt.get("root_filesystem_uuid") !=
                authority.get("root_filesystem_uuid")):
        hold()
    return True
