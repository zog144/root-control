"""Installation storage acceptance receipt: signed native handoff, no self-GO.

A short-lived *storage establishment* approval is verified at the separately
attested installation commit time; reboot later must not demand a new signature
or reinterpret it as a reusable per-operation approval. Work must independently
attest the real backing mounts, protected enrollment and S3 history.
"""
import base64
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from . import graphical_operation_owner_source as op
from . import graphical_installation_storage_authority as storage
from .graphical_native_owner import hold

SCHEMA = "zog-task-c-installation-storage-commit-v1"
DOMAIN = b"zog-task-c-installation-storage-commit-v1\0"
FIELDS = frozenset((
    "schema", "registry_sha256", "installation_scope_sha256",
    "storage_authority_sha256", "signed_storage_approval_sha256",
    "anchor_identity_sha256", "ledger_fs_uuid", "authority_fs_uuid",
    "state_fs_uuid", "owner_unit_sha256", "broker_unit_sha256",
    "accepted_at", "signature_ed25519",
))
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")


def verify_installed_storage_commit(
    *, registered_installation, pinned_registry_public,
    storage_authority, signed_storage_approval, pinned_operator_public,
    independently_retained_anchor_sha256, receipt,
    pinned_installer_public, independently_retained_commit_sha256,
    now, allow_local=False,
):
    if (type(receipt) is not dict or set(receipt) != FIELDS
            or receipt.get("schema") != SCHEMA
            or type(now) is not int
            or type(receipt["accepted_at"]) is not int
            or not 1 <= receipt["accepted_at"] <= now
            or type(pinned_installer_public) is not bytes
            or len(pinned_installer_public) != 32
            or pinned_installer_public == pinned_operator_public
            or (pinned_registry_public is not None and
                pinned_installer_public == pinned_registry_public)
            or not op.match(independently_retained_commit_sha256, op.SHA)
            or op.digest(receipt) != independently_retained_commit_sha256
            or any(not UUID.fullmatch(receipt[k]) for k in (
                "ledger_fs_uuid", "authority_fs_uuid", "state_fs_uuid"))
            or len({receipt[k] for k in (
                "ledger_fs_uuid", "authority_fs_uuid", "state_fs_uuid")}) != 3
            or any(not op.match(receipt[k], op.SHA) for k in (
                "owner_unit_sha256", "broker_unit_sha256"))
            or receipt["storage_authority_sha256"] != op.digest(storage_authority)
            or receipt["signed_storage_approval_sha256"] !=
                op.digest(signed_storage_approval)
            or receipt["anchor_identity_sha256"] !=
                independently_retained_anchor_sha256):
        hold()
    try:
        signature = base64.b64decode(
            receipt["signature_ed25519"], validate=True)
        if (len(signature) != 64
                or base64.b64encode(signature).decode("ascii") !=
                    receipt["signature_ed25519"]):
            hold()
        Ed25519PublicKey.from_public_bytes(pinned_installer_public).verify(
            signature, DOMAIN + op.canonical({
                k: v for k, v in receipt.items() if k != "signature_ed25519"}))
    except (TypeError, ValueError, InvalidSignature):
        hold()

    proof = storage.verify_installation_storage_selection(
        registry=registered_installation,
        pinned_registry_public=pinned_registry_public,
        authority=storage_authority,
        signed_storage_approval=signed_storage_approval,
        pinned_operator_public=pinned_operator_public,
        independently_retained_anchor_sha256=
            independently_retained_anchor_sha256,
        now=receipt["accepted_at"], allow_local=allow_local)
    if (receipt["registry_sha256"] != proof["registry_sha256"]
            or receipt["installation_scope_sha256"] !=
                proof["installation_scope_sha256"]):
        hold()
    return {
        "status": "SIGNED_INSTALLATION_STORAGE_RECEIPT_SOURCE_ONLY",
        "installation_scope_sha256": proof["installation_scope_sha256"],
        "accepted_at": receipt["accepted_at"],
        "runtime_storage_accepted": False,
        "owner_credentials_accepted": False,
        "owner_ipc_accepted": False,
        "ssm_authorized": False,
    }
