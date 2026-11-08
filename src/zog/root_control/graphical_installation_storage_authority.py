"""Task C prospective installation-level storage authority.

An explicitly selected local Host installation or legacy signed registry
selects persistent storage before any Fonts operation approval exists. A separate signed operation still selects
EVERY claim, send and revocation. This source never initializes remote S3,
provisions mounts, issues registry keys or accepts a native service.
"""
from __future__ import annotations

import base64
import hashlib
import re
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import graphical_operation_owner_source as operation
from .graphical_native_owner import hold

# Local operator-selected identity is NOT signed, cannot initialize /state,
# and is not Command Center enrollment. The distinct operator-signed storage
# approval plus protected installer commit authorize Task C's S3 selection.
LOCAL_SCHEMA = "zog-task-c-local-installation-selection-v1"
LOCAL_SCOPE_SCHEMA = "zog-task-c-local-installation-storage-scope-v1"
LOCAL_EXTRA = ("host_install_installation_uuid", "host_install_state_uuid")
LOCAL_KEYS = frozenset(("schema", "host_id", "host_fingerprint",
    "target_identity_sha256", "installation_id", "state_volume_id")
    + LOCAL_EXTRA)
REGISTRY_SCHEMA = "zog-task-c-registered-installation-v1"
REGISTRY_DOMAIN = b"zog-task-c-registered-installation-v1\0"
SCOPE_SCHEMA = "zog-task-c-installation-storage-scope-v1"
AUTHORITY_SCHEMA = "zog-task-c-installation-storage-authority-v1"
APPROVAL_SCHEMA = "zog-task-c-installation-storage-approval-v1"
APPROVAL_DOMAIN = b"zog-task-c-installation-storage-approval-v1\0"
GENESIS_SCHEMA = "zog-task-c-installation-checkpoint-v1"
SOURCE_MODE = "new-installation-no-historical-continuity"
SCOPE_KEYS = (
    "host_id", "host_fingerprint", "registry_id", "controller_id",
    "target_identity_sha256", "installation_id", "state_volume_id",
)
REGISTRY_KEYS = frozenset(("schema",) + SCOPE_KEYS + ("signature_ed25519",))
AUTHORITY_KEYS = frozenset((
    "schema", "mode", "registry_sha256", "installation_scope_sha256",
    "checkpoint_account_id", "checkpoint_region", "checkpoint_bucket",
    "checkpoint_prefix", "checkpoint_genesis_sha256",
    "checkpoint_writer_role_arn", "checkpoint_reader_role_arn",
    "anchor_identity_sha256", "approval_sha256",
))
APPROVAL_KEYS = frozenset((
    "schema", "mode", "registry_sha256", "installation_scope_sha256",
    "checkpoint_account_id", "checkpoint_region", "checkpoint_bucket",
    "checkpoint_prefix", "checkpoint_genesis_sha256",
    "checkpoint_writer_role_arn", "checkpoint_reader_role_arn",
    "anchor_identity_sha256", "retention_disposition_sha256",
    "operator_public_sha256", "expires_at", "signature_ed25519",
))
ARN = re.compile(r"arn:aws:iam::([0-9]{12}):role/[A-Za-z0-9_+=,.@-]{1,64}\Z")
BUCKET = re.compile(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\Z")
PREFIX = re.compile(r"[a-z0-9/-]{1,160}\Z")
REGION = re.compile(r"[a-z]{2}-[a-z]+-[0-9]\Z")


def _sha(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _digest(value):
    return operation.digest(value)


def _denied():
    hold()


def _verify_signature(signed, *, domain, public):
    if type(public) is not bytes or len(public) != 32:
        _denied()
    try:
        signature = signed["signature_ed25519"]
        raw = base64.b64decode(signature, validate=True)
        if (type(signature) is not str or len(raw) != 64 or
                base64.b64encode(raw).decode("ascii") != signature):
            _denied()
        body = {k: v for k, v in signed.items() if k != "signature_ed25519"}
        Ed25519PublicKey.from_public_bytes(public).verify(
            raw, domain + operation.canonical(body))
    except (ValueError, TypeError, KeyError, InvalidSignature):
        _denied()


def installation_scope(registry, *, pinned_registry_public=None, allow_local=False):
    """Selected registry evidence, never a request-derived storage scope."""
    if type(registry) is dict and registry.get("schema") == LOCAL_SCHEMA:
        # This branch is deliberately opt-in from a reviewed Task C runtime
        # selection, NEVER a fallback if the registrar or key is missing.
        # Pure local metadata alone supplies no operator or owner grant.
        if (allow_local is not True or pinned_registry_public is not None
                or set(registry) != LOCAL_KEYS
                or any(not operation.match(registry[k], operation.H64)
                       for k in ("host_id", "installation_id", "state_volume_id"))
                or any(not operation.match(registry[k], operation.SHA)
                       for k in ("host_fingerprint", "target_identity_sha256"))):
            _denied()
        from uuid import UUID
        try:
            for key in LOCAL_EXTRA:
                val = registry[key]
                if (type(val) is not str or str(UUID(val)) != val
                        or UUID(val).int == 0):
                    _denied()
        except (TypeError, ValueError, AttributeError):
            _denied()
        local_scope = {"schema": LOCAL_SCOPE_SCHEMA,
                       **{k: registry[k] for k in
                          ("host_id", "host_fingerprint",
                           "target_identity_sha256", "installation_id",
                           "state_volume_id") + LOCAL_EXTRA}}
        return local_scope, _digest(local_scope)
    if (allow_local is True or type(pinned_registry_public) is not bytes):
        # Distinguish the old signed-registry mode. Never downgrade it.
        _denied()
    if (type(registry) is not dict or set(registry) != REGISTRY_KEYS
            or registry["schema"] != REGISTRY_SCHEMA
            or any(not operation.match(registry[k], operation.H64)
                   for k in ("host_id", "installation_id", "state_volume_id"))
            or any(not operation.match(registry[k], operation.H32)
                   for k in ("registry_id", "controller_id"))
            or any(not operation.match(registry[k], operation.SHA)
                   for k in ("host_fingerprint", "target_identity_sha256"))):
        _denied()
    _verify_signature(registry, domain=REGISTRY_DOMAIN, public=pinned_registry_public)
    scope = {"schema": SCOPE_SCHEMA, **{k: registry[k] for k in SCOPE_KEYS}}
    return scope, _digest(scope)


def prospective_genesis(installation_scope_sha256, registry_sha256):
    """Exact proposed genesis bytes; native Work must explicitly create once."""
    if any(not operation.match(v, operation.SHA)
           for v in (installation_scope_sha256, registry_sha256)):
        _denied()
    return {"schema": GENESIS_SCHEMA,
            "installation_scope_sha256": installation_scope_sha256,
            "registry_sha256": registry_sha256,
            "sequence": 0, "action": "genesis"}


def verify_installation_storage_selection(
    *, registry, pinned_registry_public, authority,
    signed_storage_approval, pinned_operator_public,
    independently_retained_anchor_sha256, now, allow_local=False,
):
    """Source validation of independent registry + one-time storage grant.

    The independently retained anchor digest must be read from *outside* the
    candidate storage writer's rollback domain; source-supplied bytes are not
    native proof of that custody. No implicit approval of any operation.
    """
    scope, scope_sha = installation_scope(
        registry, pinned_registry_public=pinned_registry_public,
        allow_local=allow_local)
    registry_sha = _digest(registry)
    if (type(authority) is not dict or set(authority) != AUTHORITY_KEYS
            or authority.get("schema") != AUTHORITY_SCHEMA
            or authority.get("mode") != SOURCE_MODE
            or authority["registry_sha256"] != registry_sha
            or authority["installation_scope_sha256"] != scope_sha
            or type(signed_storage_approval) is not dict
            or set(signed_storage_approval) != APPROVAL_KEYS
            or signed_storage_approval.get("schema") != APPROVAL_SCHEMA
            or signed_storage_approval.get("mode") != SOURCE_MODE
            or not operation.match(independently_retained_anchor_sha256,
                                   operation.SHA)
            or independently_retained_anchor_sha256 !=
                authority["anchor_identity_sha256"]
            or type(now) is not int
            or type(signed_storage_approval["expires_at"]) is not int
            or not now <= signed_storage_approval["expires_at"] <= now + 900
            or not operation.match(
                signed_storage_approval["retention_disposition_sha256"],
                operation.SHA)
            or type(pinned_operator_public) is not bytes
            or len(pinned_operator_public) != 32
            or (pinned_registry_public is not None
                and pinned_operator_public == pinned_registry_public)
            or signed_storage_approval["operator_public_sha256"] !=
                _sha(pinned_operator_public)
            or not operation.match(authority["approval_sha256"], operation.SHA)
            or authority["approval_sha256"] != _digest(signed_storage_approval)):
        _denied()
    for key in (
        "registry_sha256", "installation_scope_sha256",
        "checkpoint_account_id", "checkpoint_region", "checkpoint_bucket",
        "checkpoint_prefix", "checkpoint_genesis_sha256",
        "checkpoint_writer_role_arn", "checkpoint_reader_role_arn",
        "anchor_identity_sha256",
    ):
        if authority[key] != signed_storage_approval.get(key):
            _denied()
    account = authority["checkpoint_account_id"]
    writer = authority["checkpoint_writer_role_arn"]
    reader = authority["checkpoint_reader_role_arn"]
    prefix = authority["checkpoint_prefix"]
    if (type(account) is not str or
            not re.fullmatch(r"[0-9]{12}", account) or
            type(authority["checkpoint_region"]) is not str or
            not REGION.fullmatch(authority["checkpoint_region"]) or
            type(authority["checkpoint_bucket"]) is not str or
            not BUCKET.fullmatch(authority["checkpoint_bucket"]) or
            type(prefix) is not str or not PREFIX.fullmatch(prefix) or
            not prefix.endswith("/") or "//" in prefix or
            type(writer) is not str or type(reader) is not str or
            not ARN.fullmatch(writer) or not ARN.fullmatch(reader) or
            writer == reader or
            ARN.fullmatch(writer).group(1) != account or
            ARN.fullmatch(reader).group(1) != account or
            not operation.match(authority["checkpoint_genesis_sha256"],
                                operation.SHA) or
            authority["checkpoint_genesis_sha256"] != _digest(
                prospective_genesis(scope_sha, registry_sha))):
        _denied()
    _verify_signature(signed_storage_approval,
                      domain=APPROVAL_DOMAIN, public=pinned_operator_public)
    return {
        "status": "INSTALLATION_STORAGE_SOURCE_ONLY",
        "installation_scope_sha256": scope_sha,
        "registry_sha256": registry_sha,
        "source_approved_storage_scope": scope,
        "native_storage_accepted": False,
        "history_continuity_accepted": False,
        "owner_admitted": False,
        "ssm_authorized": False,
    }


def bind_operation_to_installation(
    *, registry, pinned_registry_public=None, request,
    signed_operation_approval=None, pinned_operator_public=None,
    expected_approval_id=None, now=None, allow_local=False,
):
    """Separate operation digest and approval; never use as storage identity.

    Signature verification is required when an approval is supplied; a caller
    cannot bypass it by presenting an untrusted 'approved' flag. A missing
    approval still leaves an operation NOT ADMITTED (preparation only).
    """
    _, stable_scope = installation_scope(
        registry, pinned_registry_public=pinned_registry_public,
        allow_local=allow_local)
    req = operation.validate_request(request)
    check_keys = (("host_id", "host_fingerprint",
                   "target_identity_sha256", "installation_id",
                   "state_volume_id") if allow_local else SCOPE_KEYS)
    if any(req[k] != registry[k] for k in check_keys):
        _denied()
    operation_scope = operation.digest(operation.scope_from_request(req))
    result = {
        "installation_scope_sha256": stable_scope,
        "operation_scope_sha256": operation_scope,
        "operation_id": req["operation_id"],
        "request_sha256": operation.digest(req),
        "operation_approved": False,
        "owner_admitted": False,
    }
    if signed_operation_approval is not None:
        if (pinned_operator_public is None or expected_approval_id is None
                or type(now) is not int):
            _denied()
        operation.verify_original_operator_approval(
            req, signed_operation_approval,
            externally_pinned_operator_key=pinned_operator_public,
            expected_approval_id=expected_approval_id, now=now)
        result["operation_approved"] = True
    return result
