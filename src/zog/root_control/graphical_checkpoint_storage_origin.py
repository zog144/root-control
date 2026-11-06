"""Original Task C checkpoint history versus separately approved new scope.

Source contract only. No synthetic tuple, missing 000000 genesis, caller boolean,
or mounting a new empty disk can authenticate historical S3/STATE continuity.
No checkpoint creation, AWS operations, signer issuance, or native approval here.
"""
from __future__ import annotations

import base64
import hashlib
import json
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .graphical_native_owner import hold
from . import graphical_operation_owner_source as origin

ORIGINAL = "original-history-adoption"
NEW = "separately-authorized-new-scope"
SCHEMA = "zog-task-c-storage-origin-admission-v1"
ORIGINAL_RECORD = "zog-task-c-original-checkpoint-installation-v1"
FIELDS = frozenset((
    "schema", "mode", "host_id", "installation_id", "state_volume_id",
    "scope_sha256", "account_id", "region", "bucket", "prefix",
    "genesis_sha256", "writer_role_arn", "authorization_sha256",
    "original_record_sha256", "anchor_identity_sha256",
    "external_genesis_verified", "external_chain_verified",
    "original_operator_authorization_verified", "independent_anchor_verified",
))

def _sha(value):
    return type(value) is str and origin.match(value, origin.SHA) and value != "sha256:"+"0"*64

def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")

def _deny():
    hold()

def assess_checkpoint_origin(proposal, *, original_record=None,
                             independently_retained_record_digest=None):
    """Strictly classify source candidate; never supply native proof.

    External *_verified flags MUST be authenticated against actual remote S3
    readbacks and operator evidence by Work, not accepted from a proposal.
    Return an inspection plan, not a boolean that could enable the broker.
    """
    if (type(proposal) is not dict or set(proposal) != FIELDS
            or proposal.get("schema") != SCHEMA
            or proposal.get("mode") not in (ORIGINAL, NEW)
            or any(not _sha(proposal[k]) for k in (
                "scope_sha256", "genesis_sha256", "authorization_sha256"))
            or any(type(proposal[k]) is not str or not origin.match(
                proposal[k], origin.H64) for k in (
                    "host_id", "installation_id", "state_volume_id"))
            or any(type(proposal[k]) is not str or not proposal[k] for k in (
                "account_id", "region", "bucket", "prefix", "writer_role_arn"))
            or any(type(proposal[k]) is not bool or proposal[k] is not False
                   for k in ("external_genesis_verified", "external_chain_verified",
                             "original_operator_authorization_verified",
                             "independent_anchor_verified"))):
        _deny()
    if proposal["mode"] == ORIGINAL:
        if (type(original_record) is not dict
                or original_record.get("schema") != ORIGINAL_RECORD
                or not _sha(independently_retained_record_digest)
                or proposal["original_record_sha256"] != independently_retained_record_digest
                or not _sha(proposal["anchor_identity_sha256"])
                or independently_retained_record_digest != origin.digest(original_record)):
            _deny()
        mapping = {
            "host_id": "host_id", "installation_id": "installation_id",
            "state_volume_id": "state_volume_id",
            "scope_sha256": "checkpoint_scope_sha256",
            "account_id": "checkpoint_account_id",
            "region": "checkpoint_region",
            "bucket": "checkpoint_bucket", "prefix": "checkpoint_prefix",
            "genesis_sha256": "checkpoint_genesis_sha256",
            "writer_role_arn": "checkpoint_role_arn",
        }
        if any(proposal[k] != original_record.get(v) for k,v in mapping.items()):
            _deny()
        # An original-history proposal MUST NOT request automatic initialization
        # even if the local original file exists but the remote history is missing.
        result = "ORIGINAL_HISTORY_EXTERNAL_AUTHENTICATION_REQUIRED"
    else:
        if (original_record is not None
                or independently_retained_record_digest is not None
                or proposal["original_record_sha256"] is not None
                or proposal["anchor_identity_sha256"] is not None):
            _deny()
        # New authority requires a *new* independently signed scope/approval;
        # it must never masquerade as the original continuation.
        result = "NEW_SCOPE_SEPARATE_AUTHORIZATION_REQUIRED"
    return {
        "classification": result,
        "native_accepted": False,
        "existing_history_accepted": False,
        "new_scope_authorized": False,
        "broker_activation_authorized": False,
        "ssm_authorized": False,
    }

NEW_APPROVAL_SCHEMA = "zog-task-c-separately-authorized-new-scope-v1"
NEW_APPROVAL_DOMAIN = b"zog-task-c-separately-authorized-new-scope-v1\\0"
NEW_APPROVAL_FIELDS = frozenset((
    "schema", "host_id", "installation_id", "state_volume_id",
    "scope_sha256", "account_id", "region", "bucket", "prefix",
    "genesis_sha256", "writer_role_arn", "retention_disposition_sha256",
    "operator_public_sha256", "expires_at", "signature_ed25519",
))

def verify_separate_new_scope_approval(proposal, signed_approval, *,
                                       independently_pinned_operator_public,
                                       now):
    """Verify separately signed authorization bytes, not native provisioning.

    The authorization signature binds a deliberately distinct proposed scope
    and an independent disposition of the unauthenticated original history.
    Work must authenticate the operator key custody and the disposition
    separately; a valid source-fixture signature is not installation approval.
    """
    review = assess_checkpoint_origin(proposal)
    if (review["classification"] != "NEW_SCOPE_SEPARATE_AUTHORIZATION_REQUIRED"
            or type(signed_approval) is not dict
            or set(signed_approval) != NEW_APPROVAL_FIELDS
            or signed_approval.get("schema") != NEW_APPROVAL_SCHEMA
            or type(independently_pinned_operator_public) is not bytes
            or len(independently_pinned_operator_public) != 32
            or type(now) is not int
            or type(signed_approval["expires_at"]) is not int
            or not now <= signed_approval["expires_at"] <= now + 900
            or not _sha(signed_approval["retention_disposition_sha256"])
            or signed_approval["retention_disposition_sha256"] !=
                proposal["authorization_sha256"]
            or signed_approval["operator_public_sha256"] !=
                "sha256:" + hashlib.sha256(independently_pinned_operator_public).hexdigest()
            or any(signed_approval.get(k) != proposal.get(k) for k in (
                "host_id", "installation_id", "state_volume_id", "scope_sha256",
                "account_id", "region", "bucket", "prefix", "genesis_sha256",
                "writer_role_arn"))):
        _deny()
    body = {k:v for k,v in signed_approval.items() if k != "signature_ed25519"}
    try:
        encoded = signed_approval["signature_ed25519"]
        if type(encoded) is not str:
            _deny()
        raw = base64.b64decode(encoded, validate=True)
        if len(raw) != 64 or base64.b64encode(raw).decode("ascii") != encoded:
            _deny()
        Ed25519PublicKey.from_public_bytes(independently_pinned_operator_public).verify(
            raw, NEW_APPROVAL_DOMAIN + _canonical(body))
    except (InvalidSignature, ValueError, TypeError, OverflowError):
        _deny()
    return {"status":"NEW_SCOPE_SIGNED_SOURCE_ONLY_NOT_NATIVE_ACCEPTED",
            "new_scope_authorized":False, "native_accepted":False,
            "original_history_accepted":False, "ssm_authorized":False}
