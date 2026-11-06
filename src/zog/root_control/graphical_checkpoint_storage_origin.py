"""Original Task C checkpoint history versus separately approved new scope.

Source contract only. No synthetic tuple, missing 000000 genesis, caller boolean,
or mounting a new empty disk can authenticate historical S3/STATE continuity.
No checkpoint creation, AWS operations, signer issuance, or native approval here.
"""
from __future__ import annotations

import hashlib
import json

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
