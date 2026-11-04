"""Independently signed original GitHub-event evidence for Task C.

Copyright (c) 2026 Alex Black. BSD-3-Clause OR GPL-3.0-only.

The gateway never supplies or selects these bytes. The installer must pin the
genuine event issuer separately from the operator's grant and attest the source
event itself. A signature only proves custody of that previously approved
issuer key; it does not make caller-supplied issue JSON authentic.
"""
from __future__ import annotations

import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import graphical_operation_owner_source as source
from . import graphical_task_c_owner as taskc
from .graphical_native_owner import hold

SCHEMA = "zog-graphical-task-c-original-github-evidence-v1"
DOMAIN = b"zog-graphical-task-c-original-github-evidence-v1\0"
MAX_LIFETIME = 86400


def verify_installed_evidence(envelope, *, registry, pinned_issuer_key, now):
    if (not isinstance(registry, taskc.ProtectedOriginalRegistry)
            or type(pinned_issuer_key) is not bytes
            or len(pinned_issuer_key) != 32
            or type(now) is not int or type(envelope) is not dict
            or set(envelope) != {"schema", "scope_sha256", "issued_at",
                                 "expires_at", "records", "signature_ed25519"}
            or envelope["schema"] != SCHEMA
            or not source.match(envelope["scope_sha256"], source.SHA)
            or type(envelope["issued_at"]) is not int
            or type(envelope["expires_at"]) is not int
            or not envelope["issued_at"] <= now <= envelope["expires_at"]
            or not 0 < envelope["expires_at"] - envelope["issued_at"] <= MAX_LIFETIME
            or type(envelope["records"]) is not dict):
        hold()

    stage_ids = {operation_id for operation_id, entry in registry.entries.items()
                 if operation_id == entry["stage_operation_id"]}
    if not stage_ids or set(envelope["records"]) != stage_ids:
        hold()

    expected_scope = None
    for stage_id in stage_ids:
        item = registry.entries[stage_id]
        req = item["owner_request"]
        scope = source.digest(source.scope_from_request(req))
        if expected_scope is not None and expected_scope != scope:
            hold()
        expected_scope = scope

        proof = envelope["records"][stage_id]
        if (type(proof) is not dict
                or set(proof) != {"original", "github_event_sha256",
                                     "github_delivery_id", "original_commit_sha"}
                or proof["original"] != item["original"]
                or not source.match(proof["github_event_sha256"], source.SHA)
                or not source.match(proof["original_commit_sha"], source.H40)
                or type(proof["github_delivery_id"]) is not str
                or not 1 <= len(proof["github_delivery_id"]) <= 128
                or not all(ch.isalnum() or ch in "-_" for ch in
                            proof["github_delivery_id"])):
            hold()
        # A separately signed event must describe the same original action
        # for its independently derived preflight sibling.
        preflight_id = taskc.preflight_id(req["request_id"], stage_id)
        preflight = registry.entries.get(preflight_id)
        if preflight is None:
            hold()
        for key in taskc.ORIGINAL_KEYS - {"operation_id"}:
            if preflight["original"][key] != item["original"][key]:
                hold()

    if envelope["scope_sha256"] != expected_scope:
        hold()
    try:
        signature = base64.b64decode(envelope["signature_ed25519"], validate=True)
        if (len(signature) != 64 or
                base64.b64encode(signature).decode("ascii") !=
                envelope["signature_ed25519"]):
            hold()
        Ed25519PublicKey.from_public_bytes(pinned_issuer_key).verify(
            signature, DOMAIN + source.canonical({
                k: v for k, v in envelope.items() if k != "signature_ed25519"}))
    except (ValueError, TypeError, InvalidSignature):
        hold()
    return {"status": "independently-signed-original-evidence-verified",
            "scope_sha256": expected_scope, "stage_operations": sorted(stage_ids)}
