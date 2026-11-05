"""Prospective Task C original authority *issuance*, separated from runtime.

This code NEVER enrolls itself, generates production signing keys, recreates
the S3 genesis, or grants authority by running tests. Real issuance requires
independently provisioned (and independently pinned) operator and event keys.
All signing callbacks must be provided by those externally controlled roles.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import datetime, timezone
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import graphical_operation_owner_source as owner
from . import graphical_task_c_owner as taskc
from . import graphical_task_c_origin as origin
from . import graphical_task_c_trust_authority as trust

EVENT_LIMIT = 65536
WEBHOOK_LIFETIME = 900
ISSUANCE_TTL = 900


class IssuanceDenied(ValueError):
    pass


def hold():
    raise IssuanceDenied("original authority issuance denied; no authority created")


def canonical(data):
    return owner.canonical(data)


def sha(raw):
    if type(raw) is not bytes:
        hold()
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            hold()
        result[key] = value
    return result


def strict(raw):
    if type(raw) is not bytes or not 2 <= len(raw) <= EVENT_LIMIT:
        hold()
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique,
                          parse_constant=lambda _: hold())
    except (ValueError, UnicodeError, OverflowError, TypeError):
        hold()


def _uuid32(value):
    if not owner.match(value, owner.H32):
        hold()
    try:
        if uuid.UUID(hex=value).hex != value:
            hold()
    except (ValueError, TypeError, AttributeError):
        hold()


def _signature(signer, pinned_public, domain, body):
    """Opaque signer, e.g. separately approved protected signer service.

    Produces no valid signature if the pinned key does not match the signer.
    Never accepts a caller-chosen public key from the unsigned request.
    """
    if (not callable(signer) or type(pinned_public) is not bytes
            or len(pinned_public) != 32 or type(domain) is not bytes):
        hold()
    try:
        sig = signer(domain + canonical(body))
        if type(sig) is not bytes or len(sig) != 64:
            hold()
        Ed25519PublicKey.from_public_bytes(pinned_public).verify(
            sig, domain + canonical(body))
    except (ValueError, TypeError, InvalidSignature):
        hold()
    return {**body, "signature_ed25519": base64.b64encode(sig).decode("ascii")}


def issue_original_registry(
    *, stage_request, preflight_request, stage_original,
    approval_ids, expires_at, now, sign_operator, pinned_operator_public,
):
    """Create exact v1 operator approvals and mapping for two distinct claims.

    The submitted candidate MUST already be independently prepared and
    consented to by the human operator. No IDs or requests are generated.
    """
    stage = owner.validate_request(stage_request)
    preflight = owner.validate_request(preflight_request)
    stage_id = stage["operation_id"]
    pre_id = taskc.preflight_id(stage["request_id"], stage_id)
    if (preflight != {**stage, "operation_id": pre_id}
            or stage_id == pre_id or not isinstance(stage_original, dict)
            or set(stage_original) != taskc.ORIGINAL_KEYS
            or stage_original["operation_id"] != stage_id
            or stage_original["request_id"] != stage["request_id"]
            or stage_original["stage"] != stage["stage"]
            or stage_original["ordinal"] != stage["ordinal"]
            or type(approval_ids) is not dict
            or set(approval_ids) != {stage_id, pre_id}
            or approval_ids[stage_id] == approval_ids[pre_id]
            or type(now) is not int or type(expires_at) is not int
            or not now <= expires_at <= now + ISSUANCE_TTL):
        hold()
    _uuid32(stage["request_id"])
    _uuid32(stage_id)
    _uuid32(pre_id)
    for value in approval_ids.values():
        _uuid32(value)
    result = {}
    for req in (stage, preflight):
        operation_id = req["operation_id"]
        original = {**stage_original, "operation_id": operation_id}
        fake_frame = {"schema": taskc.IPC_SCHEMA, "nonce": "0"*48,
                      "action": "submit-original" if operation_id == stage_id
                      else "preflight-original", **original}
        taskc.parse_frame(canonical(fake_frame) + b"\n")
        approval_body = {
            "schema": owner.APPROVAL_SCHEMA,
            "approval_id": approval_ids[operation_id],
            "request_sha256": owner.digest(req),
            "scope_sha256": owner.digest(owner.scope_from_request(req)),
            "expires_at": expires_at,
        }
        grant = _signature(sign_operator, pinned_operator_public,
                           owner.APPROVAL_DOMAIN, approval_body)
        map_body = {
            "schema": taskc.MAPPING_SCHEMA,
            "original": original,
            "stage_operation_id": stage_id,
            "owner_request_sha256": owner.digest(req),
            "approval_sha256": owner.digest(grant),
        }
        mapping = _signature(sign_operator, pinned_operator_public,
                             taskc.MAPPING_DOMAIN, map_body)
        owner.verify_original_operator_approval(
            req, grant, externally_pinned_operator_key=pinned_operator_public,
            expected_approval_id=approval_ids[operation_id], now=now)
        result[operation_id] = {
            "mapping": mapping, "owner_request": req,
            "original_operator_approval": grant,
        }
    taskc.ProtectedOriginalRegistry(
        result, pinned_operator_public_key=pinned_operator_public)
    return result


def attest_original_github_event(
    *, event_raw, signature_header, delivery_id, secret,
    registry, authorized_actor, expected_repository_id, expected_actor_id,
    original_commit_sha, issued_at, expires_at,
    pinned_issuer_public, sign_issuer,
):
    """Issue original event evidence from authenticated *raw* issue-open webhook.

    GitHub issue API snapshots and the GITHUB_EVENT_PATH environment alone do
    NOT provide this proof: require HMAC-SHA256 of the exact raw delivery.
    """
    if (type(event_raw) is not bytes or not 1 <= len(event_raw) <= EVENT_LIMIT
            or type(secret) is not bytes or len(secret) < 32
            or type(signature_header) is not str
            or not signature_header.startswith("sha256=")
            or not owner.match(signature_header[7:], owner.H64)
            or not hmac.compare_digest(
                signature_header[7:],
                hmac.new(secret, event_raw, hashlib.sha256).hexdigest())
            or type(delivery_id) is not str or
            not 1 <= len(delivery_id) <= 128 or
            not all(c.isalnum() or c in "-_" for c in delivery_id)
            or not owner.match(original_commit_sha, owner.H40)
            or type(expected_repository_id) is not int
            or expected_repository_id <= 0
            or type(expected_actor_id) is not int or expected_actor_id <= 0
            or type(issued_at) is not int or type(expires_at) is not int
            or not issued_at <= expires_at <= issued_at + origin.MAX_LIFETIME
            or not isinstance(registry, taskc.ProtectedOriginalRegistry)):
        hold()
    event = strict(event_raw)
    repo, sender, issue = (event.get("repository"), event.get("sender"),
                           event.get("issue"))
    if (not isinstance(repo, dict) or
            repo.get("id") != expected_repository_id
            or not isinstance(sender, dict) or
            sender.get("id") != expected_actor_id
            or not isinstance(issue, dict)
            or issue.get("user", {}).get("id") != expected_actor_id
            or event.get("action") != "opened"):
        hold()
    try:
        from zog.host_deploy.gateway.github_dispatch import prepare_event
        from zog.host_deploy.gateway.protocol import request_digest
        request = prepare_event(event, frozenset({authorized_actor}))
        created = issue["created_at"]
        if type(created) is not str or not created.endswith("Z"):
            hold()
        timestamp = int(datetime.fromisoformat(
            created.replace("Z", "+00:00")).timestamp())
    except (ValueError, TypeError, KeyError, ImportError):
        hold()
    if (timestamp > issued_at or issued_at - timestamp > WEBHOOK_LIFETIME
            or request["origin"]["trigger_actor"] != authorized_actor
            or request["origin"]["issue_number"] != issue["number"]):
        hold()
    stage_ids = [op for op, item in registry.entries.items()
                 if item["stage_operation_id"] == op]
    if len(stage_ids) != 1:
        # Multiple unrelated issue deliveries require distinct receipts.
        hold()
    stage_id = stage_ids[0]
    selected = registry.entries[stage_id]
    original = selected["original"]
    if (original["origin_repository"] != request["origin"]["repository"]
            or original["origin_issue_number"] != issue["number"]
            or original["origin_trigger_actor"] != authorized_actor
            or original["request_id"] != request["request_id"]
            or original["original_request_sha256"] != request_digest(request)
            or owner.digest(owner.scope_from_request(
                selected["owner_request"])) !=
               owner.digest(owner.scope_from_request(
                registry.entries[taskc.preflight_id(
                    original["request_id"], stage_id)]["owner_request"]))):
        hold()
    body = {
        "schema": origin.SCHEMA,
        "scope_sha256": owner.digest(owner.scope_from_request(
            selected["owner_request"])),
        "issued_at": issued_at, "expires_at": expires_at,
        "records": {stage_id: {
            "original": original,
            "github_event_sha256": sha(event_raw),
            "github_delivery_id": delivery_id,
            # Reviewed source/dispatch commit; NOT claimed as a commit SHA
            # contained in the issue-opened webhook (which lacks this field).
            "original_commit_sha": original_commit_sha,
        }},
    }
    envelope = _signature(sign_issuer, pinned_issuer_public,
                          origin.DOMAIN, body)
    origin.verify_installed_evidence(
        envelope, registry=registry, pinned_issuer_key=pinned_issuer_public,
        now=issued_at)
    return envelope


def prepare_broker_purpose(
    *, record, registry, origin_evidence, operator_public, issuer_public,
    pin, broker_config, root_row, readonly_role_arn, expires_at, now,
):
    """Derive exactly the v1 broker purpose body from original input bytes."""
    from zog.host_deploy.gateway.graphics_owner_trust_history import PIN_KEYS
    if (type(record) is not dict or set(record) != trust.ORIGINAL_FIELDS
            or record["schema"] != trust.ORIGINAL_SCHEMA
            or record["root_source_revision"] != trust.OWNER_SOURCE
            or type(root_row) is not dict or type(pin) is not dict
            or set(pin) != PIN_KEYS
            or type(broker_config) is not dict
            or type(operator_public) is not bytes or len(operator_public) != 32
            or type(issuer_public) is not bytes or len(issuer_public) != 32
            or operator_public == issuer_public
            or not isinstance(registry, taskc.ProtectedOriginalRegistry)
            or registry.key != operator_public
            or type(now) is not int or type(expires_at) is not int
            or not now <= expires_at <= now + ISSUANCE_TTL
            or not isinstance(readonly_role_arn, str)
            or trust.ROLE.fullmatch(readonly_role_arn) is None):
        hold()
    scope = owner.digest(owner.scope_from_request(
        next(iter(registry.entries.values()))["owner_request"]))
    event = origin.verify_installed_evidence(
        origin_evidence, registry=registry,
        pinned_issuer_key=issuer_public, now=now)
    if (scope != event["scope_sha256"]
            or record["checkpoint_scope_sha256"] != scope
            or pin["original_checkpoint_sha256"] !=
               sha(canonical(record))
            or pin["scope_sha256"] != scope
            or pin["installation_id"] != record["installation_id"]
            or pin["state_volume_id"] != record["state_volume_id"]
            or pin["installed_owner_source"] != trust.OWNER_SOURCE
            or not owner.match(pin["installed_broker_source"], owner.H64)
            or record["host_id"] != root_row.get("host_id")
            or record["installation_id"] != root_row.get("installation_id")
            or record["state_volume_id"] != root_row.get("state_volume_id")
            or root_row.get("checkpoint", {}).get("account_id") != record["checkpoint_account_id"]
            or root_row["checkpoint"].get("region") != record["checkpoint_region"]
            or root_row["checkpoint"].get("bucket") != record["checkpoint_bucket"]
            or root_row["checkpoint"].get("prefix") != record["checkpoint_prefix"]
            or root_row["checkpoint"].get("genesis_sha256") != record["checkpoint_genesis_sha256"]
            or root_row["checkpoint"].get("role_arn") != record["checkpoint_role_arn"]
            or not trust.ROLE.fullmatch(record["checkpoint_role_arn"])
            or not trust.ROLE.fullmatch(root_row.get("ssm", {}).get("role_arn", ""))
            or readonly_role_arn in {
                record["checkpoint_role_arn"], root_row["ssm"]["role_arn"]}
            or readonly_role_arn.split(":")[4] != record["checkpoint_account_id"]
            or broker_config.get("root_source_revision") != trust.OWNER_SOURCE
            or broker_config.get("broker_source_revision") != trust.BROKER_SOURCE):
        hold()
    return {
        "schema": trust.PURPOSE_SCHEMA,
        "pin_sha256": sha(canonical(pin)),
        "original_checkpoint_sha256": sha(canonical(record)),
        "original_event_sha256": sha(canonical(origin_evidence)),
        "operator_public_sha256": sha(operator_public),
        "issuer_public_sha256": sha(issuer_public),
        "owner_source_revision": trust.OWNER_SOURCE,
        "broker_source_revision": trust.BROKER_SOURCE,
        "readonly_role_arn": readonly_role_arn,
        "writer_role_arn": record["checkpoint_role_arn"],
        "ssm_role_arn": root_row["ssm"]["role_arn"],
        "host_id": record["host_id"],
        "installation_id": record["installation_id"],
        "state_volume_id": record["state_volume_id"],
        "scope_sha256": scope,
        "gateway_uid": broker_config["gateway_uid"],
        "gateway_gid": broker_config["gateway_gid"],
        "gateway_cgroup": broker_config["gateway_cgroup"],
        "gateway_executable_sha256": broker_config["gateway_executable_sha256"],
        "expires_at": expires_at,
    }


def issue_broker_purpose(*, body, sign_operator, pinned_operator_public):
    if type(body) is not dict or set(body) != trust.APPROVAL_FIELDS - {
            "signature_ed25519"} or body["schema"] != trust.PURPOSE_SCHEMA:
        hold()
    return _signature(sign_operator, pinned_operator_public,
                      trust.PURPOSE_DOMAIN, body)


def issue_revocation(*, approved_scope, approval_id, expires_at, now,
                     sign_operator, pinned_operator_public):
    if (type(now) is not int or type(expires_at) is not int
            or not now <= expires_at <= now + ISSUANCE_TTL):
        hold()
    _uuid32(approval_id)
    body = {"schema": owner.REVOCATION_APPROVAL_SCHEMA,
            "approval_id": approval_id,
            "scope_sha256": owner.digest(approved_scope),
            "action": "revoke", "expires_at": expires_at}
    envelope = _signature(sign_operator, pinned_operator_public,
                          owner.REVOCATION_APPROVAL_DOMAIN, body)
    owner.verify_signed_revocation_approval(
        approved_scope, envelope,
        externally_pinned_operator_key=pinned_operator_public,
        expected_approval_id=approval_id, now=now)
    # Only the independently protected owner can append S3 revoke.
    return envelope


def verify_public_receipt(*, registry, event, operator_public, issuer_public, now):
    """Nonsecret inspection only, never authority installation or acceptance."""
    records = taskc.ProtectedOriginalRegistry(
        registry, pinned_operator_public_key=operator_public)
    result = origin.verify_installed_evidence(
        event, registry=records, pinned_issuer_key=issuer_public, now=now)
    return {"status": "signed-issuance-source-verified-not-installed",
            "scope_sha256": result["scope_sha256"],
            "registry_sha256": sha(canonical(registry)),
            "event_sha256": sha(canonical(event)),
            "operator_public_sha256": sha(operator_public),
            "issuer_public_sha256": sha(issuer_public)}
