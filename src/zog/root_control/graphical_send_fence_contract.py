"""Source-only externally monotonic owner protocol for graphical SSM sends.

Never install this as an active service from a source review. The actual
counter/operation history must be held in a *different independently protected*
authority storage/transaction domain from host-deploy's gateway. A gateway file,
its restored copy, and a self-signed backend are never a suitable owner.
"""
from __future__ import annotations

import hashlib
import json
import re
from cryptography.exceptions import InvalidSignature

SCHEMA = "zog-graphical-monotonic-operation-send-claim-v1"
APPROVAL_SCHEMA = "zog-graphical-send-owner-approval-v1"
RECEIPT_SCHEMA = "zog-graphical-send-owner-receipt-v1"
HEX32 = re.compile(r"[0-9a-f]{32}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
SCOPE_KEYS = frozenset(("host_id", "host_fingerprint", "installation_id",
                        "state_volume_id", "registry_id",
                        "controller_id", "authority_epoch"))
CLAIM_KEYS = frozenset(("request_id", "operation_id", "stage", "ordinal",
                        "remote_request_sha256", "binding_sha256",
                        "task_catalogue_sha256", "source_revision",
                        "source_generation", "lane", "target",
                        "monthly_pin_identity", "operation"))
STAGES = frozenset(("capabilities", "snapshot", "submit", "inspect"))


class SendOwnerDenied(ValueError):
    pass


def _deny():
    raise SendOwnerDenied("protected graphical send owner unavailable, revoked, or uncertain")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _exact(value, fields):
    if type(value) is not dict or set(value) != fields:
        _deny()
    try:
        if json.loads(canonical(value)) != value:
            _deny()
    except (ValueError, TypeError, OverflowError, UnicodeError):
        _deny()


def _hex(value, matcher):
    return type(value) is str and matcher.fullmatch(value) is not None


def validate_scope(scope):
    _exact(scope, SCOPE_KEYS)
    if (any(not _hex(scope[field], HEX32) for field in
            ("host_id", "installation_id", "registry_id", "controller_id"))
            or any(not _hex(scope[field], HEX64) for field in
                   ("host_fingerprint", "state_volume_id"))
            or type(scope["authority_epoch"]) is not int or
            scope["authority_epoch"] < 1):
        _deny()
    return dict(scope)


def validate_claim(claim):
    _exact(claim, CLAIM_KEYS)
    if (any(not _hex(claim[field], HEX32) for field in
            ("request_id", "operation_id"))
            or any(not _hex(claim[field], HEX64) for field in
                   ("remote_request_sha256", "binding_sha256",
                    "task_catalogue_sha256", "source_generation",
                    "monthly_pin_identity"))
            or not (type(claim["source_revision"]) is str and
                    re.fullmatch(r"[0-9a-f]{40}", claim["source_revision"]))
            or claim["stage"] not in STAGES
            or type(claim["ordinal"]) is not int or not 0 <= claim["ordinal"] < 64
            or type(claim["lane"]) is not str or not claim["lane"]
            or type(claim["target"]) is not str or not claim["target"]
            or claim["operation"] not in ("capabilities.inspect", "recipes.snapshot",
                                           "pipeline.submit", "pipeline.inspect")
            or dict(zip(("capabilities", "snapshot", "submit", "inspect"),
                        ("capabilities.inspect", "recipes.snapshot",
                         "pipeline.submit", "pipeline.inspect")))[claim["stage"]]
                    != claim["operation"]):
        _deny()
    return dict(claim)


def verify_signed(payload, signature_hex, public_key):
    """Caller cannot select the key; only the protected owner provides it."""
    # Ed25519 signatures are 64 bytes, encoded as exactly 128 hex chars.
    if not (type(signature_hex) is str and
            re.fullmatch(r"[0-9a-f]{128}", signature_hex)):
        _deny()
    try:
        public_key.verify(bytes.fromhex(signature_hex), canonical(payload))
    except (ValueError, TypeError, AttributeError, InvalidSignature):
        _deny()


class SendOwner:
    """Source contract; backend must be separately installed protected CAS owner.

    backend.claim_once(scope, claim_hash, operation_id) returns a strictly
    monotonic record, atomically durable before return. It *must* never offer
    reset/delete/release/replay. Revocation is an independently monotonic
    operation retaining all prior claims. The backend is explicitly not a
    gateway-owned path. Backend native authenticity is out of scope.
    """
    def __init__(self, *, scope, operator_public_key, owner_signing_key,
                 protected_backend):
        self.scope = validate_scope(scope)
        if operator_public_key is None or owner_signing_key is None or protected_backend is None:
            _deny()
        for method in ("claim_once", "revoke", "observe"):
            if not callable(getattr(protected_backend, method, None)):
                _deny()
        self.operator_public_key = operator_public_key
        self.owner_signing_key = owner_signing_key
        self.backend = protected_backend

    def _approve(self, signed_approval, signature, *, action, claim=None, now):
        if type(signed_approval) is not dict or set(signed_approval) != {
                "schema", "scope", "action", "claim_hash", "expires_at", "approval_id"}:
            _deny()
        if signed_approval["schema"] != APPROVAL_SCHEMA or signed_approval["action"] != action:
            _deny()
        if signed_approval["scope"] != self.scope or (
                signed_approval["claim_hash"] !=
                (hashlib.sha256(canonical(claim)).hexdigest() if claim is not None else "0"*64)):
            _deny()
        if (type(now) is not int or type(signed_approval["expires_at"]) is not int
                or signed_approval["expires_at"] < now
                or signed_approval["expires_at"] - now > 900
                or not _hex(signed_approval["approval_id"], HEX32)):
            _deny()
        verify_signed(signed_approval, signature, self.operator_public_key)
        return signed_approval["approval_id"]

    def _receipt(self, action, claim_hash, observation):
        # Only the native backend's authenticated, durable CAS witness may be
        # transformed into a signed receipt; a boolean return is insufficient.
        if (type(observation) is not dict or set(observation) !=
                {"sequence", "operation_id", "claim_hash", "status", "epoch"}
                or type(observation["sequence"]) is not int
                or observation["sequence"] < 1
                or observation["claim_hash"] != claim_hash
                or observation["epoch"] != self.scope["authority_epoch"]
                or observation["status"] not in ("claimed", "revoked")):
            _deny()
        result = {"schema": RECEIPT_SCHEMA, "action": action,
                  "scope": self.scope, "witness": observation}
        try:
            signature = self.owner_signing_key.sign(canonical(result)).hex()
        except (AttributeError, TypeError, ValueError):
            _deny()
        return {"body": result, "signature": signature}

    def claim_once(self, *, claim, approval, approval_signature, now):
        claim = validate_claim(claim)
        self._approve(approval, approval_signature, action="send-claim", claim=claim,
                      now=now)
        digest = hashlib.sha256(canonical({"schema": SCHEMA, "scope": self.scope,
                                          "claim": claim})).hexdigest()
        # Exactly one external atomic durable CAS. Never perform SendCommand
        # in this module; a lost ack is a permanent no-retry hold.
        try:
            state = self.backend.claim_once(self.scope, digest, claim["operation_id"])
        except Exception:
            _deny()
        if state.get("status") != "claimed" or state.get("operation_id") != claim["operation_id"]:
            _deny()
        return self._receipt("claimed", digest, state)

    def revoke(self, *, approval, approval_signature, now):
        self._approve(approval, approval_signature, action="revoke", now=now)
        digest = "0"*64
        try:
            state = self.backend.revoke(self.scope)
        except Exception:
            _deny()
        if state.get("status") != "revoked" or state.get("operation_id") is not None:
            _deny()
        return self._receipt("revoked", digest, state)

    def observe(self, operation_id):
        """Read-only recovery: observation never authorizes redelivery."""
        if not _hex(operation_id, HEX32):
            _deny()
        try:
            state = self.backend.observe(self.scope, operation_id)
        except Exception:
            _deny()
        if state is None:
            # No claim witness is NOT a send permit: a rolled-back gateway
            # cannot use observe to authorize another claim without fresh
            # current operator approval and independent CAS.
            return {"status": "unknown-no-send-authority"}
        if (type(state) is not dict or state.get("operation_id") != operation_id
                or state.get("status") not in ("claimed", "revoked")):
            _deny()
        return {"status": "claimed-or-revoked-no-retry",
                "sequence": state["sequence"], "operation_id": operation_id}
