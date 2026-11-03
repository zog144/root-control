"""Source-only protected graphical SSM operation owner protocol.

NO installed service, socket or AWS client. Native implementation must supply
independently protected monotonic storage, separate from gateway STATE, and a
fixed trusted SSM sender. A signed observation is NEVER a reusable send grant.
"""
import base64
import hashlib
import json
import re
import threading
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

SCHEMA = "zog-protected-graphical-operation-request-v1"
SCOPE = "zog-protected-graphical-operation-scope-v1"
RECEIPT = "zog-protected-graphical-operation-observation-v1"
DOMAIN = b"zog-protected-graphical-operation-observation-v1\0"
H32 = re.compile(r"[a-f0-9]{32}\Z")
H40 = re.compile(r"[a-f0-9]{40}\Z")
H64 = re.compile(r"[a-f0-9]{64}\Z")
SHA = re.compile(r"sha256:[a-f0-9]{64}\Z")
NONCE = re.compile(r"[a-f0-9]{48}\Z")
LANE = re.compile(r"[a-z0-9][a-z0-9-]{0,47}\Z")
FIELDS = {
    "schema", "host_id", "host_fingerprint", "registry_id", "controller_id",
    "target_identity_sha256", "installation_id", "state_volume_id",
    "lane", "task", "catalogue_sha256", "source_revision",
    "monthly_pin_identity", "base_generation_id",
    "predecessor_receipt_sha256", "request_id", "original_request_sha256",
    "stage_once_receipt_sha256", "operation_id", "stage", "ordinal",
    "remote_request_sha256", "authority_epoch", "authority_pin_sha256",
    "approval_sha256",
}
BIND = (
    "host_id", "host_fingerprint", "registry_id", "controller_id",
    "target_identity_sha256", "installation_id", "state_volume_id",
    "lane", "task",
    "catalogue_sha256", "source_revision", "monthly_pin_identity",
    "base_generation_id", "predecessor_receipt_sha256",
    "authority_epoch", "authority_pin_sha256", "approval_sha256",
)
STAGES = frozenset(("capabilities", "snapshot", "submit", "inspect"))
TASKS = frozenset((
    "graphics-fonts-image-v1", "graphics-xcb-core-image-v1",
    "graphics-x11-core-image-v1",
))


class OperationDenied(RuntimeError):
    pass


def deny():
    raise OperationDenied("protected graphical operation owner refused or unavailable")


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def digest(obj):
    return "sha256:" + hashlib.sha256(canonical(obj)).hexdigest()


def match(value, pattern):
    return type(value) is str and pattern.fullmatch(value) is not None


def validate_request(row):
    if type(row) is not dict or set(row) != FIELDS or row["schema"] != SCHEMA:
        deny()
    for key in ("host_id", "installation_id", "state_volume_id",
                "base_generation_id"):
        if not match(row[key], H64): deny()
    for key in ("request_id", "operation_id", "registry_id", "controller_id"):
        if not match(row[key], H32): deny()
    for key in ("host_fingerprint", "target_identity_sha256",
                "catalogue_sha256", "monthly_pin_identity",
                "predecessor_receipt_sha256", "original_request_sha256",
                "stage_once_receipt_sha256", "remote_request_sha256",
                "authority_pin_sha256", "approval_sha256"):
        if not match(row[key], SHA): deny()
    if (not match(row["source_revision"], H40)
            or not match(row["lane"], LANE)
            or type(row["task"]) is not str or row["task"] not in TASKS
            or row["stage"] not in STAGES
            or type(row["ordinal"]) is not int or not 0 <= row["ordinal"] < 64
            or type(row["authority_epoch"]) is not int
            or not 1 <= row["authority_epoch"] < 2**53):
        deny()
    return json.loads(canonical(row))


def scope_from_request(request):
    row = validate_request(request)
    return {"schema": SCOPE, **{k: row[k] for k in BIND}}


# PR28's short-lived, independently signed operator approval is retained as a
# *pre-admission prerequisite* for PR29's stronger protected-owner sender.
# This verifier NEVER grants a caller a SendCommand token.
APPROVAL_SCHEMA = "zog-protected-graphical-original-operation-approval-v1"
APPROVAL_DOMAIN = b"zog-protected-graphical-original-operation-approval-v1\0"


def verify_original_operator_approval(request, approval_envelope, *,
                                      externally_pinned_operator_key,
                                      expected_approval_id, now):
    """Verify separately approved immutable original operation before owner admission.

    An installer, not gateway request data, must supply the pinned operator
    public key and expected approval identity. This offline source check
    does not create an approved operation in a native ledger.
    """
    req = validate_request(request)
    if (type(approval_envelope) is not dict or
            set(approval_envelope) != {"schema", "approval_id", "request_sha256",
                                      "scope_sha256", "expires_at",
                                      "signature_ed25519"} or
            approval_envelope["schema"] != APPROVAL_SCHEMA or
            not match(expected_approval_id, H32) or
            approval_envelope["approval_id"] != expected_approval_id or
            approval_envelope["request_sha256"] != digest(req) or
            approval_envelope["scope_sha256"] != digest(scope_from_request(req)) or
            type(now) is not int or type(approval_envelope["expires_at"]) is not int
            or approval_envelope["expires_at"] < now
            or approval_envelope["expires_at"] - now > 900 or
            type(externally_pinned_operator_key) is not bytes or
            len(externally_pinned_operator_key) != 32):
        deny()
    try:
        signature = base64.b64decode(
            approval_envelope["signature_ed25519"], validate=True)
        if (len(signature) != 64 or
                base64.b64encode(signature).decode("ascii") !=
                approval_envelope["signature_ed25519"]):
            deny()
        Ed25519PublicKey.from_public_bytes(externally_pinned_operator_key).verify(
            signature, APPROVAL_DOMAIN + canonical({
                k: v for k, v in approval_envelope.items()
                if k != "signature_ed25519"}))
    except (ValueError, TypeError, KeyError, InvalidSignature):
        deny()
    return {"operation_id": req["operation_id"],
            "request_sha256": digest(req),
            "approval_id": expected_approval_id,
            "status": "signed-original-grant-verified-not-installed"}


REVOCATION_APPROVAL_SCHEMA = "zog-protected-graphical-revocation-approval-v1"
REVOCATION_APPROVAL_DOMAIN = b"zog-protected-graphical-revocation-approval-v1\\0"


def verify_signed_revocation_approval(approved_scope, signed_grant, *,
                                      externally_pinned_operator_key,
                                      expected_approval_id, now):
    """Source contract: revocation must not be a caller-controlled naked scope."""
    if (type(approved_scope) is not dict or
            set(approved_scope) != {"schema", *BIND}
            or approved_scope.get("schema") != SCOPE
            or type(signed_grant) is not dict or
            set(signed_grant) != {"schema", "approval_id", "scope_sha256",
                                  "action", "expires_at", "signature_ed25519"}
            or signed_grant["schema"] != REVOCATION_APPROVAL_SCHEMA
            or signed_grant["action"] != "revoke"
            or not match(expected_approval_id,H32)
            or signed_grant["approval_id"] != expected_approval_id
            or signed_grant["scope_sha256"] != digest(approved_scope)
            or type(now) is not int
            or type(signed_grant["expires_at"]) is not int
            or not now <= signed_grant["expires_at"] <= now + 900
            or type(externally_pinned_operator_key) is not bytes
            or len(externally_pinned_operator_key) != 32):
        deny()
    try:
        signature=base64.b64decode(signed_grant["signature_ed25519"],validate=True)
        if len(signature)!=64 or base64.b64encode(signature).decode("ascii") != signed_grant["signature_ed25519"]:
            deny()
        Ed25519PublicKey.from_public_bytes(externally_pinned_operator_key).verify(
            signature,REVOCATION_APPROVAL_DOMAIN+canonical({
                k:v for k,v in signed_grant.items() if k!="signature_ed25519"}))
    except (InvalidSignature,ValueError,TypeError,KeyError):
        deny()
    return {"status":"signed-revocation-verified-no-authority-changed",
            "scope_sha256":digest(approved_scope)}


class SyntheticExternalLedger:
    """TEST ONLY: fixture represents independently durable service state.

    It is *not* rollback-resistant. The native owner must use another
    rollback domain, immutable current authority and persistent monotonic CAS.
    """
    def __init__(self, approved_scope, *, independently_approved_operations):
        if (type(approved_scope) is not dict
                or set(approved_scope) != {"schema", *BIND}
                or approved_scope["schema"] != SCOPE
                or type(independently_approved_operations) is not dict
                or not independently_approved_operations
                or any(not match(k, H32) or not match(v, SHA)
                       for k,v in independently_approved_operations.items())):
            deny()
        self.lock = threading.RLock()
        self.scope = json.loads(canonical(approved_scope))
        # TEST: preinstalled original-history decisions from a separate
        # protected root owner, not arbitrary first-seen remote requests.
        # Native source must authenticate each external approval before any
        # operation is added; this fixture deliberately cannot add entries.
        self.approved_operations = dict(independently_approved_operations)
        self.revoked = False
        self.sequence = 0
        self.claims = {}

    def revoke(self, scope):
        with self.lock:
            if scope != self.scope: deny()
            if not self.revoked:
                self.revoked = True
                self.sequence += 1
            return self.sequence


class SourceOnlyProtectedOwner:
    """Testable contract; NO runnable native sender is installed.

    The test_sender and test_signer are injected only in synthetic tests.
    Native entry points must NOT accept caller-supplied sender/keys/backends.
    """
    def __init__(self, ledger, *, test_sender, test_signer):
        if (type(ledger) is not SyntheticExternalLedger
                or not isinstance(test_signer, Ed25519PrivateKey)
                or not callable(test_sender)):
            deny()
        self._ledger = ledger
        self._sender = test_sender
        self._signer = test_signer
        self.public_key = test_signer.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def submit_once(self, request):
        req = validate_request(request)
        ledger = self._ledger
        with ledger.lock:
            if (ledger.revoked or scope_from_request(req) != ledger.scope
                    or ledger.approved_operations.get(req["operation_id"]) !=
                    digest(req)):
                deny()
            if req["operation_id"] in ledger.claims:
                # Exact replay and differing same-ID requests both deny.
                deny()
            ledger.sequence += 1
            ledger.claims[req["operation_id"]] = {
                "operation_id": req["operation_id"],
                "request_sha256": digest(req),
                "sequence": ledger.sequence,
                "outcome": "CLAIMED_UNCERTAIN",
                "command_id": None,
            }
            # Native linearization: durable independent claim must commit
            # BEFORE fixed-trusted-SendCommand, all under revocation lock.
            # Lost response, crash and cancellation NEVER release the claim.
            command_id = self._sender(json.loads(canonical(req)))
            if (type(command_id) is not str or
                    not 1 <= len(command_id) <= 128):
                deny()
            item = ledger.claims[req["operation_id"]]
            item["outcome"] = "SENT_ORIGINAL"
            item["command_id"] = command_id
            return json.loads(canonical(item))

    def revoke(self, approved_scope):
        return self._ledger.revoke(approved_scope)

    def revoke_signed(self, approved_scope, signed_grant, *,
                      externally_pinned_operator_key, expected_approval_id, now):
        """Selected revocation source interface: operator signed, same lock."""
        verify_signed_revocation_approval(
            approved_scope,signed_grant,
            externally_pinned_operator_key=externally_pinned_operator_key,
            expected_approval_id=expected_approval_id,now=now)
        # Existing synthetic ledger.revoke uses the SAME RLock as submit_once.
        # No gateway or native caller may invoke raw revoke as an RPC.
        return self._ledger.revoke(approved_scope)

    def read_signed(self, *, request, nonce):
        """Fresh signed observation; cannot be redeemed for another send."""
        req = validate_request(request)
        if not match(nonce, NONCE): deny()
        with self._ledger.lock:
            if scope_from_request(req) != self._ledger.scope: deny()
            item = self._ledger.claims.get(req["operation_id"])
            if item is None or item["request_sha256"] != digest(req): deny()
            body = {
                "schema": RECEIPT,
                "nonce": nonce,
                "scope": self._ledger.scope,
                "revoked": self._ledger.revoked,
                "sequence": self._ledger.sequence,
                "operation": json.loads(canonical(item)),
            }
            sig = self._signer.sign(DOMAIN + canonical(body))
            return canonical({**body, "signature_ed25519":
                              base64.b64encode(sig).decode("ascii")})



def verify_signed_observation(raw, *, expected_nonce, original_request,
                              externally_pinned_public_key,
                              externally_pinned_key_sha256,
                              minimum_sequence):
    """Offline contract verifier; no operation grants returned.

    The public key and highwater MUST come from separately installed,
    protected independent authority, never a caller-chosen gateway file.
    A native consumer needs fixed-provenance transport/peer admission and
    a fresh online nonce; a signed old/cache reply is not current authority.
    """
    if (type(raw) is not bytes or not 0 < len(raw) <= 8192
            or not match(expected_nonce, NONCE)
            or type(externally_pinned_public_key) is not bytes
            or len(externally_pinned_public_key) != 32
            or not match(externally_pinned_key_sha256, SHA)
            or "sha256:" + hashlib.sha256(externally_pinned_public_key).hexdigest()
            != externally_pinned_key_sha256
            or type(minimum_sequence) is not int or minimum_sequence < 1):
        deny()
    try:
        def unique(pairs):
            obj = {}
            for k,v in pairs:
                if k in obj: deny()
                obj[k] = v
            return obj
        row=json.loads(raw,object_pairs_hook=unique,
                       parse_constant=lambda _:deny())
        if type(row) is not dict or canonical(row) != raw:
            deny()
        if (set(row) != {"schema","nonce","scope","revoked","sequence",
                         "operation","signature_ed25519"}
                or row["schema"] != RECEIPT or row["nonce"] != expected_nonce
                or row["scope"] != scope_from_request(original_request)
                or type(row["revoked"]) is not bool
                or type(row["sequence"]) is not int
                or row["sequence"] < minimum_sequence):
            deny()
        item = row["operation"]
        if (type(item) is not dict or
                set(item) != {"operation_id","request_sha256",
                              "sequence","outcome","command_id"}
                or item["operation_id"] != original_request["operation_id"]
                or item["request_sha256"] != digest(
                    validate_request(original_request))
                or type(item["sequence"]) is not int
                or not 1 <= item["sequence"] <= row["sequence"]
                or item["outcome"] not in (
                    "CLAIMED_UNCERTAIN","SENT_ORIGINAL")
                or (item["outcome"] == "CLAIMED_UNCERTAIN" and
                    item["command_id"] is not None)
                or (item["outcome"] == "SENT_ORIGINAL" and
                    (type(item["command_id"]) is not str or
                     not 1 <= len(item["command_id"]) <= 128))):
            deny()
        signature=base64.b64decode(row["signature_ed25519"],validate=True)
        if (len(signature) != 64 or
                base64.b64encode(signature).decode("ascii") !=
                row["signature_ed25519"]):
            deny()
        Ed25519PublicKey.from_public_bytes(
            externally_pinned_public_key).verify(
                signature, DOMAIN+canonical({
                    k:v for k,v in row.items() if k!="signature_ed25519"
                }))
        return {"outcome":item["outcome"],"revoked":row["revoked"],
                "sequence":row["sequence"],"command_id":item["command_id"]}
    except (ValueError,KeyError,TypeError,UnicodeError,
            InvalidSignature,OverflowError):
        deny()
