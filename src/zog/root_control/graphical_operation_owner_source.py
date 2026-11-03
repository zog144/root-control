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
    "schema", "host_id", "installation_id", "state_volume_id",
    "lane", "task", "catalogue_sha256", "source_revision",
    "monthly_pin_identity", "base_generation_id",
    "predecessor_receipt_sha256", "request_id", "original_request_sha256",
    "stage_once_receipt_sha256", "operation_id", "stage", "ordinal",
    "remote_request_sha256", "authority_epoch", "authority_pin_sha256",
    "approval_sha256",
}
BIND = (
    "host_id", "installation_id", "state_volume_id", "lane", "task",
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
    for key in ("request_id", "operation_id"):
        if not match(row[key], H32): deny()
    for key in ("catalogue_sha256", "monthly_pin_identity",
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


class SyntheticExternalLedger:
    """TEST ONLY: fixture represents independently durable service state.

    It is *not* rollback-resistant. The native owner must use another
    rollback domain, immutable current authority and persistent monotonic CAS.
    """
    def __init__(self, approved_scope):
        if (type(approved_scope) is not dict
                or set(approved_scope) != {"schema", *BIND}
                or approved_scope["schema"] != SCOPE):
            deny()
        self.lock = threading.RLock()
        self.scope = json.loads(canonical(approved_scope))
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
            if ledger.revoked or scope_from_request(req) != ledger.scope:
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
