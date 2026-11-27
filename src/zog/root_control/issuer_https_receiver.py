"""Fail-closed, purpose-scoped HTTPS credential receiver for the enrolled Host.

Opt-in root operation only. No daemon RPC, SSH command, browser access, or
automatic retry. The station producer must implement the exact signed v1
envelope before live delivery can be authorized.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
from functools import wraps
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import uuid
import ssl
import stat
import time
from urllib.parse import urlsplit

from zog.box_control.project import Project
from zog.host_identify import credential_delivery as cd
from zog.host_identify import signatures
from . import issuer_credentials as credentials
from . import issuer_station_transfer as local
from .issuer_receipt_common import (
    CredentialReceiptDenied, deny as _deny, root_regular as _root_regular,
    pairs as _pairs,
)

# The only wire schemas are defined by pinned host-identify 0.3.5.
PROTOCOL_SOURCE = "4a176373ff4cb47a66a8ab1b5fd3d6ff01ff2a3b"
# A separate native owner acceptance/release is mandatory. Source review is
# intentionally incapable of contacting a real Station or installing a token.
LIVE_NETWORK_ACTIVATION = False
PURPOSE = "issuer-cloudflare-dns01"
CONSUMER = "certify-manage"
PROFILE_SCHEMA = "zog-issuer-https-credential-client-v1"
PATH = "/.well-known/zog/credential-delivery/v1"
RECEIPT_PATH = PATH + "/receipt"
CANCEL_PATH = PATH + "/cancel"
_TLS_CA = Path("/etc/zog/issuer-credentials/station-ca.pem")
_AUTHORITY_PIN = credentials.AUTH_ROOT / "credential-authority.json"
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_UUID = credentials._UUID


def canonical(value):
    return cd.canonical(value)


def _profile_path(project):
    return credentials.AUTH_ROOT / (
        hashlib.sha256(str(project.path).encode()).hexdigest() + ".https-receiver.json")


def _profile(project):
    try:
        value = json.loads(_root_regular(_profile_path(project)), object_pairs_hook=_pairs)
        fields = {"schema", "project", "https_origin", "tls_authority_pin_sha256",
            "station_signer_pin_sha256", "owner_authority_sha256", "host_id",
            "installation_id", "state_volume_id", "host_fingerprint",
            "registry_id", "authorization_id", "assignment_id",
            "assignment_revision", "receipt_sha256", "purpose",
            "credential_revision", "grant_id", "storage_id", "consumer_uid",
            "delivery_credential_id", "credential_authorization_id",
            "credential_authorization_revision", "credential_authority_pin_sha256"}
        if type(value) is not dict or set(value) != fields or value["schema"] != PROFILE_SCHEMA:
            _deny()
        if value["project"] != str(project.path):
            _deny()
        for name in ("host_id", "installation_id", "state_volume_id",
                     "assignment_id"):
            if type(value[name]) is not str or not _UUID.fullmatch(value[name]):
                _deny()
        for name in ("grant_id", "storage_id"):
            if type(value[name]) is not str or not credentials._HEX32.fullmatch(value[name]):
                _deny()
        for name in ("host_fingerprint", "authorization_id", "receipt_sha256",
                     "tls_authority_pin_sha256", "station_signer_pin_sha256",
                     "owner_authority_sha256", "credential_authority_pin_sha256"):
            if type(value[name]) is not str or not _HEX.fullmatch(value[name]):
                _deny()
        if (type(value["delivery_credential_id"]) is not str
                or not re.fullmatch(r"cloudflare-[a-z0-9-]{1,50}",
                                    value["delivery_credential_id"])
                or type(value["credential_authorization_id"]) is not str
                or not _UUID.fullmatch(value["credential_authorization_id"])
                or type(value["credential_authorization_revision"]) is not int
                or value["credential_authorization_revision"] < 1):
            _deny()
        if type(value["registry_id"]) is not str or not re.fullmatch(
                r"[a-z0-9][a-z0-9-]{0,63}", value["registry_id"]):
            _deny()
        if (type(value["assignment_revision"]) is not int or value["assignment_revision"] < 1
                or type(value["credential_revision"]) is not int or value["credential_revision"] < 1
                or type(value["consumer_uid"]) is not int or value["consumer_uid"] <= 0):
            _deny()
        origin = urlsplit(value["https_origin"])
        if (origin.scheme != "https" or origin.port not in (None, 443)
                or origin.path not in ("", "/") or not origin.hostname
                or origin.username or origin.password or origin.query or origin.fragment
                or origin.hostname != origin.hostname.encode("idna").decode("ascii")
                or not re.fullmatch(r"[a-z0-9.-]{1,253}", origin.hostname)):
            _deny()
        if (value["https_origin"] != "https://" + origin.hostname
                or value["purpose"] != PURPOSE):
            _deny()
        authority = _root_regular("/state/host-install/certificate-owner-authority/authority.json")
        pin = _root_regular("/etc/zog/host-install/certificate-assignment-authority.json", mode=0o444)
        ca = _root_regular(_TLS_CA, max_bytes=16384)
        credential_authority_pin = _root_regular(_AUTHORITY_PIN, max_bytes=4096)
        if (hashlib.sha256(authority).hexdigest() != value["owner_authority_sha256"]
                or hashlib.sha256(pin).hexdigest() != value["station_signer_pin_sha256"]
                or hashlib.sha256(ca).hexdigest() != value["tls_authority_pin_sha256"]
                or hashlib.sha256(credential_authority_pin).hexdigest() !=
                   value["credential_authority_pin_sha256"]
                or b"BEGIN CERTIFICATE" not in ca):
            _deny()
        return value
    except (ValueError, TypeError, OSError, UnicodeError):
        _deny()


def _projection(project, approved):
    """Read the retained nonsecret station projection without local vault peer state."""
    path, _peer_path = credentials._projection_paths(project)
    try:
        credentials._check_root_directory(path.parent)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                    or stat.S_IMODE(info.st_mode) not in (0o440, 0o600)
                    or info.st_nlink != 1 or info.st_size > 8192):
                _deny()
            raw = os.read(fd, 8193)
            if len(raw) != info.st_size or len(raw) > 8192:
                _deny()
        finally:
            os.close(fd)
        projection = json.loads(raw, object_pairs_hook=_pairs)
        if local._validated(projection, approved) != credentials._authorization_id(approved):
            _deny()
        return projection
    except (OSError, ValueError, UnicodeError, TypeError):
        _deny()


def _approval(project, profile):
    approval_path, ledger_path, pending_path, _lock_path = credentials._paths(project)
    if pending_path.exists() or pending_path.is_symlink():
        _deny()
    approved, grant = credentials._authorization(project, approval_path)
    ledger = credentials._read_protected(ledger_path, missing_ok=True)
    credentials._check_revision(ledger, approved)
    credentials._quiet(project)
    aid = credentials._authorization_id(approved)
    projection = _projection(project, approved)
    if (projection.get("origin") != "managed"
            or projection.get("host_id") != profile["host_id"]
            or projection.get("installation_id") != profile["installation_id"]
            or aid != profile["authorization_id"]):
        _deny()
    for key in ("assignment_id", "assignment_revision", "receipt_sha256",
                "credential_revision", "grant_id", "storage_id"):
        if approved.get(key) != profile[key]:
            _deny()
    if (not credentials._UUID.fullmatch(approved.get("credential_id", ""))
            or not credentials._HEX64.fullmatch(approved.get("policy_sha256", ""))
            or grant.get("grant_id") != profile["grant_id"]
            or grant.get("uid") != profile["consumer_uid"]):
        _deny()
    return aid, {"credential_id": approved["credential_id"],
                 "policy_sha256": approved["policy_sha256"]}



def _authority_key(profile):
    """Credential Authority is NOT the assignment signer or TLS CA."""
    try:
        pin = json.loads(_root_regular(_AUTHORITY_PIN, max_bytes=4096),
                         object_pairs_hook=_pairs)
        if (type(pin) is not dict or set(pin) != {
                "schema", "registry_id", "authority_public_key", "authority_key_id"}
                or pin["schema"] != "zog-credential-authority-pin-v1"
                or pin["registry_id"] != profile["registry_id"]):
            _deny()
        key = signatures.public_key(pin["authority_public_key"])
        if signatures.fingerprint(key) != pin["authority_key_id"]:
            _deny()
        return key
    except (ValueError, KeyError, TypeError, UnicodeError):
        _deny()


def _signed_authorization_path(project):
    key = hashlib.sha256(str(project.path).encode()).hexdigest()
    return credentials.AUTH_ROOT / (key + ".credential-authorization.json")


def _authorization(project, profile, authority_key, *, now=None):
    """Verify independently signed *current* source authority, never a local hash."""
    try:
        envelope = json.loads(_root_regular(
            _signed_authorization_path(project), max_bytes=8192),
            object_pairs_hook=_pairs)
        expected = {
            "host_id": profile["host_id"],
            "host_fingerprint": profile["host_fingerprint"],
            "installation_id": profile["installation_id"],
            "state_volume_id": profile["state_volume_id"],
            "registry_id": profile["registry_id"],
            "consumer": CONSUMER, "purpose": PURPOSE,
            "credential_id": profile["delivery_credential_id"],
        }
        auth = cd.verify_authorization(
            envelope, authority_key, expected_issuer=profile["https_origin"],
            expected_binding=expected, now=now)
        if (auth["authorization_id"] != profile["credential_authorization_id"]
                or auth["revision"] != profile["credential_authorization_revision"]
                or auth["credential_revision"] != profile["credential_revision"]
                or auth["status"] != "approved"):
            _deny()
        return auth
    except (cd.CredentialProtocolError, TypeError, ValueError, KeyError,
            UnicodeError, OSError):
        _deny()


def _state_paths(project):
    base = credentials.AUTH_ROOT / "https-receipts"
    digest = hashlib.sha256(str(project.path).encode()).hexdigest()
    return base, digest + ".credential-ledger.json", digest + ".operation.json"


def _raw_state(project):
    """Local ledger never contains delivery secrets; rollback is rejected."""
    directory, name, _ = _state_paths(project)
    credentials._check_root_directory(directory)
    path = directory / name
    try:
        if path.is_symlink():
            _deny()
        if path.exists():
            raw = json.loads(_root_regular(path, max_bytes=65536),
                             object_pairs_hook=_pairs)
            return cd.validate_ledger(raw)
        return None
    except (ValueError, KeyError, OSError, TypeError, cd.CredentialProtocolError):
        _deny()


def _load_state(project, authorization):
    raw = _raw_state(project)
    return cd.advance_authorization(raw, authorization) if raw is not None else cd.new_ledger(authorization)


def _persist_state(project, state):
    directory, name, _ = _state_paths(project)
    try:
        cd.validate_ledger(state)
        credentials._check_root_directory(directory)
        credentials._atomic_json(directory, name, state)
    except (OSError, ValueError, TypeError):
        _deny()


def _operation(project):
    directory, _, name = _state_paths(project)
    path = directory / name
    try:
        if path.is_symlink():
            _deny()
        if not path.exists():
            return None
        record = json.loads(_root_regular(path, max_bytes=131072),
                            object_pairs_hook=_pairs)
        if (type(record) is not dict or set(record) not in (
                {"request", "delivery_metadata", "phase"},
                {"request", "delivery_metadata", "phase", "schema",
                 "profile_sha256", "authorization_sha256", "before_sha256",
                 "ledger", "ack_payload", "send_payload", "acknowledged"})
                or record["phase"] not in {
                    "pending", "delivered", "installed", "cancelled"}
                or type(record["request"]) is not dict):
            _deny()
        cd.binding(record["request"])
        if "schema" in record:
            _validate_operation(record)
        return record
    except (OSError, ValueError, TypeError, KeyError, cd.CredentialProtocolError):
        _deny()


def _save_operation(project, request, metadata, phase):
    directory, _, name = _state_paths(project)
    if phase not in ("pending", "delivered", "installed", "cancelled"):
        _deny()
    if metadata is not None and (type(metadata) is not dict
            or "secret" in metadata):
        _deny()
    try:
        credentials._check_root_directory(directory)
        credentials._atomic_json(directory, name, {
            "request": request, "delivery_metadata": metadata, "phase": phase,
        })
    except (OSError, ValueError, TypeError):
        _deny()


def _new_request(authorization, state, *, now=None):
    now = int(time.time()) if now is None else int(now)
    previous = next((r for r in reversed(state["requests"])
                     if r["status"] == "installed"), None)
    action = "renew" if previous is not None else "deliver"
    return {
        "schema": cd.REQUEST_SCHEMA,
        **cd.binding(authorization),
        "credential_revision": authorization["credential_revision"],
        "authorization_id": authorization["authorization_id"],
        "authorization_revision": authorization["revision"],
        "request_id": str(uuid.uuid4()),
        "action": action,
        "previous_delivery_id": (
            previous["delivery_id"] if previous is not None else None),
        "created_at": now,
        "expires_at": now + 60,
    }


def _delivery(raw, request, authorization, authority_key, *, now=None):
    """Parse canonical signed envelope before any secret decoding."""
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= cd.MAX_BODY:
            _deny()
        envelope = json.loads(raw, object_pairs_hook=_pairs)
        if canonical(envelope) != raw:
            _deny()
        delivery = cd.verify_delivery(
            envelope, authority_key, request, authorization, now=now)
        # Source-private decoded bytes must never enter logging or audit.
        token = cd.secret_bytes(delivery)
        if not credentials._TOKEN.fullmatch(token):
            _deny()
        metadata = {k: v for k, v in delivery.items() if k != "secret"}
        return token, metadata
    except (ValueError, UnicodeError, TypeError, KeyError, OverflowError,
            cd.CredentialProtocolError):
        _deny()


def _post(profile, prepared, *, expected_status, transport=None):
    """Exact HTTPS URL and status; no redirects/proxies, no JSON errors."""
    import requests
    expected_path = (
        PATH if expected_status == 200 else
        RECEIPT_PATH if prepared.url.endswith(RECEIPT_PATH) else CANCEL_PATH
    )
    if (prepared.method != "POST"
            or prepared.url != profile["https_origin"] + expected_path
            or expected_status not in (200, 204)):
        _deny()
    if transport is not None:
        # Synthetic transport only; production availability remains gated.
        response = transport(prepared, profile, expected_status=expected_status)
        if type(response) is not bytes:
            _deny()
        return response
    session = requests.Session()
    session.trust_env = False
    try:
        response = session.send(prepared, timeout=(5, 10),
                                allow_redirects=False, verify=str(_TLS_CA),
                                stream=True)
        try:
            if (response.status_code != expected_status
                    or (expected_status == 200 and
                        response.headers.get("Content-Type", "").split(";")[0]
                        != "application/json")
                    or response.headers.get("Content-Encoding", "identity")
                       != "identity"):
                _deny()
            limit = cd.MAX_BODY if expected_status == 200 else 0
            length = response.headers.get("Content-Length")
            if length is not None and (
                    not length.isdecimal() or int(length) > limit):
                _deny()
            data = response.raw.read(limit + 1, decode_content=False)
            if len(data) > limit or response.raw.read(1, decode_content=False):
                _deny()
            return data
        finally:
            response.close()
    except (requests.RequestException, ValueError, OSError):
        _deny()
    finally:
        session.close()


def _identity(private_identity, profile):
    try:
        if signatures.fingerprint(private_identity.public_key()) != (
                profile["host_fingerprint"]):
            _deny()
    except (AttributeError, TypeError, ValueError):
        _deny()


def _current(project, profile, authority_key, authorization):
    """Fresh live local authority, issuer grant, owner and signer check."""
    latest = _profile(project)
    if latest != {key: value for key, value in profile.items()
                  if key not in ("credential_id", "policy_sha256")}:
        _deny()
    local_id, selected = _approval(project, latest)
    if (local_id != profile["authorization_id"]
            or selected["credential_id"] != profile["credential_id"]
            or selected["policy_sha256"] != profile["policy_sha256"]):
        _deny()
    key = _authority_key(profile)
    if signatures.fingerprint(key) != signatures.fingerprint(authority_key):
        _deny()
    current = _authorization(project, profile, key)
    if current != authorization:
        _deny()


def _native(admission):
    if not LIVE_NETWORK_ACTIVATION:
        _deny()
    if (type(admission) is not dict
            or admission.get("status") != "protected-source-preflight-only"
            or admission.get("native_https_accepted") is not True
            or admission.get("owner", {}).get("status") != "retained"):
        _deny()


_DELIVERY_PUBLIC_FIELDS = ["authorization_id","authorization_revision","consumer","credential_id","credential_revision","delivery_id","expires_at","issued_at","purpose","request_id","schema","secret_format"]
_OPERATION_SCHEMA = "zog-issuer-https-recovery-v1"


def _digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def _validate_operation(record):
    request, metadata = record["request"], record["delivery_metadata"]
    phase, payload = record["phase"], record["ack_payload"]
    if (record["schema"] != _OPERATION_SCHEMA
            or type(record["acknowledged"]) is not bool
            or any(type(record[k]) is not str or not _HEX.fullmatch(record[k])
                   for k in ("profile_sha256", "authorization_sha256", "before_sha256"))):
        _deny()
    ledger = cd.validate_ledger(record["ledger"])
    if (not ledger["requests"] or cd.binding(ledger) != cd.binding(request)
            or ledger["authorization_id"] != request["authorization_id"]
            or ledger["authorization_revision"] != request["authorization_revision"]
            or ledger["credential_revision"] != request["credential_revision"]):
        _deny()
    row = ledger["requests"][-1]
    if any(row[k] != request[k] for k in (
            "request_id", "action", "credential_revision", "authorization_revision",
            "previous_delivery_id")):
        _deny()
    if metadata is not None:
        # Exact nonsecret delivery schema. Never persist a secret or arbitrary
        # extension from a protected response.
        if (type(metadata) is not dict or "secret" in metadata
                or set(metadata) != set(_DELIVERY_PUBLIC_FIELDS)
                or metadata["schema"] != cd.DELIVERY_SCHEMA
                or metadata["secret_format"] != "base64"
                or any(metadata[k] != request[k] for k in (
                    "request_id", "authorization_id", "authorization_revision",
                    "credential_id", "consumer", "purpose", "credential_revision"))
                or metadata["delivery_id"] != row["delivery_id"]):
            _deny()
    elif row["delivery_id"] is not None:
        _deny()
    if phase in ("pending", "delivered"):
        if (row["status"] != phase or payload is not None
                or record["send_payload"] is not None or record["acknowledged"]
                or not ledger["rotation_required"]
                or (phase == "delivered") != (metadata is not None)):
            _deny()
    elif phase == "installed":
        cd.validate_receipt(payload, request, metadata)
        if (row["status"] != "installed" or row["receipt_id"] != payload["receipt_id"]
                or record["send_payload"] != payload or ledger["rotation_required"]):
            _deny()
    elif phase == "cancelled":
        # Validate original and most recent wire body at their own creation
        # times; the actual POST is separately checked at current time.
        cd.validate_cancel(payload, request, now=payload["created_at"])
        sent = record["send_payload"]
        cd.validate_cancel(sent, request, now=sent["created_at"])
        if (row["status"] != ("cancelled-after-delivery" if metadata is not None else "cancelled")
                or row["cancel_id"] != payload["cancel_id"] or not ledger["rotation_required"]
                or any(sent[k] != payload[k] for k in payload
                       if k not in ("created_at", "expires_at"))
                or sent["created_at"] < payload["created_at"]):
            _deny()
    else:
        _deny()


def _write_record(project, record):
    _validate_operation(record)
    directory, _, name = _state_paths(project)
    credentials._check_root_directory(directory)
    credentials._atomic_json(directory, name, record)


def _sync(project, profile, authorization):
    """Under provision lock: repair only an exact write-ahead boundary.

    The operation file is the durable intent and contains the complete
    nonsecret next ledger. The old ledger digest must match exactly, or
    the ledger must already equal the next state. No inference from a
    partial/mismatched legacy operation is allowed.
    """
    raw = _raw_state(project)
    op = _operation(project)
    if op is None:
        if raw is not None and raw["requests"]:
            _deny()
    else:
        if op.get("schema") != _OPERATION_SCHEMA:
            _deny()  # old records lack recoverable receipt bodies
        same_authority = (op["profile_sha256"] == _digest(profile)
                          and op["authorization_sha256"] == _digest(authorization))
        if not op["acknowledged"] and not same_authority:
            _deny()
        if raw != op["ledger"]:
            if (not same_authority or _digest(raw) != op["before_sha256"]):
                _deny()
            _persist_state(project, op["ledger"])
            raw = op["ledger"]
    state = (cd.advance_authorization(raw, authorization) if raw is not None
             else cd.new_ledger(authorization))
    return raw, state, op


def _commit(project, profile, authorization, raw, state, request, metadata,
            phase, payload=None):
    record = {
        "schema": _OPERATION_SCHEMA, "request": request,
        "delivery_metadata": metadata, "phase": phase,
        "profile_sha256": _digest(profile),
        "authorization_sha256": _digest(authorization),
        "before_sha256": _digest(raw), "ledger": state,
        "ack_payload": payload, "send_payload": payload, "acknowledged": False,
    }
    # Bound the snapshot before any write; neither file may become unreadable.
    if len(canonical(state)) + 1 > 65536 or len(canonical(record)) + 1 > 131072:
        _deny()
    _write_record(project, record)
    _persist_state(project, state)
    return record


@contextmanager
def _receiver_lock(project):
    # Separate from installer lock: serializes receipt recovery, cancellation
    # and delivery across network and installer boundaries without deadlock.
    directory, _, name = _state_paths(project)
    credentials._check_root_directory(directory)
    fd = os.open(directory / (name + ".lock"),
                 os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        credentials._check_lock_info(os.fstat(fd))
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def _serialized(function):
    @wraps(function)
    def run(project_root, *, private_identity, admission, **kwargs):
        credentials._require_root()
        _native(admission)
        project = Project(Path(project_root))
        if str(project.path) != str(Path(project_root)):
            _deny()
        with _receiver_lock(project):
            try:
                return function(project_root, private_identity=private_identity,
                                admission=admission, **kwargs)
            except (cd.CredentialProtocolError, OSError, ValueError, TypeError, KeyError):
                _deny()
    return run


def _claim(project, profile, authorization):
    """Durable uncertain-delivery barrier: no automatic request retransmit."""
    with credentials._locked(project):
        raw, state, prior = _sync(project, profile, authorization)
        if prior is not None and not prior["acknowledged"]:
            _deny()
        request = _new_request(authorization, state)
        cd.validate_request(request, authorization)
        new_state = cd.admit_request(state, request)
        new_state["rotation_required"] = True
        _commit(project, profile, authorization, raw, new_state, request, None, "pending")
        return request


def _save_delivered(project, profile, authorization, request, metadata):
    with credentials._locked(project):
        raw, state, op = _sync(project, profile, authorization)
        if op is None or op["phase"] != "pending" or op["request"] != request:
            _deny()
        next_state = cd.record_delivery(state, metadata)
        _commit(project, profile, authorization, raw, next_state,
                request, metadata, "delivered")


def _installed(project, profile, authorization, request, metadata, receipt):
    with credentials._locked(project):
        raw, state, op = _sync(project, profile, authorization)
        if (op is None or op["phase"] != "delivered" or op["request"] != request
                or op["delivery_metadata"] != metadata):
            _deny()
        cd.validate_receipt(receipt, request, metadata)
        next_state = cd.record_installation(state, receipt)
        _commit(project, profile, authorization, raw, next_state,
                request, metadata, "installed", receipt)


def _acknowledge(project, binding, key, auth, private_identity, request_id, transport):
    """Resend only retained nonsecret terminal evidence, never the delivery."""
    _current(project, binding, key, auth)
    with credentials._locked(project):
        _, _, op = _sync(project, binding, auth)
        if (op is None or op["request"]["request_id"] != request_id
                or op["phase"] not in ("installed", "cancelled")
                or op["profile_sha256"] != _digest(binding)
                or op["authorization_sha256"] != _digest(auth)):
            _deny()
    if op["phase"] == "installed":
        _assert_installed_bytes(project, binding)
    _current(project, binding, key, auth)
    request, payload = op["request"], op["ack_payload"]
    if not op["acknowledged"]:
        if op["phase"] == "installed":
            prepared = cd.prepare_receipt(binding["https_origin"] + RECEIPT_PATH,
                payload, request, op["delivery_metadata"], private_identity)
        else:
            now = int(time.time())
            payload_to_send = op["send_payload"]
            try:
                cd.validate_cancel(payload_to_send, request, now=now)
            except cd.CredentialProtocolError:
                if now < payload_to_send["expires_at"]:
                    _deny()
                # v1 validates a bounded cancellation window even for an
                # idempotent retry. Only timestamps change; the original
                # canonical cancellation, reason and ID stay retained.
                payload_to_send = dict(payload, created_at=now, expires_at=now + 60)
                op = dict(op, send_payload=payload_to_send)
                with credentials._locked(project):
                    _write_record(project, op)
            prepared = cd.prepare_cancel(binding["https_origin"] + CANCEL_PATH,
                payload_to_send, request, private_identity)
        if _post(binding, prepared, expected_status=204, transport=transport) != b"":
            _deny()
        _current(project, binding, key, auth)
        if op["phase"] == "installed":
            _assert_installed_bytes(project, binding)
        with credentials._locked(project):
            _, _, latest = _sync(project, binding, auth)
            if latest != op:
                _deny()
            _write_record(project, dict(op, acknowledged=True))
    return {"schema": payload["schema"], "status": op["phase"],
            "request_id": request_id,
            **({"credential_revision": request["credential_revision"],
                "delivery_id": payload["delivery_id"],
                "receipt_id": payload["receipt_id"]} if op["phase"] == "installed"
               else {"cancel_id": payload["cancel_id"]})}


def _assert_installed_bytes(project, profile):
    """Read back protected installed result AND approved private issuer target.

    The private-file mode/owner/inode and exact selected execution grant are
    independently checked by issuer_credentials.require_installed; inspecting
    a JSON audit alone would not establish installed-byte durability.
    """
    approval_path, _, _, _ = credentials._paths(project)
    approved, grant = credentials._authorization(project, approval_path)
    if (approved.get("storage_id") != profile["storage_id"]
            or approved.get("grant_id") != profile["grant_id"]
            or grant.get("uid") != profile["consumer_uid"]):
        _deny()
    credentials.require_installed(project.path, {
        "application_name": CONSUMER,
        "selected_program": "renew",  # read-only protected admission check only
        "persistent_storage_id": approved["storage_id"],
        "execution_binding": grant,
    })
    record = credentials.inspect(project.path)
    if (record.get("status") != "installed"
            or record.get("credential_revision") !=
               profile["credential_revision"]):
        _deny()


@_serialized
def receive_and_install(project_root, *, private_identity, admission,
                        transport=None):
    """Explicit root-selected operation, not a controller RPC or a retry loop.

    Local signed authorization and all durable request history must preexist;
    newly prepared canonical requests cannot bypass issuer grant/state checks.
    """
    credentials._require_root()
    project = Project(Path(project_root))
    if str(project.path) != str(Path(project_root)):
        _deny()
    _native(admission)
    profile = _profile(project)
    identifier, selected = _approval(project, profile)
    binding = {**profile, **selected}
    key = _authority_key(profile)
    auth = _authorization(project, profile, key)
    _identity(private_identity, profile)
    _current(project, binding, key, auth)
    request = _claim(project, binding, auth)
    try:
        signed = cd.prepare_request(
            profile["https_origin"] + PATH, request, auth, private_identity)
        raw = _post(profile, signed, expected_status=200, transport=transport)
        token, metadata = _delivery(raw, request, auth, key)
        _save_delivered(project, binding, auth, request, metadata)
        _current(project, binding, key, auth)
        reader, writer = os.pipe()
        try:
            try:
                remaining = memoryview(token)
                while remaining:
                    n = os.write(writer, remaining)
                    if n <= 0:
                        _deny()
                    remaining = remaining[n:]
            finally:
                os.close(writer)
            installed = credentials.install_from_fd(
                project.path, reader, expected_authorization_id=identifier)
        finally:
            os.close(reader)
        if (type(installed) is not dict or installed.get("status") != "installed"
                or installed.get("replayed") is not False
                or installed.get("credential_revision") !=
                   profile["credential_revision"]):
            _deny()
        # Independently re-open the actual private 0600 target and compare
        # the current approved storage/grant. No issuer process is launched.
        _assert_installed_bytes(project, binding)
        _current(project, binding, key, auth)
        moment = int(time.time())
        receipt = {
            "schema": cd.RECEIPT_SCHEMA,
            **cd.binding(request),
            **{name: request[name] for name in (
                "credential_revision", "authorization_id",
                "authorization_revision", "request_id")},
            "delivery_id": metadata["delivery_id"],
            "receipt_id": str(uuid.uuid4()),
            "outcome": "installed",
            "installed_at": moment,
        }
        _installed(project, binding, auth, request, metadata, receipt)
        return _acknowledge(project, binding, key, auth, private_identity,
                            request["request_id"], transport)
    except CredentialReceiptDenied:
        raise
    except (cd.CredentialProtocolError, OSError, ValueError, TypeError,
            KeyError):
        _deny()


@_serialized
def cancel_pending(project_root, *, private_identity, admission,
                   transport=None):
    """Explicit owner-selected cancellation, never automatic retry/recovery.

    Pending network delivery is uncertain: mark rotation_required before
    sending cancellation even if the local request lacks a response.
    """
    credentials._require_root()
    project = Project(Path(project_root))
    if str(project.path) != str(Path(project_root)):
        _deny()
    _native(admission)
    profile = _profile(project)
    identifier, selected = _approval(project, profile)
    binding = {**profile, **selected}
    key = _authority_key(profile)
    auth = _authorization(project, profile, key)
    _identity(private_identity, profile)
    _current(project, binding, key, auth)
    with credentials._locked(project):
        raw, state, operation = _sync(project, binding, auth)
        if operation is None or operation["phase"] not in ("pending", "delivered"):
            _deny()
        request = operation["request"]
        try:
            if (request["authorization_id"] != auth["authorization_id"]
                    or request["authorization_revision"] != auth["revision"]
                    or cd.binding(request) != cd.binding(auth)
                    or request["credential_revision"] != auth["credential_revision"]):
                _deny()
            now = int(time.time())
            cancel = {
                "schema": cd.CANCEL_SCHEMA,
                **cd.binding(request),
                **{name: request[name] for name in (
                    "credential_revision", "authorization_id",
                    "authorization_revision", "request_id")},
                "cancel_id": str(uuid.uuid4()),
                "reason": "operator-request",
                "created_at": now, "expires_at": now + 60,
            }
            next_state = cd.record_cancel(state, cancel)
            next_state["rotation_required"] = True
            cd.validate_cancel(cancel, request)
            _commit(project, binding, auth, raw, next_state, request,
                    operation["delivery_metadata"], "cancelled", cancel)
        except (cd.CredentialProtocolError, TypeError, ValueError):
            _deny()
    return _acknowledge(project, binding, key, auth, private_identity,
                        request["request_id"], transport)


@_serialized
def recover_acknowledgement(project_root, *, request_id, private_identity,
                            admission, transport=None):
    """Explicit same-request acknowledgement recovery; never install again."""
    project = Project(Path(project_root))
    profile = _profile(project)
    _, selected = _approval(project, profile)
    binding = {**profile, **selected}
    key = _authority_key(profile)
    auth = _authorization(project, profile, key)
    _identity(private_identity, profile)
    return _acknowledge(project, binding, key, auth, private_identity,
                        request_id, transport)
