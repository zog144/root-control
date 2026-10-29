"""Fail-closed, purpose-scoped HTTPS credential receiver for the enrolled Host.

Opt-in root operation only. No daemon RPC, SSH command, browser access, or
automatic retry. The station producer must implement the exact signed v1
envelope before live delivery can be authorized.
"""
from __future__ import annotations

import base64
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


def _load_state(project, authorization):
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
            return cd.advance_authorization(raw, authorization)
        return cd.new_ledger(authorization)
    except (ValueError, KeyError, OSError, TypeError, cd.CredentialProtocolError):
        _deny()


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
        record = json.loads(_root_regular(path, max_bytes=8192),
                            object_pairs_hook=_pairs)
        if (type(record) is not dict or set(record) !=
                {"request", "delivery_metadata", "phase"}
                or record["phase"] not in {
                    "pending", "delivered", "installed", "cancelled"}
                or type(record["request"]) is not dict):
            _deny()
        cd.binding(record["request"])
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


def _claim(project, profile, authorization):
    """Durable uncertain-delivery barrier: no automatic request retransmit."""
    with credentials._locked(project):
        state = _load_state(project, authorization)
        prior = _operation(project)
        if prior is not None and prior["phase"] not in ("installed", "cancelled"):
            _deny()
        request = _new_request(authorization, state)
        try:
            cd.validate_request(request, authorization)
            new_state = cd.admit_request(state, request)
            # The network may deliver a secret and fail before we see it.
            # Conservative rotation hold even on pending unknown delivery.
            new_state["rotation_required"] = True
            _save_operation(project, request, None, "pending")
            _persist_state(project, new_state)
            return request
        except (ValueError, TypeError, cd.CredentialProtocolError):
            _deny()


def _save_delivered(project, authorization, request, metadata):
    with credentials._locked(project):
        state = _load_state(project, authorization)
        try:
            next_state = cd.record_delivery(state, metadata)
            _persist_state(project, next_state)
            _save_operation(project, request, metadata, "delivered")
        except (ValueError, TypeError, cd.CredentialProtocolError):
            _deny()


def _installed(project, authorization, request, metadata, receipt):
    with credentials._locked(project):
        state = _load_state(project, authorization)
        try:
            cd.validate_receipt(receipt, request, metadata)
            next_state = cd.record_installation(state, receipt)
            _persist_state(project, next_state)
            _save_operation(project, request, metadata, "installed")
        except (ValueError, TypeError, cd.CredentialProtocolError):
            _deny()


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
        _save_delivered(project, auth, request, metadata)
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
        signed_receipt = cd.prepare_receipt(
            profile["https_origin"] + RECEIPT_PATH,
            receipt, request, metadata, private_identity)
        _installed(project, auth, request, metadata, receipt)
        if _post(profile, signed_receipt, expected_status=204,
                 transport=transport) != b"":
            _deny()
        return {"schema": cd.RECEIPT_SCHEMA, "status": "installed",
                "credential_revision": request["credential_revision"],
                "request_id": request["request_id"],
                "delivery_id": metadata["delivery_id"],
                "receipt_id": receipt["receipt_id"]}
    except CredentialReceiptDenied:
        raise
    except (cd.CredentialProtocolError, OSError, ValueError, TypeError,
            KeyError):
        _deny()


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
        state = _load_state(project, auth)
        operation = _operation(project)
        if operation is None or operation["phase"] not in ("pending", "delivered"):
            _deny()
        request = operation["request"]
        try:
            if (request["authorization_id"] != auth["authorization_id"]
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
            _persist_state(project, next_state)
            _save_operation(project, request, operation["delivery_metadata"],
                            "cancelled")
        except (cd.CredentialProtocolError, TypeError, ValueError):
            _deny()
    signed = cd.prepare_cancel(
        profile["https_origin"] + CANCEL_PATH,
        cancel, request, private_identity)
    if _post(profile, signed, expected_status=204,
             transport=transport) != b"":
        _deny()
    return {"schema": cd.CANCEL_SCHEMA, "status": "cancelled",
            "request_id": request["request_id"]}
