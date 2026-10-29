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
import ssl
import stat
import time
from urllib.parse import urlsplit

from zog.box_control.project import Project
from . import issuer_credentials as credentials
from . import issuer_station_transfer as local
from . import issuer_cross_host as legacy  # authority checks only; never SSH
from .issuer_cross_host import CrossHostDenied, _deny, _root_regular, _pairs

SCHEMA = "zog-protected-credential-delivery-v1"
PURPOSE = "managed-dns01"
CONSUMER = "certify-manage"
PROFILE_SCHEMA = "zog-issuer-https-credential-receiver-v1"
RESPONSE_SCHEMA = "zog-protected-credential-response-v1"
PATH = "/api/hosts/credential-delivery/v1/receive/"
_SIGNING_DOMAIN = b"zog-protected-credential-delivery-response-v1\n"
_MAX_REQUEST = 2048
_MAX_RESPONSE = 8192
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_UUID = credentials._UUID
_RESPONSE_FIELDS = frozenset({
    "schema", "purpose", "consumer", "request_sha256", "nonce", "issued_at",
    "expires_at", "host_id", "installation_id", "state_volume_id", "registry_id",
    "host_fingerprint", "authorization_id", "assignment_id",
    "assignment_revision", "receipt_sha256", "credential_id",
    "credential_revision", "storage_id", "grant_id", "policy_sha256",
    "token_base64", "signature"
})


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _profile_path(project):
    return credentials.AUTH_ROOT / (
        hashlib.sha256(str(project.path).encode()).hexdigest() + ".https-receiver.json")


def _profile(project):
    try:
        value = json.loads(_root_regular(_profile_path(project)), object_pairs_hook=_pairs)
        fields = {"schema", "project", "https_origin", "tls_ca_path", "tls_ca_sha256",
            "signer_pin_sha256", "owner_authority_sha256", "host_id",
            "installation_id", "state_volume_id", "host_fingerprint",
            "registry_id", "authorization_id", "assignment_id",
            "assignment_revision", "receipt_sha256", "credential_id",
            "credential_revision", "grant_id", "storage_id", "policy_sha256",
            "consumer_uid"}
        if type(value) is not dict or set(value) != fields or value["schema"] != PROFILE_SCHEMA:
            _deny()
        if value["project"] != str(project.path):
            _deny()
        for name in ("host_id", "installation_id", "state_volume_id",
                     "assignment_id", "credential_id", "grant_id", "storage_id"):
            if type(value[name]) is not str or not _UUID.fullmatch(value[name]):
                _deny()
        for name in ("host_fingerprint", "authorization_id", "receipt_sha256",
                     "policy_sha256", "tls_ca_sha256", "signer_pin_sha256",
                     "owner_authority_sha256"):
            if type(value[name]) is not str or not _HEX.fullmatch(value[name]):
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
                or not value["tls_ca_path"].startswith("/etc/zog/")):
            _deny()
        authority = _root_regular("/state/host-install/certificate-owner-authority/authority.json")
        pin = _root_regular("/etc/zog/host-install/certificate-assignment-authority.json", mode=0o444)
        ca = _root_regular(value["tls_ca_path"], max_bytes=16384)
        if (hashlib.sha256(authority).hexdigest() != value["owner_authority_sha256"]
                or hashlib.sha256(pin).hexdigest() != value["signer_pin_sha256"]
                or hashlib.sha256(ca).hexdigest() != value["tls_ca_sha256"]
                or b"BEGIN CERTIFICATE" not in ca):
            _deny()
        return value
    except (ValueError, TypeError, OSError, UnicodeError):
        _deny()


def _approval(project, profile):
    aid, peer = local._checked_current(project)
    path, _ = credentials._projection_paths(project)
    projection = local._private_file(path, gid=peer["reader_gid"], mode=0o440)
    approved = projection.get("authorization")
    if (projection.get("origin") != "managed"
            or projection.get("host_id") != profile["host_id"]
            or projection.get("installation_id") != profile["installation_id"]
            or not isinstance(approved, dict)
            or aid != profile["authorization_id"]):
        _deny()
    for k in ("assignment_id", "assignment_revision", "receipt_sha256",
              "credential_id", "credential_revision", "grant_id", "storage_id",
              "policy_sha256"):
        if approved.get(k) != profile[k]:
            _deny()
    grant = credentials._authorization(project, credentials._paths(project)[0])[1]
    if grant.get("uid") != profile["consumer_uid"]:
        _deny()
    return aid


def _pin_key(profile):
    from zog.host_identify import signatures
    pin = json.loads(_root_regular(
        "/etc/zog/host-install/certificate-assignment-authority.json",
        mode=0o444), object_pairs_hook=_pairs)
    if (pin.get("registry_id") != profile["registry_id"]
            or type(pin.get("authority_public_key")) is not str):
        _deny()
    key = signatures.public_key(pin["authority_public_key"])
    if signatures.fingerprint(key) != pin.get("authority_key_id"):
        _deny()
    return key


def _request(profile):
    fields = ("host_id", "installation_id", "state_volume_id", "host_fingerprint",
              "registry_id", "authorization_id", "assignment_id",
              "assignment_revision", "receipt_sha256", "credential_id",
              "credential_revision", "storage_id", "grant_id", "policy_sha256")
    request = {name: profile[name] for name in fields}
    request.update(schema=SCHEMA, purpose=PURPOSE, consumer=CONSUMER,
                   consumer_uid=profile["consumer_uid"],
                   nonce=secrets.token_hex(16), issued_at=int(time.time()))
    raw = canonical(request)
    if len(raw) > _MAX_REQUEST:
        _deny()
    return request, raw


def _signed_response(raw, *, request, request_bytes, profile, authority_key, now=None):
    """Verify the independently pinned Ed25519 station signature before decoding token."""
    from cryptography.exceptions import InvalidSignature
    if type(raw) is not bytes or len(raw) > _MAX_RESPONSE or not raw:
        _deny()
    try:
        response = json.loads(raw, object_pairs_hook=_pairs)
        if type(response) is not dict or set(response) != _RESPONSE_FIELDS:
            _deny()
        if canonical(response) != raw:
            _deny()
        signature = base64.b64decode(response["signature"], validate=True)
        signed = {k: v for k, v in response.items() if k != "signature"}
        authority_key.verify(signature, _SIGNING_DOMAIN + canonical(signed))
        if (signed["schema"] != RESPONSE_SCHEMA or signed["purpose"] != PURPOSE
                or signed["consumer"] != CONSUMER
                or signed["request_sha256"] != hashlib.sha256(request_bytes).hexdigest()
                or signed["nonce"] != request["nonce"]):
            _deny()
        for field in ("host_id", "installation_id", "state_volume_id", "registry_id",
                      "host_fingerprint", "authorization_id", "assignment_id",
                      "assignment_revision", "receipt_sha256", "credential_id",
                      "credential_revision", "storage_id", "grant_id", "policy_sha256"):
            if type(signed[field]) is not type(profile[field]) or signed[field] != profile[field]:
                _deny()
        current = int(time.time()) if now is None else now
        if (type(signed["issued_at"]) is not int or type(signed["expires_at"]) is not int
                or not current - 5 <= signed["issued_at"] <= current + 5
                or not current < signed["expires_at"] <= current + 60):
            _deny()
        encoded = signed["token_base64"]
        if type(encoded) is not str or len(encoded) > 5500:
            _deny()
        token = base64.b64decode(encoded, validate=True)
        if base64.b64encode(token).decode() != encoded or not credentials._TOKEN.fullmatch(token):
            _deny()
        return token
    except (InvalidSignature, ValueError, UnicodeError, TypeError, KeyError, OverflowError):
        _deny()


def _https_post(profile, request, private_identity, *, transport=None):
    """RFC 9421 signed Host request, strict TLS origin, never follow redirects/proxy."""
    from zog.host_identify import signatures
    import requests

    url = profile["https_origin"] + PATH
    wire = canonical(request)
    signed = signatures.sign(url, wire, private_identity, profile["host_id"],
                             nonce=secrets.token_urlsafe(24))
    if signatures.fingerprint(private_identity.public_key()) != profile["host_fingerprint"]:
        _deny()
    if transport is not None:
        return transport(signed, profile)
    session = requests.Session()
    session.trust_env = False
    try:
        resp = session.send(signed, timeout=(5, 10), allow_redirects=False,
                            verify=profile["tls_ca_path"], stream=True)
        try:
            if (resp.status_code != 200
                    or resp.headers.get("Content-Type", "").split(";")[0] != "application/json"
                    or resp.headers.get("Content-Length") and
                    int(resp.headers["Content-Length"]) > _MAX_RESPONSE):
                _deny()
            data = resp.raw.read(_MAX_RESPONSE + 1, decode_content=False)
            if len(data) > _MAX_RESPONSE or resp.raw.read(1, decode_content=False):
                _deny()
            return data
        finally:
            resp.close()
    except (requests.RequestException, ValueError, OSError):
        _deny()
    finally:
        session.close()


def _consume_request(project, nonce, *, profile):
    """Durable consumed-request record; never automatically retry a sent request."""
    root = credentials.AUTH_ROOT / "https-receipts"
    credentials._check_root_directory(root)
    name = hashlib.sha256((str(project.path) + ":" + profile["authorization_id"]
                           + ":" + nonce).encode()).hexdigest() + ".used"
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fd = os.open(name, os.O_WRONLY | os.O_EXCL | os.O_CREAT | os.O_NOFOLLOW, 0o600,
                     dir_fd=directory)
        try:
            os.write(fd, b"consumed\n")
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(directory)
    except (OSError, ValueError):
        _deny()
    finally:
        os.close(directory)


def receive_and_install(project_root, *, private_identity, admission,
                        transport=None):
    """Selected root-owned operation; admission MUST be verified host-install preflight.

    The caller supplies only an independently consumed HostIdentity and read-only
    owner admission, never a remote command, destination, token or URL.
    """
    credentials._require_root()
    project = Project(Path(project_root))
    if str(project.path) != str(Path(project_root)):
        _deny()
    initial = _profile(project)
    if (type(admission) is not dict or admission.get("status") != "protected-source-preflight-only"
            or admission.get("native_https_accepted") is not True
            or admission.get("owner", {}).get("status") != "retained"):
        _deny()
    identifier = _approval(project, initial)
    key = _pin_key(initial)
    request, request_bytes = _request(initial)
    # Persist before any outbound bytes: an interrupted request is not replayed.
    _consume_request(project, request["nonce"], profile=initial)
    raw = _https_post(initial, request, private_identity, transport=transport)
    token = _signed_response(raw, request=request, request_bytes=request_bytes,
                             profile=initial, authority_key=key)
    if (_profile(project) != initial or _approval(project, initial) != identifier
            or _pin_key(initial).public_bytes_raw() != key.public_bytes_raw()):
        _deny()
    reader, writer = os.pipe()
    try:
        try:
            remaining = memoryview(token)
            while remaining:
                count = os.write(writer, remaining)
                if count <= 0:
                    _deny()
                remaining = remaining[count:]
        finally:
            os.close(writer)
        return credentials.install_from_fd(
            project.path, reader, expected_authorization_id=identifier)
    finally:
        os.close(reader)
