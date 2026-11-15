"""Protected, explicitly selected cross-host issuer Cloudflare credential transport.

The SSH link does not replace the station's local SO_PEERCRED vault reader.
This is a root-owned, separately provisioned *source* implementation; native
sshd forced-command, key lifecycle, host-install authority and mount acceptance
are required before enabling it. No daemon RPC or generic shell entry point.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import socket
import stat
import struct
import subprocess
import time

from zog.box_control.project import Project
from . import issuer_credentials as credentials
from . import issuer_station_transfer as local

SCHEMA = "zog-station-issuer-cloudflare-cross-host-v1"
OPERATION = "read-approved-cloudflare-issuer-token"
CLIENT_SCHEMA = "zog-issuer-cross-host-client-v1"
STATION_SCHEMA = "zog-issuer-cross-host-station-v1"
REQUEST_FIELDS = frozenset(("schema", "operation", "authorization_id", "host_id",
    "installation_id", "assignment_id", "assignment_revision", "receipt_sha256", "nonce"))
_BROKER = Path("/run/zog/issuer-cross-host-broker.sock")
_STATION_BINDING = Path("/etc/zog/issuer-credentials/cross-host-station.json")
_SSH = Path("/usr/bin/ssh")
_UUID = credentials._UUID
_HEX64 = credentials._HEX64
_HEX32 = credentials._HEX32
_HOST = re.compile(r"[a-z0-9][a-z0-9.-]{0,252}\Z")
_USER = re.compile(r"[a-z_][a-z0-9_-]{0,31}\Z")
_SHA = re.compile(r"SHA256:[A-Za-z0-9+/]{43}\Z")

class CrossHostDenied(credentials.IssuerCredentialError):
    """Fixed non-secret denial."""

def _deny():
    raise CrossHostDenied("approved cross-host issuer transfer unavailable") from None

def _pairs(pairs):
    obj = {}
    for name, value in pairs:
        if name in obj:
            _deny()
        obj[name] = value
    return obj

def _read_request(raw):
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= 1024 or not raw.endswith(b"\n"):
        _deny()
    try:
        value = json.loads(raw[:-1].decode("ascii"), object_pairs_hook=_pairs)
        if credentials._canonical(value) + b"\n" != raw:
            _deny()
    except (UnicodeError, ValueError, TypeError, OverflowError):
        _deny()
    if (type(value) is not dict or set(value) != REQUEST_FIELDS
            or value["schema"] != SCHEMA or value["operation"] != OPERATION
            or any(type(value[k]) is not str or not _HEX64.fullmatch(value[k])
                   for k in ("authorization_id", "receipt_sha256"))
            or any(type(value[k]) is not str or not _UUID.fullmatch(value[k])
                   for k in ("host_id", "installation_id", "assignment_id"))
            or type(value["nonce"]) is not str or not _HEX32.fullmatch(value["nonce"])
            or type(value["assignment_revision"]) is not int
            or value["assignment_revision"] <= 0):
        _deny()
    return value

def _root_regular(path, *, mode=0o600, max_bytes=8192):
    """Open only exact root-protected files, no symlink or writable ancestor."""
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        _deny()
    try:
        credentials._check_root_directory(path.parent)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                    or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != mode
                    or info.st_nlink != 1 or info.st_size > max_bytes):
                _deny()
            value = os.read(fd, max_bytes + 1)
            if len(value) > max_bytes or len(value) != info.st_size:
                _deny()
            return value
        finally:
            os.close(fd)
    except (OSError, ValueError):
        _deny()

def _load_json(path):
    try:
        return json.loads(_root_regular(path), object_pairs_hook=_pairs)
    except (ValueError, UnicodeError, TypeError):
        _deny()

def _client_path(project):
    key = hashlib.sha256(str(project.path).encode("utf-8")).hexdigest()
    return credentials.AUTH_ROOT / (key + ".cross-host-client.json")

def _client_binding(project):
    value = _load_json(_client_path(project))
    fields = {"schema", "project", "authorization_id", "host_id",
              "installation_id", "state_volume_id", "host_fingerprint",
              "registry_id", "assignment_id", "assignment_revision",
              "receipt_sha256", "ssh_host", "ssh_port", "ssh_user",
              "ssh_identity", "ssh_known_hosts", "ssh_known_hosts_sha256",
              "owner_authority_sha256", "station_signer_pin_sha256"}
    if (type(value) is not dict or set(value) != fields or value["schema"] != CLIENT_SCHEMA
            or value["project"] != str(project.path)
            or any(type(value[k]) is not str or not _UUID.fullmatch(value[k])
                   for k in ("host_id", "installation_id", "state_volume_id", "assignment_id"))
            or any(type(value[k]) is not str or not _HEX64.fullmatch(value[k])
                   for k in ("authorization_id", "host_fingerprint", "receipt_sha256",
                             "ssh_known_hosts_sha256", "owner_authority_sha256", "station_signer_pin_sha256"))
            or not isinstance(value["registry_id"], str)
            or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", value["registry_id"])
            or type(value["assignment_revision"]) is not int or value["assignment_revision"] < 1
            or type(value["ssh_host"]) is not str
            or not _HOST.fullmatch(value["ssh_host"])
            or value["ssh_host"].startswith("-") or ".." in value["ssh_host"]
            or type(value["ssh_user"]) is not str or not _USER.fullmatch(value["ssh_user"])
            or type(value["ssh_port"]) is not int or not 1 <= value["ssh_port"] <= 65535):
        _deny()
    # Pin the current Host's independently established authority and signer.
    owner = _root_regular("/state/host-install/certificate-owner-authority/authority.json")
    signer = _root_regular("/etc/zog/host-install/certificate-assignment-authority.json", mode=0o444)
    if (hashlib.sha256(owner).hexdigest() != value["owner_authority_sha256"]
            or hashlib.sha256(signer).hexdigest() != value["station_signer_pin_sha256"]):
        _deny()
    for key in ("ssh_identity", "ssh_known_hosts"):
        candidate = value[key]
        if type(candidate) is not str or not candidate.startswith("/etc/zog/"):
            _deny()
        raw = _root_regular(candidate)
        if key == "ssh_known_hosts":
            if hashlib.sha256(raw).hexdigest() != value["ssh_known_hosts_sha256"]:
                _deny()
            # Exactly one host and one ed25519 key; reject fallback CAs/keys.
            name = value["ssh_host"] if value["ssh_port"] == 22 else (
                "[" + value["ssh_host"] + "]:" + str(value["ssh_port"]))
            try:
                entries = raw.decode("ascii").splitlines()
                if len(entries) != 1:
                    _deny()
                host, kind, encoded = entries[0].split()
                raw_key = base64.b64decode(encoded, validate=True)
                if (host != name or kind != "ssh-ed25519"
                        or len(raw_key) != 51
                        or raw_key[:15] != b"\x00\x00\x00\x0bssh-ed25519"
                        or raw_key[15:19] != b"\x00\x00\x00\x20"):
                    _deny()
            except (UnicodeError, ValueError, binascii.Error):
                _deny()
    return value

def _client_approved(project, binding):
    # Recheck the *local* root-owned authorization/grant and projection both
    # before the outbound SSH call and after token retrieval.
    aid, _peer = local._checked_current(project)
    _projection_path, _ = credentials._projection_paths(project)
    approval = local._private_file(_projection_path, gid=_peer["reader_gid"], mode=0o440)
    if (approval.get("origin") != "managed"
            or approval.get("host_id") != binding["host_id"]
            or approval.get("installation_id") != binding["installation_id"]):
        _deny()
    approved = approval["authorization"]
    if (aid != binding["authorization_id"]
            or approved["assignment_id"] != binding["assignment_id"]
            or approved["assignment_revision"] != binding["assignment_revision"]
            or approved["receipt_sha256"] != binding["receipt_sha256"]):
        _deny()
    return aid

def _request(binding):
    fields = {key: binding[key] for key in ("authorization_id", "host_id",
        "installation_id", "assignment_id", "assignment_revision", "receipt_sha256")}
    fields.update(schema=SCHEMA, operation=OPERATION, nonce=secrets.token_hex(16))
    result = credentials._canonical(fields) + b"\n"
    if len(result) > 1024:
        _deny()
    return result

def _ssh_token(binding, request):
    # ssh binary, configuration, host key database and private identity are
    # fixed and separately root-owned; no caller remote command/host/path.
    info = _SSH.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022):
        _deny()
    args = [str(_SSH), "-F", "/dev/null", "-T", "-p", str(binding["ssh_port"]),
        "-i", binding["ssh_identity"],
        "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
        "-o", "IdentityAgent=none", "-o", "StrictHostKeyChecking=yes",
        "-o", "HostKeyAlgorithms=ssh-ed25519",
        "-o", "UserKnownHostsFile=" + binding["ssh_known_hosts"],
        "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", "UpdateHostKeys=no", "-o", "ProxyCommand=none",
        "-o", "ProxyJump=none", "-o", "ClearAllForwardings=yes",
        "-o", "ControlMaster=no", "-o", "PermitLocalCommand=no",
        "-o", "PasswordAuthentication=no",
        "-o", "KbdInteractiveAuthentication=no",
        "-o", "HostbasedAuthentication=no", "-o", "ConnectTimeout=5",
        "-o", "LogLevel=QUIET",
        binding["ssh_user"] + "@" + binding["ssh_host"], "issuer-cloudflare-read-v1"]
    proc = None
    output = bytearray()
    try:
        proc = subprocess.Popen(args, stdin=subprocess.PIPE,
             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, close_fds=True,
             env={"PATH": "/usr/bin:/bin", "HOME": "/var/empty", "LANG": "C"})
        assert proc.stdin is not None and proc.stdout is not None
        proc.stdin.write(request)
        proc.stdin.close()
        deadline = time.monotonic() + 15.0
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    _deny()
                part = os.read(proc.stdout.fileno(), 4097 - len(output))
                if not part:
                    break
                output.extend(part)
                if len(output) > 4096:
                    _deny()
        if proc.wait(timeout=max(0.001, deadline - time.monotonic())) != 0:
            _deny()
        token = bytes(output)
        if not credentials._TOKEN.fullmatch(token):
            _deny()
        return token
    except (OSError, ValueError, subprocess.SubprocessError, AssertionError):
        _deny()
    finally:
        if proc is not None:
            if proc.poll() is None:
                proc.kill()
            proc.wait()

def transfer_and_install(project_root):
    credentials._require_root()
    project = Project(Path(project_root))
    if str(project.path) != str(Path(project_root)):
        _deny()
    initial = _client_binding(project)
    auth = _client_approved(project, initial)
    token = _ssh_token(initial, _request(initial))
    # Always re-read and verify the original root grant/assignment, key pin,
    # station endpoint and issuer storage identity *before* committing.
    if _client_binding(project) != initial or _client_approved(project, initial) != auth:
        _deny()
    read_fd, write_fd = os.pipe()
    try:
        try:
            view = memoryview(token)
            while view:
                size = os.write(write_fd, view)
                if size <= 0:
                    _deny()
                view = view[size:]
        finally:
            os.close(write_fd)
        return credentials.install_from_fd(
            project.path, read_fd, expected_authorization_id=auth)
    finally:
        os.close(read_fd)

def _station_binding():
    value = _load_json(_STATION_BINDING)
    fields = {"schema", "peer_uid", "peer_gid", "ssh_key_fingerprint",
        "host_id", "installation_id", "state_volume_id", "host_fingerprint",
        "registry_id", "authorization_id", "assignment_id",
        "assignment_revision", "receipt_sha256", "reader_uid", "reader_gid",
        "projection_path", "nonce_directory"}
    if (type(value) is not dict or set(value) != fields or value["schema"] != STATION_SCHEMA
            or any(type(value[k]) is not int or not 1 <= value[k] < 2**31
                   for k in ("peer_uid", "peer_gid", "reader_uid", "reader_gid"))
            or type(value["ssh_key_fingerprint"]) is not str
            or not _SHA.fullmatch(value["ssh_key_fingerprint"])
            or any(type(value[k]) is not str or not _UUID.fullmatch(value[k])
                   for k in ("host_id", "installation_id", "state_volume_id", "assignment_id"))
            or any(type(value[k]) is not str or not _HEX64.fullmatch(value[k])
                   for k in ("host_fingerprint", "authorization_id", "receipt_sha256"))
            or type(value["registry_id"]) is not str
            or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", value["registry_id"])
            or type(value["assignment_revision"]) is not int
            or value["assignment_revision"] < 1
            or type(value["projection_path"]) is not str
            or not value["projection_path"].startswith("/etc/zog/")
            or type(value["nonce_directory"]) is not str
            or not value["nonce_directory"].startswith("/var/lib/zog-issuer-bridge/")):
        _deny()
    return value

def _station_approved(binding, request):
    # SSH's distinct authorized key is mapped by reviewed sshd policy to the
    # dedicated UID below. Neither payload nor environment can select it.
    for key in ("authorization_id", "host_id", "installation_id",
                "assignment_id", "assignment_revision", "receipt_sha256"):
        if binding[key] != request[key]:
            _deny()
    projection = local._private_file(Path(binding["projection_path"]),
             gid=binding["reader_gid"], mode=0o440)
    approved = projection.get("authorization")
    if (projection.get("origin") != "managed"
            or projection.get("host_id") != binding["host_id"]
            or projection.get("installation_id") != binding["installation_id"]
            or type(approved) is not dict or set(approved) != credentials._FIELDS
            or credentials._authorization_id(approved) != binding["authorization_id"]
            or approved["assignment_id"] != binding["assignment_id"]
            or approved["assignment_revision"] != binding["assignment_revision"]
            or approved["receipt_sha256"] != binding["receipt_sha256"]):
        _deny()
    return {"schema": local._PEER_SCHEMA, "authorization_id": binding["authorization_id"],
        "reader_uid": binding["reader_uid"], "reader_gid": binding["reader_gid"],
        "socket_path": str(local._SOCKET)}

def _consume_nonce(binding, request):
    directory = Path(binding["nonce_directory"])
    credentials._check_root_directory(directory)
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        if len(os.listdir(fd)) >= 10000:
            _deny()   # No automatic pruning; never reopen a consumed nonce.
        name = hashlib.sha256((str(binding["peer_uid"]) + ":" +
            request["authorization_id"] + ":" + request["nonce"]).encode("ascii")).hexdigest() + ".nonce"
        record = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
        try:
            info = os.fstat(record)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                _deny()
            os.write(record, b"used\n")
            os.fsync(record)
        finally:
            os.close(record)
        os.fsync(fd)
    except (OSError, ValueError):
        _deny()
    finally:
        os.close(fd)

def _serve_broker_connection(connection, binding):
    # Caller is the sshd key-bound forced-command bridge, not remote user
    # payload. Zero-byte response on every failure.
    try:
        if not hasattr(socket, "SO_PEERCRED"):
            _deny()
        pid, uid, gid = struct.unpack("3i",
            connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if pid <= 0 or uid != binding["peer_uid"] or gid != binding["peer_gid"]:
            _deny()
        connection.settimeout(5)
        raw = bytearray()
        while len(raw) <= 1024:
            block = connection.recv(1025 - len(raw))
            if not block:
                break
            raw.extend(block)
        req = _read_request(bytes(raw))
        peer = _station_approved(binding, req)
        _consume_nonce(binding, req)  # Durable barrier *before* vault decrypt.
        token = local._read_station_socket(binding["authorization_id"], peer)
        if _station_binding() != binding or _station_approved(binding, req) != peer:
            _deny()
        connection.sendall(token)
        return True
    except Exception:
        return False

def serve_once(listener):
    binding = _station_binding()
    connection, _ = listener.accept()
    with connection:
        return _serve_broker_connection(connection, binding)

def _verify_broker_listener(listener, path, *, owner_uid, bridge_gid):
    """Independently verify kernel listener and protected pathname metadata.

    Linux socketfs fstat(fd) and filesystem lstat(path) refer to different
    objects. Their dev/ino values must NOT be compared. The fixed, root-owned
    parent is validated separately by the privileged caller.
    """
    try:
        if (listener.family != socket.AF_UNIX
                or listener.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
                or listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1
                or listener.getsockname() != str(path)):
            _deny()
        descriptor = os.fstat(listener.fileno())
        pathname = path.lstat()
        if (not stat.S_ISSOCK(descriptor.st_mode)
                or not stat.S_ISSOCK(pathname.st_mode)
                or pathname.st_uid != owner_uid or pathname.st_gid != bridge_gid
                or stat.S_IMODE(pathname.st_mode) != 0o660):
            _deny()
    except (OSError, ValueError, TypeError):
        _deny()
    return listener


def broker_main():
    # Fixed systemd socket fd3; sshd must not execute this privileged broker.
    credentials._require_root()
    binding = _station_binding()
    listener = socket.socket(fileno=3)
    credentials._check_root_directory(_BROKER.parent)
    _verify_broker_listener(listener, _BROKER, owner_uid=0,
                            bridge_gid=binding["peer_gid"])
    while True:
        serve_once(listener)

def bridge_main():
    # sshd forced command executes under the *dedicated non-root* bridge UID.
    # Forbid any caller-selected remote command, environment or file target.
    if os.environ.get("SSH_ORIGINAL_COMMAND") != "issuer-cloudflare-read-v1":
        _deny()
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        credentials._check_root_directory(_BROKER.parent)
        location = _BROKER.lstat()
        if (not stat.S_ISSOCK(location.st_mode) or location.st_uid != 0
                or location.st_gid != os.getgid()
                or stat.S_IMODE(location.st_mode) != 0o660):
            _deny()
        connection.settimeout(5)
        connection.connect(str(_BROKER))
        if not hasattr(socket, "SO_PEERCRED"):
            _deny()
        pid, uid, _gid = struct.unpack("3i",
            connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if pid <= 0 or uid != 0:
            _deny()
        wire = bytearray()
        while len(wire) <= 1024:
            import select
            if not select.select([0], [], [], 5)[0]:
                _deny()
            chunk = os.read(0, 1025 - len(wire))
            if not chunk:
                break
            wire.extend(chunk)
        _read_request(bytes(wire))
        connection.sendall(wire)
        connection.shutdown(socket.SHUT_WR)
        payload = bytearray()
        while len(payload) <= 4096:
            part = connection.recv(4097 - len(payload))
            if not part:
                break
            payload.extend(part)
        if not credentials._TOKEN.fullmatch(bytes(payload)):
            _deny()
        rest = memoryview(payload)
        while rest:
            sent = os.write(1, rest)
            if sent <= 0:
                _deny()
            rest = rest[sent:]
    finally:
        connection.close()

def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("client-transfer", "station-broker", "ssh-bridge"))
    parser.add_argument("--project")
    args = parser.parse_args(argv)
    if args.action == "client-transfer" and args.project:
        result = transfer_and_install(args.project)
        print(json.dumps(result, sort_keys=True))
    elif args.action == "station-broker" and args.project is None:
        broker_main()
    elif args.action == "ssh-bridge" and args.project is None:
        bridge_main()
    else:
        _deny()

if __name__ == "__main__":
    main()
