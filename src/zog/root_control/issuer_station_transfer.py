"""Root-owner projection and exact station-access vault-reader transfer.

This module has NO root-control daemon RPC. Root's protected preapproved
issuer identity is authoritative. The station broker only supplies token bytes
after independently checking the exact root-owned projection.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import secrets
import select
import socket
import stat
import struct
import time

from zog.box_control.project import Project

from . import issuer_credentials as credentials

_PEER_SCHEMA = "zog-issuer-cloudflare-reader-peer-v1"
_PROJECTION_SCHEMA = "zog-station-issuer-reader-authorization-v1"
_REQUEST_SCHEMA = "zog-station-issuer-cloudflare-read-v1"
_READ_OPERATION = "read-approved-cloudflare-issuer-token"
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
_HEX32 = re.compile(r"[0-9a-f]{32}\Z")
_FIELDS = frozenset({"schema", "authorization", "origin", "installation_id",
                     "host_id", "account_id", "owner_user_id"})
_SOCKET = Path("/run/zog/issuer-cloudflare-reader.sock")


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise credentials.IssuerCredentialError("station projection has duplicate keys")
        result[key] = value
    return result


def _read_projection_fd(fd):
    if type(fd) is not int or fd < 0:
        raise credentials.IssuerCredentialError("nonsecret projection descriptor required")
    deadline = time.monotonic() + 5
    collected = bytearray()
    while len(collected) <= 8192:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise credentials.IssuerCredentialError("station projection transfer did not complete")
        readable, _, _ = select.select([fd], [], [], remaining)
        if not readable:
            raise credentials.IssuerCredentialError("station projection transfer did not complete")
        chunk = os.read(fd, 8193 - len(collected))
        if not chunk:
            break
        collected.extend(chunk)
    value = bytes(collected)
    if not 0 < len(value) <= 8192:
        raise credentials.IssuerCredentialError("station projection size invalid")
    try:
        parsed = json.loads(value, object_pairs_hook=_unique_pairs)
    except (ValueError, TypeError, UnicodeError):
        raise credentials.IssuerCredentialError("station projection JSON invalid") from None
    return parsed


def _validated(projection, approved):
    if (type(projection) is not dict or set(projection) != _FIELDS
            or projection["schema"] != _PROJECTION_SCHEMA
            or type(projection["authorization"]) is not dict
            or projection["authorization"] != approved
            or projection["origin"] not in ("local", "managed")
            or type(projection["installation_id"]) is not str
            or not _UUID.fullmatch(projection["installation_id"])
            or (projection["host_id"] is not None and (
                type(projection["host_id"]) is not str
                or not _UUID.fullmatch(projection["host_id"])))
            or ((projection["origin"] == "local") != (projection["host_id"] is None))
            or type(projection["account_id"]) is not str
            or not _HEX32.fullmatch(projection["account_id"])
            or type(projection["owner_user_id"]) is not int
            or projection["owner_user_id"] <= 0):
        raise credentials.IssuerCredentialError("station projection disagrees with approved issuer")
    # The station reader uses exactly these root-authoritative nested keys.
    if set(projection["authorization"]) != credentials._FIELDS:
        raise credentials.IssuerCredentialError("station projection has extra authorization fields")
    return credentials._authorization_id(approved)


def _private_file(path, *, gid, mode):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_gid != gid
                or stat.S_IMODE(st.st_mode) != mode or st.st_nlink != 1
                or st.st_size > 8192):
            raise credentials.IssuerCredentialError("station projection ownership or DAC changed")
        data = os.read(fd, 8193)
        if len(data) > 8192:
            raise credentials.IssuerCredentialError("station projection too large")
    finally:
        os.close(fd)
    try:
        return json.loads(data, object_pairs_hook=_unique_pairs)
    except (ValueError, TypeError, UnicodeError):
        raise credentials.IssuerCredentialError("station projection file is malformed") from None


def _atomic_private(name, value, *, gid, mode):
    directory = credentials.AUTH_ROOT
    temporary = "." + name + "." + secrets.token_hex(12) + ".pending"
    fd = os.open(directory / temporary,
                 os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600)
    try:
        os.fchown(fd, 0, gid)
        os.fchmod(fd, mode)
        raw = credentials._canonical(value) + b"\n"
        remaining = memoryview(raw)
        while remaining:
            n = os.write(fd, remaining)
            if n <= 0:
                raise OSError("incomplete station projection write")
            remaining = remaining[n:]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(directory / temporary, directory / name)
    credentials._fsync(directory)


def _expected_peer(peer, authorization_id):
    if (type(peer) is not dict or set(peer) != {
            "schema", "authorization_id", "reader_uid", "reader_gid", "socket_path"}
            or peer["schema"] != _PEER_SCHEMA
            or peer["authorization_id"] != authorization_id
            or type(peer["reader_uid"]) is not int
            or not 1 <= peer["reader_uid"] < 2**31
            or type(peer["reader_gid"]) is not int
            or not 1 <= peer["reader_gid"] < 2**31
            or peer["socket_path"] != str(_SOCKET)):
        raise credentials.IssuerCredentialError("pinned station reader identity unavailable")
    return peer


def publish_projection(project_root, projection_fd, *, reader_uid, reader_gid):
    """Root-owned offline provisioning, after separate owner receipt verification.

    Caller passes only a NONSECRET independently approved projection on an FD.
    The protected authorization must already exist and be valid.
    """
    credentials._require_root()
    project = Project(Path(project_root))
    if str(project.path) != str(Path(project_root)):
        raise credentials.IssuerCredentialError("noncanonical credential project")
    if (type(reader_uid) is not int or not 1 <= reader_uid < 2**31
            or type(reader_gid) is not int or not 1 <= reader_gid < 2**31):
        raise credentials.IssuerCredentialError("invalid approved vault reader identity")
    from zog.box_control.locking import ProjectLock
    with ProjectLock(project.lock_file, timeout_seconds=10), credentials._locked(project) as paths:
        approval_path, installed_path, pending_path = paths
        approved, _ = credentials._authorization(project, approval_path)
        if pending_path.exists() or pending_path.is_symlink():
            raise credentials.IssuerCredentialError("incomplete credential installation blocks projection")
        previous = credentials._read_protected(installed_path, missing_ok=True)
        credentials._check_revision(previous, approved)
        parsed = _read_projection_fd(projection_fd)
        authorization_id = _validated(parsed, approved)
        projection_path, peer_path = credentials._projection_paths(project)
        prior_peer = credentials._read_protected(peer_path, missing_ok=True)
        if prior_peer is not None:
            _expected_peer(prior_peer, prior_peer.get("authorization_id"))
            if ((prior_peer["reader_uid"], prior_peer["reader_gid"])
                    != (reader_uid, reader_gid)):
                raise credentials.IssuerCredentialError("station vault reader identity migration not approved")
        current = {
            "schema": _PEER_SCHEMA,
            "authorization_id": authorization_id,
            "reader_uid": reader_uid, "reader_gid": reader_gid,
            "socket_path": str(_SOCKET),
        }
        # Publish root-only peer pin first. If interrupted, a digest mismatch
        # prevents using an old projection with newly approved authority.
        credentials._atomic_json(credentials.AUTH_ROOT, peer_path.name, current)
        _atomic_private(projection_path.name, parsed, gid=reader_gid, mode=0o440)
        return {"schema": _PROJECTION_SCHEMA, "status": "published",
                "authorization_id": authorization_id,
                "projection_path": str(projection_path), "reader_uid": reader_uid}


def _checked_current(project):
    credentials._require_root()
    credentials._check_root_directory(credentials.AUTH_ROOT)
    approval_path, installed_path, pending_path, _ = credentials._paths(project)
    if pending_path.exists() or pending_path.is_symlink():
        raise credentials.IssuerCredentialError("unfinished issuer install")
    approved, _grant = credentials._authorization(project, approval_path)
    ledger = credentials._read_protected(installed_path, missing_ok=True)
    credentials._check_revision(ledger, approved)
    authorization_id = credentials._authorization_id(approved)
    projection_path, peer_path = credentials._projection_paths(project)
    peer = _expected_peer(credentials._read_protected(peer_path), authorization_id)
    projection = _private_file(projection_path, gid=peer["reader_gid"], mode=0o440)
    if _validated(projection, approved) != authorization_id:
        raise credentials.IssuerCredentialError("station credential projection is stale")
    return authorization_id, peer


def _verify_socket(path, peer):
    # Fixed root-owner policy path, never a socket or UID supplied by the caller.
    for parent in reversed(path.parents):
        st = parent.lstat()
        if (not stat.S_ISDIR(st.st_mode) or st.st_uid != 0
                or st.st_mode & 0o022):
            raise credentials.IssuerCredentialError("station vault reader socket path unsafe")
    info = path.lstat()
    if (not stat.S_ISSOCK(info.st_mode)
            or info.st_uid != peer["reader_uid"]
            or stat.S_IMODE(info.st_mode) != 0o600):
        raise credentials.IssuerCredentialError("station vault reader socket identity changed")


def _read_station_socket(authorization_id, peer):
    _verify_socket(_SOCKET, peer)
    request = {
        "schema": _REQUEST_SCHEMA, "operation": _READ_OPERATION,
        "authorization_id": authorization_id, "nonce": secrets.token_hex(16),
    }
    wire = credentials._canonical(request) + b"\n"
    if len(wire) > 1024:
        raise credentials.IssuerCredentialError("bounded station vault request exceeded")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(5)
        connection.connect(str(_SOCKET))
        if not hasattr(socket, "SO_PEERCRED"):
            raise credentials.IssuerCredentialError("station socket peer authentication unavailable")
        pid, uid, _gid = struct.unpack(
            "3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        )
        if pid <= 0 or uid != peer["reader_uid"]:
            raise credentials.IssuerCredentialError("station vault reader peer identity disagrees")
        connection.sendall(wire)
        connection.shutdown(socket.SHUT_WR)
        chunks = bytearray()
        while len(chunks) <= 4096:
            part = connection.recv(4097 - len(chunks))
            if not part:
                break
            chunks.extend(part)
        if not credentials._TOKEN.fullmatch(bytes(chunks)):
            raise credentials.IssuerCredentialError("station vault response unavailable or invalid")
        return bytes(chunks)


def transfer_and_install(project_root):
    """Root-only, reviewed station reader -> private installer operation."""
    credentials._require_root()
    project = Project(Path(project_root))
    if str(project.path) != str(Path(project_root)):
        raise credentials.IssuerCredentialError("noncanonical credential project")
    # Root owner evidence is checked before and after station returns secret.
    # Never hold ProjectLock during remote RPC; installer acquires it later.
    authorization_id, peer = _checked_current(project)
    try:
        token = _read_station_socket(authorization_id, peer)
        checked_id, checked_peer = _checked_current(project)
        if checked_id != authorization_id or checked_peer != peer:
            raise credentials.IssuerCredentialError("station approval or pinned peer rotated during vault read")
        read_fd, write_fd = os.pipe()
        try:
            os.write(write_fd, token)
        finally:
            os.close(write_fd)
        try:
            return credentials.install_from_fd(
                project.path, read_fd, expected_authorization_id=authorization_id
            )
        finally:
            os.close(read_fd)
    except credentials.IssuerCredentialError:
        raise
    except (OSError, ValueError, TimeoutError):
        raise credentials.IssuerCredentialError("trusted station credential transfer unavailable") from None


def main(argv=None):
    parser = argparse.ArgumentParser(description="Root-owned station issuer credential projection and transfer")
    sub = parser.add_subparsers(dest="operation", required=True)
    publish = sub.add_parser("publish-projection")
    publish.add_argument("project")
    publish.add_argument("--projection-fd", type=int, required=True)
    publish.add_argument("--reader-uid", type=int, required=True)
    publish.add_argument("--reader-gid", type=int, required=True)
    install = sub.add_parser("transfer")
    install.add_argument("project")
    args = parser.parse_args(argv)
    if args.operation == "publish-projection":
        result = publish_projection(
            args.project, args.projection_fd,
            reader_uid=args.reader_uid, reader_gid=args.reader_gid
        )
    else:
        result = transfer_and_install(args.project)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    main()
