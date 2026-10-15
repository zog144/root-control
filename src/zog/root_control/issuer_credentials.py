"""Issuer-only Cloudflare credential installer.

This module is intentionally NOT registered as a root-control daemon RPC.
A future reviewed station-access local vault reader may feed token bytes through
a private FD to a trusted root-owned provisioning process. Never serialize token
bytes into controller requests, argv, environment, journal, or audit records.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import select
import socket
import struct
import stat
import time
from contextlib import contextmanager

from zog.box_control.project import Project
from zog.box_control.application_storage import ApplicationStorage
from zog.box_control.runtime.reference import RuntimeReferenceStore
from zog.box_control.operations import OperationStore
from zog.box_control.requests import ApplicationRequestStore
from zog.box_control.model import ApplicationRuntimeState
from .identities import verify

AUTH_ROOT = Path("/etc/zog/issuer-credentials")
SCHEMA = "zog-issuer-cloudflare-credential-v1"
AUDIT_SCHEMA = "zog-issuer-cloudflare-installation-v1"
_HEX32 = re.compile(r"[0-9a-f]{32}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
_TOKEN = re.compile(rb"[A-Za-z0-9_-]{20,4096}\Z")
_FIELDS = frozenset({
    "schema", "state", "project", "certificate_id",
    "assignment_id", "assignment_revision", "credential_id",
    "credential_revision", "zone_id", "zone_name", "grant_id",
    "storage_id", "policy_sha256", "receipt_sha256", "expires_at",
})
_APPLICATION = "certify-manage"
PROJECTION_SCHEMA = "zog-station-issuer-reader-authorization-v1"
READER_REQUEST_SCHEMA = "zog-station-issuer-cloudflare-read-v1"
READER_SOCKET = Path("/run/zog/issuer-cloudflare-reader.sock")
_PROJECTION_FIELDS = frozenset({
    "schema", "authorization", "origin", "installation_id",
    "host_id", "account_id", "owner_user_id",
})
_READER_PEER_SCHEMA = "zog-issuer-cloudflare-reader-peer-v1"



class IssuerCredentialError(ValueError):
    """Intentionally secret-free, fixed-message admission failure."""


def _require_root():
    if os.geteuid() != 0:
        raise IssuerCredentialError("issuer credential provisioning requires root")


def _check_root_directory(path):
    path = Path(path)
    for item in reversed((path, *path.parents)):
        info = item.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                or info.st_mode & 0o022):
            raise IssuerCredentialError("issuer authorization directory is not root controlled")


def _read_protected(path, *, missing_ok=False):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        if missing_ok:
            return None
        raise IssuerCredentialError("protected issuer authorization is missing") from None
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                or info.st_mode & 0o077 or info.st_nlink != 1
                or info.st_size > 16384):
            raise IssuerCredentialError("protected issuer authorization is unsafe")
        raw = os.read(fd, 16385)
        if len(raw) > 16384:
            raise IssuerCredentialError("protected issuer authorization exceeds bound")
        return json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise IssuerCredentialError("protected issuer authorization is invalid") from exc
    finally:
        os.close(fd)


def _atomic_json(directory, name, value):
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()
    temporary = "." + name + "." + secrets.token_hex(12) + ".pending"
    fd = os.open(directory / temporary,
                 os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                 0o600)
    try:
        remaining = memoryview(raw)
        while remaining:
            n = os.write(fd, remaining)
            if n <= 0:
                raise OSError("incomplete authorization record write")
            remaining = remaining[n:]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(directory / temporary, directory / name)
    _fsync(directory)


def _fsync(directory):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _paths(project):
    key = hashlib.sha256(str(project.path).encode()).hexdigest()
    return (AUTH_ROOT / (key + ".approval.json"),
            AUTH_ROOT / (key + ".installed.json"),
            AUTH_ROOT / (key + ".pending.json"),
            AUTH_ROOT / (key + ".lock"))


def _projection_paths(project):
    key = hashlib.sha256(str(project.path).encode()).hexdigest()
    return AUTH_ROOT / (key + ".station-reader.json"), AUTH_ROOT / (key + ".reader-peer.json")


def _canonical(value):
    # Identical to station-access's immutable canonical() routine.
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _authorization_id(approved):
    return hashlib.sha256(_canonical(approved)).hexdigest()


def _check_lock_info(info):
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
            or info.st_mode & 0o077 or info.st_nlink != 1):
        raise IssuerCredentialError("issuer provision lock is unsafe")


@contextmanager
def _locked(project):
    _require_root()
    _check_root_directory(AUTH_ROOT)
    approval, installed, pending, lock = _paths(project)
    fd = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        _check_lock_info(os.fstat(fd))
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield approval, installed, pending
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _policy():
    # Shared trusted nonsecret host-owner policy, never a station-side proposal.
    from zog.box_control.host_bindings import (
        _certify_policy_digest, _CERT_POLICY_SOURCE,
    )
    _certify_policy_digest(_CERT_POLICY_SOURCE)
    directory = Path(_CERT_POLICY_SOURCE)
    fd = os.open(directory / "policy.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > 65536:
            raise IssuerCredentialError("issuer policy is unavailable")
        policy = json.loads(os.read(fd, 65537))
    finally:
        os.close(fd)
    if (not isinstance(policy, dict)
            or set(policy) != {"schema", "certificate_id", "hostnames",
                                "email", "acme_directory", "challenge", "dns_plugin"}
            or policy["schema"] != "zog-certify-manage-v1"):
        raise IssuerCredentialError("issuer policy schema is unavailable")
    digest = hashlib.sha256(json.dumps(
        policy, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ).encode()).hexdigest()
    return policy, digest


def _authorization(project, approval):
    raw = _read_protected(approval)
    if (not isinstance(raw, dict) or set(raw) != _FIELDS
            or raw["schema"] != SCHEMA or raw["state"] != "approved"
            or raw["project"] != str(project.path)
            or raw["certificate_id"] != "station-web"
            or any(not isinstance(raw[name], str) or not _UUID.fullmatch(raw[name])
                   for name in ("assignment_id", "credential_id"))
            or any(not isinstance(raw[name], str) or not _HEX32.fullmatch(raw[name])
                   for name in ("grant_id", "storage_id"))
            or any(type(raw[name]) is not int or raw[name] < 1
                   for name in ("assignment_revision", "credential_revision"))
            or any(not isinstance(raw[name], str) or not _HEX64.fullmatch(raw[name])
                   for name in ("policy_sha256", "receipt_sha256"))
            or any(not isinstance(raw[name], str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", raw[name])
                   for name in ("zone_id",))
            or not isinstance(raw["zone_name"], str)
            or not re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+", raw["zone_name"])
            or len(raw["zone_name"]) > 253
            or type(raw["expires_at"]) is not int or raw["expires_at"] <= int(time.time())):
        raise IssuerCredentialError("issuer authorization is missing, expired or invalid")
    policy, digest = _policy()
    # Root-control cannot depend on the issuer's Python distribution:
    # that software lives in its immutable application image. Enforce the
    # security-critical subset of the issuer policy independently here.
    names = policy.get("hostnames")
    if (not isinstance(names, list) or not 1 <= len(names) <= 20
            or any(type(n) is not str or n != n.lower()
                   or len(n) > 253 or not re.fullmatch(
                       r"(?:\*\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)+", n)
                   for n in names)
            or names != sorted(set(names))
            or type(policy.get("certificate_id")) is not str
            or not re.fullmatch(r"[a-z][a-z0-9-]{0,62}", policy["certificate_id"])
            or type(policy.get("acme_directory")) is not str
            or not policy["acme_directory"].startswith("https://")
            or type(policy.get("email")) is not str
            or "@" not in policy["email"]):
        raise IssuerCredentialError("issuer policy fails independent scope validation")
    if (policy["certificate_id"] != raw["certificate_id"]
            or policy["challenge"] != "dns-01"
            or policy["dns_plugin"] != "dns-cloudflare"
            or raw["policy_sha256"] != digest):
        raise IssuerCredentialError("issuer policy and approved credential disagree")
    names = policy["hostnames"]
    if (not isinstance(names, list) or not names
            or any(not isinstance(n, str)
                   or (n.removeprefix("*.") != raw["zone_name"]
                       and not n.removeprefix("*.").endswith("." + raw["zone_name"]))
                   for n in names)):
        raise IssuerCredentialError("issuer zone and hostname scope disagree")
    saved = ApplicationStorage(project).load(_APPLICATION)
    if (saved is None or saved["state"] != "ready"
            or saved.get("cleanup_pending")
            or saved["storage_id"] != raw["storage_id"]):
        raise IssuerCredentialError("issuer storage preparation is not ready")
    grant = verify(project.path, _APPLICATION,
                   saved["definition"].get("execution_binding"),
                   storage_id=raw["storage_id"])
    if grant["grant_id"] != raw["grant_id"]:
        raise IssuerCredentialError("issuer execution grant disagrees")
    return raw, grant


def _quiet(project):
    # Credential rotation cannot occur while an issuer operation is running
    # or queued. No implicit cancellation, service termination or retry.
    for record in OperationStore(project).records():
        if (record.get("application", {}).get("name") == _APPLICATION
                and (not record["finished"] or not record["published"]
                     or record["phase"] not in {"committed", "failed", "abandoned"})):
            raise IssuerCredentialError("issuer operation is unresolved")
    refs = RuntimeReferenceStore(project.runtime_reference_file).load()
    for ref in refs.values():
        if ref.application != _APPLICATION:
            continue
        if (ref.cleanup_pending or ref.state not in {
                ApplicationRuntimeState.TERMINATED, ApplicationRuntimeState.FAILED,
            }):
            raise IssuerCredentialError("issuer runtime is not safely terminal")
    requests = ApplicationRequestStore(
        project.application_request_dir, project.application_request_result_dir
    )
    for path in requests.paths():
        req = requests.load(path)
        if req.application == _APPLICATION:
            raise IssuerCredentialError("issuer request is queued or unresolved")
    from zog.box_control.durability import _blocked_projects
    if (project.path in _blocked_projects
            or (project.state_dir / "mutation-incomplete.json").exists()
            or (project.state_dir / "session-recovery-pending.json").exists()):
        raise IssuerCredentialError("controller persistence recovery is required")


def _opened_destination(project, authorization, grant, *, create_dns):
    """Walk project-owned storage with no-follow anchored directory FDs.

    A station caller cannot select any component; neither the project owner
    nor an unprivileged issuer can redirect this privileged writer through a
    symlinked parent between the initial project selection and publication.
    """
    uid, gid = grant["uid"], grant["gid"]
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(project.path, flags)
    try:
        for name in ("state", "mounts", "persistent",
                     authorization["storage_id"], "certificate-data"):
            child = os.open(name, flags, dir_fd=fd)
            try:
                info = os.fstat(child)
                if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022:
                    raise IssuerCredentialError("persistent storage ancestry is unsafe")
            except BaseException:
                os.close(child)
                raise
            os.close(fd)
            fd = child

        parent = os.fstat(fd)
        if ((parent.st_uid, parent.st_gid) != (uid, gid)
                or stat.S_IMODE(parent.st_mode) != 0o700):
            raise IssuerCredentialError("issuer persistent directory identity or mode drift")
        if create_dns:
            try:
                os.mkdir("dns", 0o700, dir_fd=fd)
                os.chown("dns", uid, gid, dir_fd=fd, follow_symlinks=False)
                os.fsync(fd)
            except FileExistsError:
                pass
        child = os.open("dns", flags, dir_fd=fd)
        info = os.fstat(child)
        if (not stat.S_ISDIR(info.st_mode)
                or (info.st_uid, info.st_gid) != (uid, gid)
                or stat.S_IMODE(info.st_mode) != 0o700):
            os.close(child)
            raise IssuerCredentialError("issuer private DNS directory identity or mode drift")
        return child
    finally:
        os.close(fd)


def _file_ok(dfd, uid, gid):
    try:
        fd = os.open("cloudflare.ini", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dfd)
    except FileNotFoundError:
        return False
    try:
        info = os.fstat(fd)
        return (stat.S_ISREG(info.st_mode)
                and (info.st_uid, info.st_gid) == (uid, gid)
                and stat.S_IMODE(info.st_mode) == 0o600
                and info.st_nlink == 1 and 0 < info.st_size <= 4200)
    finally:
        os.close(fd)


def _matching(previous, current):
    return all(previous.get(field) == current.get(field) for field in (
        "project", "certificate_id", "assignment_id", "assignment_revision",
        "credential_id", "credential_revision", "zone_id", "zone_name",
        "grant_id", "storage_id", "policy_sha256", "receipt_sha256",
        "expires_at",
    ))


def _check_revision(previous, approved):
    if previous is None:
        return
    if (previous.get("schema") != AUDIT_SCHEMA
            or previous.get("status") not in {"installed", "blocked"}
            or type(previous.get("assignment_revision")) is not int
            or type(previous.get("credential_revision")) is not int):
        raise IssuerCredentialError("issuer installation ledger is malformed")
    if (approved["assignment_revision"] < previous["assignment_revision"]
            or approved["credential_revision"] < previous["credential_revision"]):
        raise IssuerCredentialError("issuer credential authorization rollback rejected")
    if (approved["assignment_revision"] == previous["assignment_revision"]
            and not _matching(previous, approved)):
        raise IssuerCredentialError("issuer assignment revision conflict")
    if (approved["credential_revision"] == previous["credential_revision"]
            and previous["credential_id"] != approved["credential_id"]):
        raise IssuerCredentialError("issuer credential revision conflict")


def _receipt(approved, *, status):
    return {**approved, "schema": AUDIT_SCHEMA, "status": status,
            "installed_at": int(time.time())}


def _read_token(fd):
    # Inherited FD, not command-line arguments or JSON RPC. Read to EOF;
    # a short pipe read must never be mistaken for a complete provider token.
    if type(fd) is not int or fd < 0:
        raise IssuerCredentialError("invalid trusted token descriptor")
    deadline = time.monotonic() + 5
    content = bytearray()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise IssuerCredentialError("trusted token transfer did not complete")
        try:
            readable, _, _ = select.select([fd], [], [], remaining)
            if not readable:
                raise IssuerCredentialError("trusted token transfer did not complete")
            chunk = os.read(fd, 4097 - len(content))
        except OSError:
            raise IssuerCredentialError("trusted token transfer unavailable") from None
        if not chunk:
            break
        content.extend(chunk)
        if len(content) > 4096:
            raise IssuerCredentialError("Cloudflare credential bytes are invalid")
    token = bytes(content)
    if not _TOKEN.fullmatch(token):
        raise IssuerCredentialError("Cloudflare credential bytes are invalid")
    return token


def install_from_fd(project_root, token_fd, *, expected_authorization_id=None):
    """Privileged offline installer, invoked only by an approved local owner.

    Does not create approval files and is deliberately not a daemon RPC.
    Interrupted installs retain a durable pending marker and block new issuance.
    """
    _require_root()
    project = Project(Path(project_root))
    if str(Path(project_root)) != str(project.path):
        raise IssuerCredentialError("noncanonical issuer project")
    from zog.box_control.locking import ProjectLock
    with ProjectLock(project.lock_file, timeout_seconds=10), _locked(project) as paths:
        approval_path, ledger_path, pending_path = paths
        approved, grant = _authorization(project, approval_path)
        if (expected_authorization_id is not None
                and _authorization_id(approved) != expected_authorization_id):
            raise IssuerCredentialError("station token authorization changed before installation")
        _quiet(project)
        if pending_path.exists() or pending_path.is_symlink():
            raise IssuerCredentialError("issuer credential installation needs explicit recovery")
        old = _read_protected(ledger_path, missing_ok=True)
        _check_revision(old, approved)
        if old is not None and old["status"] == "installed" and _matching(old, approved):
            dfd = _opened_destination(project, approved, grant, create_dns=False)
            try:
                if not _file_ok(dfd, grant["uid"], grant["gid"]):
                    raise IssuerCredentialError("recorded issuer credential file is unavailable")
            finally:
                os.close(dfd)
            return {"schema": AUDIT_SCHEMA, "status": "installed",
                    "replayed": True, "assignment_revision": approved["assignment_revision"],
                    "credential_revision": approved["credential_revision"]}
        token = _read_token(token_fd)
        # The approval file is a root-owner installed durable authority, not
        # an attacker-selected destination or a station web credential export.
        _atomic_json(AUTH_ROOT, pending_path.name, _receipt(approved, status="blocked"))
        try:
            dfd = _opened_destination(project, approved, grant, create_dns=True)
            try:
                name = ".cloudflare-" + secrets.token_hex(12) + ".pending"
                fd = os.open(name, os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                             os.O_CLOEXEC | os.O_NOFOLLOW, 0o600, dir_fd=dfd)
                try:
                    os.fchown(fd, grant["uid"], grant["gid"])
                    os.fchmod(fd, 0o600)
                    written = b"dns_cloudflare_api_token = " + token + b"\n"
                    remaining = memoryview(written)
                    while remaining:
                        n = os.write(fd, remaining)
                        if n <= 0:
                            raise OSError("incomplete private credential write")
                        remaining = remaining[n:]
                    os.fsync(fd)
                finally:
                    os.close(fd)
                # Even an initial install must refuse overwriting an unrelated
                # file, symlink or hardlink. Rotation is permitted only from a
                # validated previous install with an intact owner-only target.
                if _exists(dfd) and (
                        old is None or old["status"] != "installed"
                        or not _file_ok(dfd, grant["uid"], grant["gid"])):
                    raise IssuerCredentialError("existing issuer credential target is unsafe")
                os.rename(name, "cloudflare.ini", src_dir_fd=dfd, dst_dir_fd=dfd)
                os.fsync(dfd)
            finally:
                os.close(dfd)
            _atomic_json(AUTH_ROOT, ledger_path.name, _receipt(approved, status="installed"))
            os.unlink(pending_path)
            _fsync(AUTH_ROOT)
        except Exception:
            # Keep durable pending receipt; never claim success after a failed
            # rename, fsync or audit barrier. No token is included in errors.
            raise IssuerCredentialError("issuer credential provisioning incomplete; review pending evidence") from None
        return {"schema": AUDIT_SCHEMA, "status": "installed",
                "replayed": False, "assignment_revision": approved["assignment_revision"],
                "credential_revision": approved["credential_revision"]}


def _exists(dfd):
    try:
        os.stat("cloudflare.ini", dir_fd=dfd, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False


def require_installed(project_root, definition):
    """Fail-closed privileged admission for selected DNS-01 issue/renew."""
    if definition.get("application_name") != _APPLICATION or definition.get("selected_program") not in ("issue", "renew"):
        return
    policy, _ = _policy()
    if policy["challenge"] != "dns-01":
        return
    project = Project(Path(project_root))
    with _locked(project) as (approval_path, ledger_path, pending_path):
        if pending_path.exists() or pending_path.is_symlink():
            raise IssuerCredentialError("issuer secret installation is uncertain")
        approval, grant = _authorization(project, approval_path)
        record = _read_protected(ledger_path)
        _check_revision(record, approval)
        if record.get("status") != "installed" or not _matching(record, approval):
            raise IssuerCredentialError("issuer secret authorization not installed")
        if (definition.get("persistent_storage_id") != approval["storage_id"]
                or definition.get("execution_binding") != grant):
            raise IssuerCredentialError("issuer operation grant or storage differs")
        dfd = _opened_destination(project, approval, grant, create_dns=False)
        try:
            if not _file_ok(dfd, grant["uid"], grant["gid"]):
                raise IssuerCredentialError("issuer credential private file is not trustworthy")
        finally:
            os.close(dfd)


def inspect(project_root):
    """Nonsecret offline view for the trusted root owner; never token bytes."""
    _require_root()
    project = Project(Path(project_root))
    with _locked(project) as (approval_path, ledger_path, pending_path):
        if pending_path.exists() or pending_path.is_symlink():
            return {"schema": AUDIT_SCHEMA, "status": "blocked", "reason": "pending-install"}
        old = _read_protected(ledger_path, missing_ok=True)
        if old is None:
            return {"schema": AUDIT_SCHEMA, "status": "unavailable"}
        return {"schema": AUDIT_SCHEMA, "status": old["status"],
                "assignment_revision": old["assignment_revision"],
                "credential_revision": old["credential_revision"],
                "grant_id": old["grant_id"], "storage_id": old["storage_id"]}


def main(argv=None):
    """Root-only offline interface; never accepts token text or JSON RPC."""
    import argparse
    parser = argparse.ArgumentParser(description="Offline private issuer DNS credential installer")
    sub = parser.add_subparsers(dest="operation", required=True)
    install = sub.add_parser("install")
    install.add_argument("project")
    install.add_argument("--token-fd", type=int, required=True)
    view = sub.add_parser("inspect")
    view.add_argument("project")
    args = parser.parse_args(argv)
    if args.operation == "install":
        result = install_from_fd(args.project, args.token_fd)
    else:
        result = inspect(args.project)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    main()

