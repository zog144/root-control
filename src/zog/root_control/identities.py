"""Protected, administrator-issued execution identity grants (v1).

No unprivileged RPC can provision or choose credentials. A root administrator
provisions through the offline CLI after approving a collision-free host range.
The registry is immutable per project/application and never automatically reclaimed.
"""
from __future__ import annotations

import argparse
import fcntl
import grp
import json
import os
import pwd
import re
import secrets
import stat
import subprocess
from pathlib import Path

REGISTRY = Path("/etc/zog/execution-identities.json")
SCHEMA = "zog-execution-identity-v1"
_COMPONENT = re.compile(r"^[A-Za-z0-9-]+$")
_MAX_FILE = 262144
_MIN_ID = 1000
_MAX_ID = 2**31 - 2


class ExecutionIdentityError(ValueError):
    pass


def _parents(path: Path):
    for parent in reversed(path.parents):
        yield parent


def _check_directory(path: Path):
    if path.is_symlink():
        raise ExecutionIdentityError("execution identity registry directory is redirected")
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ExecutionIdentityError("execution identity registry directory must be protected by root")


def _check_registry_file(info):
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ExecutionIdentityError("execution identity registry is not root-owned and protected")


def _read():
    for parent in _parents(REGISTRY):
        _check_directory(parent)
    if not REGISTRY.exists() and not REGISTRY.is_symlink():
        return {"schema": SCHEMA, "grants": []}
    info = REGISTRY.lstat()
    _check_registry_file(info)
    if info.st_size > _MAX_FILE:
        raise ExecutionIdentityError("execution identity registry exceeds size bound")
    fd = os.open(REGISTRY, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        with os.fdopen(fd, "rb") as stream:
            content = stream.read(_MAX_FILE + 1)
    except BaseException:
        raise
    if len(content) > _MAX_FILE:
        raise ExecutionIdentityError("execution identity registry exceeds size bound")
    try:
        raw = json.loads(content)
    except (ValueError, UnicodeError) as exc:
        raise ExecutionIdentityError("invalid execution identity registry JSON") from exc
    if not isinstance(raw, dict) or set(raw) != {"schema", "grants"} or raw["schema"] != SCHEMA:
        raise ExecutionIdentityError("unsupported execution identity registry schema")
    if not isinstance(raw["grants"], list) or len(raw["grants"]) > 2048:
        raise ExecutionIdentityError("invalid execution identity grant count")
    seen_apps, seen_uids, seen_gids, seen_grants = set(), set(), set(), set()
    for grant in raw["grants"]:
        if not isinstance(grant, dict) or set(grant) != {"schema", "grant_id", "version", "project", "application", "uid", "gid"}:
            raise ExecutionIdentityError("invalid execution identity grant fields")
        project, app = grant["project"], grant["application"]
        if (not isinstance(project, str) or not project.startswith("/") or
                str(Path(project)) != project or ".." in Path(project).parts or
                not isinstance(app, str) or not _COMPONENT.fullmatch(app)):
            raise ExecutionIdentityError("invalid execution identity grant scope")
        if (grant["schema"] != SCHEMA or type(grant["version"]) is not int or grant["version"] != 1 or
                not isinstance(grant["grant_id"], str) or not re.fullmatch("[a-f0-9]{32}", grant["grant_id"]) or
                type(grant["uid"]) is not int or type(grant["gid"]) is not int or
                not (_MIN_ID <= grant["uid"] <= _MAX_ID and _MIN_ID <= grant["gid"] <= _MAX_ID)):
            raise ExecutionIdentityError("invalid execution identity grant identity")
        scope = (project, app)
        if scope in seen_apps or grant["uid"] in seen_uids or grant["gid"] in seen_gids or grant["grant_id"] in seen_grants:
            raise ExecutionIdentityError("duplicate or shared execution identity grant")
        seen_apps.add(scope); seen_uids.add(grant["uid"]); seen_gids.add(grant["gid"]); seen_grants.add(grant["grant_id"])
    return raw


def _host_unused(uid: int, gid: int):
    try:
        pwd.getpwuid(uid)
    except KeyError:
        pass
    else:
        raise ExecutionIdentityError("execution UID collides with host account")
    try:
        grp.getgrgid(gid)
    except KeyError:
        pass
    else:
        raise ExecutionIdentityError("execution GID collides with host group")


def principal_name(grant):
    """Stable name derived solely from the immutable grant ID, never the app label."""
    return "zog-app-" + grant["grant_id"][:16]


def _shadow_password_locked(name):
    """Inspect only the host's root-protected shadow entry for our local user.

    Python's deprecated spwd module is unavailable on newer interpreters.
    We never expose a shadow field through an RPC or diagnostics.
    """
    shadow = Path("/etc/shadow")
    metadata = shadow.lstat()
    if (not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0 or metadata.st_mode & 0o027):
        raise ExecutionIdentityError("host shadow database is not protected")
    fd = os.open(shadow, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        stat_fd = os.fstat(fd)
        if not stat.S_ISREG(stat_fd.st_mode) or (stat_fd.st_dev, stat_fd.st_ino) != (
                metadata.st_dev, metadata.st_ino):
            raise ExecutionIdentityError("host shadow database changed during validation")
        found = []
        with os.fdopen(fd, "r", encoding="utf-8", errors="strict") as stream:
            fd = -1
            for line in stream:
                # The password field never leaves this privileged function.
                if line.startswith(name + ":"):
                    found.append(line.split(":", 2)[1])
                if len(found) > 1:
                    break
    finally:
        if fd >= 0:
            os.close(fd)
    return len(found) == 1 and bool(found[0]) and found[0][0] in ("!", "*")


def _checked_nss(grant):
    """Ensure host systemd NSS resolves exactly this grant and no extra groups.

    systemd v252's service execution path requests a full passwd record even
    with numeric User=, so an absent record may fail with 217/USER. The record
    is administrator-activated, never synthesized during an application RPC.
    """
    name = principal_name(grant)
    try:
        account = pwd.getpwnam(name)
        by_uid = pwd.getpwuid(grant["uid"])
        group = grp.getgrnam(name)
        by_gid = grp.getgrgid(grant["gid"])
    except KeyError as exc:
        raise ExecutionIdentityError(
            "execution grant needs host NSS activation; run root-only identities activate"
        ) from exc
    if (account.pw_name != name or account.pw_uid != grant["uid"]
            or account.pw_gid != grant["gid"]
            or by_uid.pw_name != name or by_uid.pw_gid != grant["gid"]
            or group.gr_name != name or group.gr_gid != grant["gid"]
            or by_gid.gr_name != name or group.gr_mem):
        raise ExecutionIdentityError("host NSS record differs from protected execution grant")
    if (account.pw_dir != "/nonexistent"
            or account.pw_shell not in ("/sbin/nologin", "/usr/sbin/nologin")):
        raise ExecutionIdentityError("managed execution identity is not non-login")
    # systemd's initgroups() must not assign ambient or privileged groups.
    try:
        memberships = os.getgrouplist(name, grant["gid"])
    except (OSError, KeyError, ValueError) as exc:
        raise ExecutionIdentityError("cannot validate execution supplementary groups") from exc
    if set(memberships) != {grant["gid"]}:
        raise ExecutionIdentityError("managed execution identity has supplementary groups")
    try:
        locked = _shadow_password_locked(name)
    except (OSError, UnicodeError, ValueError) as exc:
        raise ExecutionIdentityError("cannot verify locked execution account") from exc
    if not locked:
        raise ExecutionIdentityError("managed execution identity must have a locked password")
    return name


def _run_identity_tool(*arguments):
    try:
        process = subprocess.run(
            arguments, check=False, capture_output=True, text=True, timeout=30,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ExecutionIdentityError("host identity tool failed; inspect and retry activation") from exc
    if process.returncode != 0:
        raise ExecutionIdentityError(
            f"host identity tool {Path(arguments[0]).name} failed with exit {process.returncode}; "
            "inspect partial activation and retry"
        )


def _activate_nss(grant):
    """Idempotent, explicit administrator action; cannot change an issued grant."""
    name = principal_name(grant)
    # An unrelated account occupying either number or derived name is forbidden.
    try:
        existing_group = grp.getgrnam(name)
    except KeyError:
        existing_group = None
    try:
        by_gid = grp.getgrgid(grant["gid"])
    except KeyError:
        by_gid = None
    if (existing_group is not None and existing_group.gr_gid != grant["gid"]
            or by_gid is not None and by_gid.gr_name != name):
        raise ExecutionIdentityError("execution GID/name collides with unrelated host group")
    try:
        existing_user = pwd.getpwnam(name)
    except KeyError:
        existing_user = None
    try:
        by_uid = pwd.getpwuid(grant["uid"])
    except KeyError:
        by_uid = None
    if (existing_user is not None and
            (existing_user.pw_uid != grant["uid"] or existing_user.pw_gid != grant["gid"])
            or by_uid is not None and by_uid.pw_name != name):
        raise ExecutionIdentityError("execution UID/name collides with unrelated host account")

    if existing_group is None:
        _run_identity_tool("/usr/sbin/groupadd", "--gid", str(grant["gid"]), name)
    # Recheck after every step; a groupadd failure is retained, not rolled back.
    actual_group = grp.getgrnam(name)
    if actual_group.gr_gid != grant["gid"]:
        raise ExecutionIdentityError("provisioned group disagrees with grant")
    if existing_user is None:
        shell = "/usr/sbin/nologin" if Path("/usr/sbin/nologin").is_file() else "/sbin/nologin"
        if not Path(shell).is_file():
            raise ExecutionIdentityError("host nologin shell is unavailable")
        _run_identity_tool(
            "/usr/sbin/useradd", "--no-create-home", "--no-user-group",
            "--uid", str(grant["uid"]), "--gid", str(grant["gid"]),
            "--home-dir", "/nonexistent", "--shell", shell, name,
        )
    _checked_nss(grant)


def activate(project_root, application):
    """Activate an existing grant for systemd; never create a new UID/GID grant.

    Must run as root offline (not exposed through the daemon). Holds the same
    registry lock as provision() and is safe to repeat after partial useradd.
    """
    if os.geteuid() != 0:
        raise ExecutionIdentityError("only host administrator can activate an identity")
    for parent in _parents(REGISTRY):
        _check_directory(parent)
    fd = os.open(REGISTRY.parent / "execution-identities.lock",
                 os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        _check_provision_lock(fd)
        fcntl.flock(fd, fcntl.LOCK_EX)
        project = str(Path(project_root).resolve())
        matches = [g for g in _read()["grants"]
                   if g["project"] == project and g["application"] == application]
        if len(matches) != 1:
            raise ExecutionIdentityError("no unique protected grant to activate")
        _activate_nss(matches[0])
        return dict(matches[0])
    finally:
        os.close(fd)


def resolve(project_root, application):
    """Read-only grant lookup with mandatory host NSS consistency verification."""
    project = str(Path(project_root).resolve())
    if not isinstance(application, str) or not _COMPONENT.fullmatch(application):
        raise ExecutionIdentityError("invalid application execution identity scope")
    grants = [grant for grant in _read()["grants"]
              if grant["project"] == project and grant["application"] == application]
    if not grants:
        raise ExecutionIdentityError("application execution identity is not provisioned")
    grant = grants[0]
    _checked_nss(grant)
    return dict(grant)


def verify(project_root, application, binding, *, storage_id=None):
    """Fail closed if a prepared immutable grant is missing, replaced or forged."""
    if not isinstance(binding, dict):
        raise ExecutionIdentityError("missing prepared application execution identity")
    current = resolve(project_root, application)
    if binding != current:
        raise ExecutionIdentityError("prepared execution identity disagrees with protected grant")
    if storage_id is not None and (not isinstance(storage_id, str) or not re.fullmatch("[a-f0-9]{32}", storage_id)):
        raise ExecutionIdentityError("invalid prepared storage identity")
    return current


def _check_provision_lock(fd):
    lock = os.fstat(fd)
    if not stat.S_ISREG(lock.st_mode) or lock.st_uid != 0 or lock.st_mode & 0o077:
        raise ExecutionIdentityError("execution identity provision lock is not protected")


def provision(project_root, application, *, first_uid, last_uid):
    """Offline root-only, range-reviewed allocator. IDs are never auto-recycled."""
    if os.geteuid() != 0:
        raise ExecutionIdentityError("only the host administrator may provision execution identities")
    if type(first_uid) is not int or type(last_uid) is not int or not (_MIN_ID <= first_uid <= last_uid <= _MAX_ID):
        raise ExecutionIdentityError("invalid reviewed UID/GID range")
    # Protect the containing directory against unprivileged registry replacement.
    for parent in _parents(REGISTRY):
        _check_directory(parent)
    lock_path = REGISTRY.parent / "execution-identities.lock"
    fd = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        _check_provision_lock(fd)
        fcntl.flock(fd, fcntl.LOCK_EX)
        raw = _read()
        project = str(Path(project_root).resolve())
        if not isinstance(application, str) or not _COMPONENT.fullmatch(application):
            raise ExecutionIdentityError("invalid application execution identity scope")
        existing = [g for g in raw["grants"] if g["project"] == project and g["application"] == application]
        if existing:
            # Provisioning is idempotent even before host NSS is activated.
            return dict(existing[0])
        used_uid = {g["uid"] for g in raw["grants"]}
        used_gid = {g["gid"] for g in raw["grants"]}
        for number in range(first_uid, last_uid + 1):
            if number in used_uid or number in used_gid:
                continue
            try:
                _host_unused(number, number)
            except ExecutionIdentityError:
                continue
            grant = dict(schema=SCHEMA, grant_id=secrets.token_hex(16),
                         version=1, project=project, application=application, uid=number, gid=number)
            raw["grants"].append(grant)
            payload = (json.dumps(raw, sort_keys=True, separators=(",", ":")) + "\n").encode()
            if len(payload) > _MAX_FILE:
                raise ExecutionIdentityError("execution identity registry full")
            temp = REGISTRY.parent / (".execution-identities-" + secrets.token_hex(8))
            out = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
            try:
                os.fchmod(out, 0o644)
                with os.fdopen(out, "wb", closefd=False) as stream:
                    stream.write(payload); stream.flush(); os.fsync(stream.fileno())
            finally:
                os.close(out)
            try:
                os.replace(temp, REGISTRY)
                parent_fd = os.open(REGISTRY.parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(parent_fd)
                finally:
                    os.close(parent_fd)
            finally:
                if temp.exists():
                    temp.unlink()
            return dict(grant)
        raise ExecutionIdentityError("no unused identity in reviewed host range")
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description="Privileged Zog execution identity administration")
    sub = parser.add_subparsers(dest="operation", required=True)
    issue = sub.add_parser("provision", help="Reserve an immutable UID/GID grant")
    issue.add_argument("project")
    issue.add_argument("application")
    issue.add_argument("--range-start", type=int, required=True)
    issue.add_argument("--range-end", type=int, required=True)
    active = sub.add_parser("activate", help="Materialize the issued grant in host NSS")
    active.add_argument("project")
    active.add_argument("application")
    args = parser.parse_args()
    if args.operation == "provision":
        grant = provision(args.project, args.application,
                          first_uid=args.range_start, last_uid=args.range_end)
    else:
        grant = activate(args.project, args.application)
    print(json.dumps(grant, sort_keys=True))


if __name__ == "__main__":
    main()
