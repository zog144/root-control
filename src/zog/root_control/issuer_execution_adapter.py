"""Fixed-path root-only selected issuer execution serialization.

The selected systemd start *must* enter this adapter: there is no caller-
selected fence directory, lock, commit hash, program or boot epoch.
The protected installer owns creation of the 0700 fence directory and initial
ledger. A missing/changed installation always blocks launch.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import stat

from .issuer_execution_fence import IssuerExecutionFence, IssuerFenceDenied

_AUTHORITY_PARTS = ("etc", "zog", "host-deploy")
_FENCE_DIR = "selected-issuer-execution"
_COMMIT = "certificate-issuer-broker-install-commit.json"
_REVOCATIONS = ("certificate-issuer-broker-revoked.json",
                ".pending.certificate-issuer-broker-revoked.json")
_PENDING_COMMIT = ".pending." + _COMMIT


def _deny():
    raise IssuerFenceDenied("selected issuer execution admission unavailable") from None


@contextmanager
def protected_execution_directory():
    """Open exact root:root ancestry, 0755 parent and fixed 0700 ledger.

    Never creates missing STATE, lock directory, or an authority record.
    """
    if os.geteuid() != 0:
        _deny()
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for part in _AUTHORITY_PARTS:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY |
                          os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = nxt
            st = os.fstat(fd)
            if (st.st_uid, st.st_gid) != (0, 0) or (
                    stat.S_IMODE(st.st_mode) & 0o022):
                _deny()
        if stat.S_IMODE(os.fstat(fd).st_mode) != 0o755:
            _deny()
        # Revocation can be pending or committed. Both are terminal.
        _require_no_revocation(fd)
        commit = _read_commit(fd)
        nxt = os.open(_FENCE_DIR, os.O_RDONLY | os.O_DIRECTORY |
                      os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
        try:
            root = os.fstat(nxt)
            if root.st_uid != 0 or root.st_gid != 0 or (
                    stat.S_IMODE(root.st_mode) != 0o700):
                _deny()
            yield nxt, hashlib.sha256(commit).hexdigest()
        finally:
            os.close(nxt)
    finally:
        os.close(fd)


def _require_no_revocation(parent):
    for name in (*_REVOCATIONS, _PENDING_COMMIT):
        try:
            os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            continue
        _deny()


def _read_commit(parent):
    fd = os.open(_COMMIT, os.O_RDONLY | os.O_NOFOLLOW |
                 os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
    try:
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or (st.st_uid, st.st_gid) != (0, 0)
                or stat.S_IMODE(st.st_mode) != 0o444 or st.st_nlink != 1
                or not 0 < st.st_size <= 8192):
            _deny()
        raw = os.read(fd, st.st_size + 1)
        if len(raw) != st.st_size:
            _deny()
        return raw
    finally:
        os.close(fd)


def _boot_id():
    with open("/proc/sys/kernel/random/boot_id", "r", encoding="ascii") as f:
        boot = f.read(64).strip().replace("-", "")
    if len(boot) != 32 or any(x not in "0123456789abcdef" for x in boot):
        _deny()
    return boot


def _saved_request_id(project_root, definition):
    # The recorded launch is the ONLY permissible selector. No separate
    # request_id/epoch supplied by the caller is trusted.
    from zog.box_control.operations import OperationStore
    from zog.box_control.project import Project
    project = Project(Path(project_root))
    candidates = [
        row for row in OperationStore(project).records()
        if row.get("operation") == "launch"
        and row.get("new_runtime_id") == definition.get("runtime_id")
        and row.get("selected_program") == definition.get("selected_program")
        and row.get("phase") == "launching"
        and row.get("attempted_units") == [definition.get("unit_name")]
    ]
    if len(candidates) != 1:
        _deny()
    return candidates[0]["request_id"]


def admit_selected_start(backend, *, project_root, definition, dispatch):
    """Fsync intent, serialize actual StartTransientUnit and observe PID1.

    Called ONLY from BusctlSystemdBackend.start_service after preparing its
    exact property list. Failure or lost PID1 acknowledgment remains durable
    admission-uncertain, never reexecuted with the same request identity.
    """
    if (definition.get("application_name") != "certify-manage"
            or definition.get("selected_program") not in
            {"renew", "inspect", "stage"} or not callable(dispatch)):
        _deny()
    request_id = _saved_request_id(project_root, definition)
    boot_id = _boot_id()
    runtime_id = definition["runtime_id"]
    unit_name = definition["unit_name"]
    with protected_execution_directory() as (fd, commit_sha):
        fence = IssuerExecutionFence(fd)
        def launch(*, request_id, program, epoch, boot_id):
            # Recheck original recorded intent under the SAME lock held
            # through PID1 admission. No arbitrary callback crosses RPC.
            backend._validate_program_selection(project_root, definition)
            dispatch()
            observation = backend.observe(project_root=project_root, unit_name=unit_name)
            invocation = observation.get("invocation_id")
            if (observation.get("exists") is not True
                    or type(invocation) is not str or len(invocation) != 32
                    or any(x not in "0123456789abcdef" for x in invocation)):
                _deny()
            return {"request_id": request_id, "program": program,
                    "runtime_id": runtime_id, "invocation_id": invocation}
        return fence.admit(request_id=request_id,
                           program=definition["selected_program"],
                           boot_id=boot_id, trusted_commit_sha256=commit_sha,
                           native_launch=launch)
