"""Fixed protected fresh worker start gate: no grant, no PID1 execution.

Only the pinned build-only sidecar may call this from BuildBackend.start().
The host-deploy root owner creates ONE 0600 grant for a reviewed exact job.
No client can supply a budget path, a second gate, an exemption, or a timer.
An exclusive, fsynced claim is made before StartTransientUnit, and is NEVER
removed on an uncertain D-Bus response. Historical build roles are unaffected.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
from contextlib import contextmanager

from .build import (FRESH_COMPILER_BUILD_MOUNT, FRESH_COMPILER_EXTERNAL_MOUNT, FRESH_COMPILER_PARENT_SLICE,
                    FRESH_COMPILER_PROJECT, canonical_request)
from .systemd import SystemdBackendError, _UNIT_IFACE

STATE = FRESH_COMPILER_EXTERNAL_MOUNT / "owner-state"
LOCK = STATE / "fresh-start.lock"
GRANT = STATE / "fresh-start-grant.json"
PHASE = STATE / "fresh-start-phase.json"
BUDGET = STATE / "budget"
TIMER = "zogfreshcrossbootstrapoct25-deadline.timer"
STOP_UNIT = "zogfreshcrossbootstrapoct25-deadline.service"
SCOPE = "fresh-dedicated-reservation-32gib-v1"
BUDGET_SCHEMA = "host-deploy-fresh-dedicated-storage-budget-v2"
GRANT_SCHEMA = "host-deploy-fresh-start-grant-v1"
PHASE_SCHEMA = "host-deploy-fresh-start-phase-v1"
CLAIM_SCHEMA = "root-control-fresh-worker-claim-v1"
MAX_SECONDS = 21600
_HEX = re.compile(r"[0-9a-f]{32}\Z")


def _canonical(x):
    return json.dumps(x, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("ascii")


def digest_request(request):
    return "sha256:" + hashlib.sha256(_canonical(canonical_request(request))).hexdigest()


def _protected_dir(path):
    # No symlink following through owner-state or its quota-backed ancestors.
    cursor = Path("/")
    for component in path.parts[1:]:
        cursor = cursor / component
        st = cursor.lstat()
        if (not stat.S_ISDIR(st.st_mode) or st.st_uid != 0
                or st.st_mode & 0o022 or cursor.is_symlink()):
            raise SystemdBackendError("unprotected fresh start directory")
    if (path.stat().st_dev != FRESH_COMPILER_EXTERNAL_MOUNT.stat().st_dev
            or path.stat().st_dev == FRESH_COMPILER_BUILD_MOUNT.stat().st_dev):
        raise SystemdBackendError("fresh start grant lacks 2-GiB backing")


def _read(path):
    _protected_dir(path.parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_nlink != 1
                or stat.S_IMODE(st.st_mode) != 0o600 or st.st_size > 16384):
            raise SystemdBackendError("untrusted fresh start evidence")
        raw = os.read(fd, st.st_size + 1)
        if len(raw) != st.st_size:
            raise SystemdBackendError("short fresh start evidence")
        return json.loads(raw)
    finally:
        os.close(fd)


def _write_once(path, record):
    _protected_dir(path.parent)
    data = _canonical(record) + b"\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        if os.write(fd, data) != len(data):
            raise OSError("short fresh start claim")
        os.fsync(fd)
    finally:
        os.close(fd)
    dfd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def _update_phase(record):
    # The one-shot claim already exists. If this replace fails, admission is
    # uncertain and no retry is authorized by a leftover grant.
    temp = STATE / (".fresh-start-" + os.urandom(16).hex())
    _write_once(temp, record)
    os.replace(temp, PHASE)
    fd = os.open(STATE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


@contextmanager
def locked():
    _protected_dir(STATE)
    fd = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0
                or st.st_nlink != 1 or stat.S_IMODE(st.st_mode) != 0o600):
            raise SystemdBackendError("untrusted fresh start lock")
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _timer_active(systemd, now_us):
    obj = systemd._get_unit_path(TIMER)
    if obj is None:
        raise SystemdBackendError("fresh deadline timer absent")
    state = systemd._get_property(obj, _UNIT_IFACE, "ActiveState")
    _TIMER_IFACE = 'org.freedesktop.systemd1.Timer'
    target = systemd._get_property(obj, _TIMER_IFACE, "Unit")
    expiry = systemd._get_property(obj, _TIMER_IFACE, "NextElapseUSecMonotonic")
    if (state != "active" or target != STOP_UNIT
            or type(expiry) is not int or not now_us < expiry):
        raise SystemdBackendError("fresh PID1 deadline not active or expired")


def claim(*, backend, project_root, job_id, request):
    """Atomic exact grant consumption. Caller MUST hold locked() until PID1.

    This method does not create the host owner's grant; only consumes it.
    It MUST occur before root-control's job start_attempted write.
    """
    if (backend.parent_slice != FRESH_COMPILER_PARENT_SLICE
            or project_root != backend.authorized_project_root
            or Path(project_root).name != FRESH_COMPILER_PROJECT
            or os.geteuid() != 0 or not _HEX.fullmatch(job_id)):
        raise SystemdBackendError("untrusted fresh start principal or Project")
    grant = _read(GRANT)
    phase = _read(PHASE)
    if (type(grant) is not dict
            or set(grant) != {"schema","kind","host_id","boot_id",
              "project_root","request_id","plan_sha256","job_id",
              "request_sha256","budget_scope","canary_receipt_sha256"}
            or grant["schema"] != GRANT_SCHEMA
            or grant["kind"] not in ("canary", "compiler")
            or grant["job_id"] != job_id
            or grant["request_sha256"] != digest_request(request)
            or grant["project_root"] != project_root
            or grant["budget_scope"] != SCOPE
            or not _HEX.fullmatch(grant["request_id"])):
        raise SystemdBackendError("fresh worker lacks exact reviewed start grant")
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    if grant["boot_id"] != boot:
        raise SystemdBackendError("fresh worker grant belongs to another boot")
    record = _read(BUDGET / (grant["request_id"] + ".json"))
    if (record.get("schema") != BUDGET_SCHEMA
            or any(record.get(k) != grant[k] for k in (
                "host_id","boot_id","project_root","request_id"))
            or record.get("sidecar_plan_sha256") != grant["plan_sha256"]
            or record.get("status") != "active"):
        raise SystemdBackendError("fresh budget is not current for worker start")
    now = time.monotonic_ns()
    now_sec = now // 1_000_000_000
    if (now_sec < record.get("started_monotonic_seconds", 0)
            or now_sec >= record["started_monotonic_seconds"] + MAX_SECONDS - 30
            or now_sec - record.get("last_monotonic_seconds", 0) > 60):
        raise SystemdBackendError("fresh worker start passed deadline/heartbeat")
    _timer_active(backend.systemd, now // 1000)
    expected_phase = ("armed-idle" if grant["kind"] == "canary"
                      else "canary-clean-idle")
    if (type(phase) is not dict or phase.get("schema") != PHASE_SCHEMA
            or phase.get("phase") != expected_phase
            or any(phase.get(k) != grant[k] for k in (
                "host_id","boot_id","project_root","request_id","plan_sha256"))
            or phase.get("pending_job") is not None):
        raise SystemdBackendError("fresh worker phase not idle or identity changed")
    if grant["kind"] == "canary":
        if grant["canary_receipt_sha256"] is not None:
            raise SystemdBackendError("fresh canary cannot reuse acceptance")
    elif (not isinstance(grant["canary_receipt_sha256"], str)
          or not re.fullmatch(r"sha256:[0-9a-f]{64}",
                              grant["canary_receipt_sha256"])):
        raise SystemdBackendError("compiler start lacks accepted canary")
    path = STATE / ("fresh-" + grant["kind"] + "-claim.json")
    intent = {k: grant[k] for k in (
        "kind","host_id","boot_id","project_root","request_id",
        "plan_sha256","job_id","request_sha256")}
    intent.update({"schema": CLAIM_SCHEMA, "attempt_monotonic_ns": now})
    _write_once(path, intent)
    _update_phase({
        **phase, "phase": grant["kind"] + "-start-attempted",
        "pending_job": intent, "last_worker_job_id": job_id,
    })
    return intent
