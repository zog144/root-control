"""Read-only fresh-root-control empty-lane PID1 witness.

An empty worker inventory is NOT an authorization to start a compiler.
This verifies that every process in the exact fresh parent slice belongs to
the pinned root-control sidecar before the timer/ledger are armed; any worker,
unknown PID, or cgroup race is a NO-GO. No systemd mutations, RPC or grant.
"""
import os
from pathlib import Path

from .build import FRESH_COMPILER_PARENT_SLICE, FRESH_COMPILER_PROJECT

SCHEMA = "root-control-fresh-empty-lane-witness-v1"
CONTROLLER_UNIT = "zog-fresh-cross-bootstrap-oct25-controller.service"
CONTROLLER_GROUP = "/" + FRESH_COMPILER_PARENT_SLICE + "/" + CONTROLLER_UNIT
CGROUP_ROOT = Path("/sys/fs/cgroup") / FRESH_COMPILER_PARENT_SLICE
MAX_PROCESSES = 512


def _read(path, limit=65536):
    with open(path, "rb") as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise RuntimeError("fresh empty-lane kernel observation too large")
    return data.decode("utf-8")


def _census():
    if CGROUP_ROOT.is_symlink() or not CGROUP_ROOT.is_dir():
        raise RuntimeError("fresh compiler parent slice absent")
    found = set()
    for parent, dirs, _ in os.walk(CGROUP_ROOT, followlinks=False):
        if any((Path(parent) / d).is_symlink() for d in dirs):
            raise RuntimeError("symlinked fresh compiler sub-cgroup")
        for line in _read(Path(parent) / "cgroup.procs").splitlines():
            if not line.isdecimal() or int(line) < 2:
                raise RuntimeError("invalid fresh PID census")
            found.add(int(line))
            if len(found) > MAX_PROCESSES:
                raise RuntimeError("fresh PID census exceeds protected bound")
    return tuple(sorted(found))


def inspect(*, backend, project_root):
    """Read-only native EMPTY evidence; never a future-worker attestation."""
    if (backend.parent_slice != FRESH_COMPILER_PARENT_SLICE
            or backend.authorized_project_root != project_root
            or Path(project_root).name != FRESH_COMPILER_PROJECT):
        raise PermissionError("fresh empty-lane role and Project differ")
    if os.geteuid() != 0:
        raise PermissionError("native empty-lane evidence needs protected root")
    backend._verify_active_parent()
    obj = backend.systemd._get_unit_path(CONTROLLER_UNIT)
    if obj is None:
        raise RuntimeError("native fresh controller unit missing")
    from .systemd import _UNIT_IFACE, _SERVICE_IFACE
    pid = backend.systemd._get_property(obj, _SERVICE_IFACE, "MainPID")
    group = backend.systemd._get_property(obj, _UNIT_IFACE, "ControlGroup")
    if type(pid) is not int or pid < 2 or group != CONTROLLER_GROUP:
        raise RuntimeError("native fresh controller PID/cgroup mismatch")
    first = _census()
    if first != (pid,):
        raise RuntimeError("empty fresh lane contains missing or foreign worker")
    if (_read(Path("/proc") / str(pid) / "cgroup").strip() != "0::" + group
            or _read("/proc/sys/kernel/random/boot_id").strip() == ""):
        raise RuntimeError("controller kernel identity changed")
    second = _census()
    if first != second:
        raise RuntimeError("fresh worker appeared during idle observation")
    return {
        "schema": SCHEMA, "status": "native-empty-only-not-admission",
        "project_root": project_root, "parent_slice": FRESH_COMPILER_PARENT_SLICE,
        "controller_pid": pid, "boot_id": _read(
            "/proc/sys/kernel/random/boot_id").strip(),
        "processes": list(first), "future_workers_verified": False,
    }
