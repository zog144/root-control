"""Read-only kernel witness for the exact fresh build-only worker.

Never trust a controller's string saying "verified": BuildBackend.observe()
must first compare the frozen PID1 properties, and this module independently
checks the actual MainPID, mountinfo, cgroup, boot, UID/GID and swap. It
neither starts a job nor grants host-deploy admission; its receipt is only
evidence about the *currently observed* process on this boot.
"""
import os
from pathlib import Path
import stat

from .build import (
    FRESH_COMPILER_PROJECT, FRESH_COMPILER_PARENT_SLICE,
    FRESH_COMPILER_BUILD_MOUNT,
)

SCHEMA = "root-control-fresh-live-worker-witness-v1"
_TARGETS = ("/image-build/source", "/image-build/output", "/tmp", "/var/tmp", "/run")
_ALLOWED_PSEUDO = {
    "/dev": {"tmpfs", "devtmpfs"}, "/dev/pts": {"devpts"},
    "/dev/shm": {"tmpfs"}, "/dev/mqueue": {"mqueue"},
    "/proc": {"proc"}, "/sys": {"sysfs"}, "/sys/fs/cgroup": {"cgroup2"},
}


def _read(path, limit=262144):
    with open(path, "rb") as fd:
        value = fd.read(limit + 1)
    if len(value) > limit:
        raise RuntimeError("native worker evidence exceeds fixed limit")
    return value.decode("utf-8")


def inspect(*, backend, project_root, path, info, observed):
    if backend.parent_slice != FRESH_COMPILER_PARENT_SLICE:
        raise PermissionError("native witness available only to fresh build-only role")
    if (Path(project_root).name != FRESH_COMPILER_PROJECT
            or not observed.get("exists")
            or observed.get("active_state") != "active"
            or type(observed.get("main_pid")) is not int
            or observed["main_pid"] < 2):
        raise RuntimeError("finite fresh worker is not actually running")
    pid = observed["main_pid"]
    expected = backend._pid1_resource_path(path / "root", fresh=True)
    root = Path("/proc") / str(pid) / "root"
    if (os.readlink(root) != str(expected)
            or root.stat().st_dev != FRESH_COMPILER_BUILD_MOUNT.stat().st_dev):
        raise RuntimeError("live RootDirectory is not the quota-backed import")
    cg = _read(Path("/proc") / str(pid) / "cgroup").splitlines()
    if len(cg) != 1 or not cg[0].startswith("0::/"):
        raise RuntimeError("worker lacks unified native cgroup")
    value = cg[0][3:]
    if (value != observed.get("control_group")
            or not value.startswith("/" + FRESH_COMPILER_PARENT_SLICE + "/")):
        raise RuntimeError("worker has unexpected cgroup or parent")
    ids = {}
    for line in _read(Path("/proc") / str(pid) / "status").splitlines():
        if line.startswith(("Uid:", "Gid:")):
            key, raw = line.split(":", 1)
            ids[key] = raw.split()
    request = info["request"]
    if (ids.get("Uid") != [str(request["execution_user_id"])] * 4
            or ids.get("Gid") != [str(request["execution_group_id"])] * 4):
        raise RuntimeError("worker effective identity changed")
    dev = FRESH_COMPILER_BUILD_MOUNT.stat().st_dev
    majmin = f"{os.major(dev)}:{os.minor(dev)}"
    mounts = {}
    for line in _read(Path("/proc") / str(pid) / "mountinfo").splitlines():
        f = line.split()
        if "-" not in f:
            raise RuntimeError("malformed worker kernel mount")
        n = f.index("-")
        if n < 6 or len(f) < n + 3 or "\\" in f[4] or f[4] in mounts:
            raise RuntimeError("invalid native worker mount")
        mounts[f[4]] = (f[2], set(f[5].split(",")), f[n + 1])
        if len(mounts) > 512:
            raise RuntimeError("worker mount inventory exceeds limit")
    for target in _TARGETS:
        m = mounts.get(target)
        if not m or m[0] != majmin or "rw" not in m[1]:
            raise RuntimeError("native worker has unbounded writable path: " + target)
        st = (root / target.lstrip("/")).stat()
        if not stat.S_ISDIR(st.st_mode) or st.st_dev != dev:
            raise RuntimeError("worker writable mount redirected: " + target)
    for mount, (device, options, fstype) in mounts.items():
        if "rw" in options and device != majmin and fstype not in _ALLOWED_PSEUDO.get(mount, ()):
            raise RuntimeError("native worker has foreign writable mount: " + mount)
    cgpath = Path("/sys/fs/cgroup") / value.lstrip("/")
    if (_read(cgpath / "memory.swap.max").strip() != "0"
            or not _read(cgpath / "memory.max").strip().isdecimal()):
        raise RuntimeError("native worker memory/swap confinement not attested")
    return {
        "schema": SCHEMA, "status": "live-process-only-not-admission",
        "project_root": project_root, "job_id": info["job_id"],
        "build_root_id": info["request"]["build_root_id"],
        "main_pid": pid, "invocation_id": observed["invocation_id"],
        "boot_id": _read("/proc/sys/kernel/random/boot_id").strip(),
        "control_group": value, "image_device": majmin,
        "mount_count": len(mounts), "future_workers_verified": False,
    }
