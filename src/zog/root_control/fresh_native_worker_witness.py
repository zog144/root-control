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



def _mount_inventory(raw):
    """Resolve Linux mount stacks by mount ID/parent ID, not line order.

    Return the visible mount at each pathname and *all* kernel entries, so a
    hidden foreign writer cannot be silently discarded. Reject broken or
    ambiguous parent chains rather than guessing which layer is accessible.
    """
    entries = {}
    by_point = {}
    for line in raw.splitlines():
        f = line.split()
        if "-" not in f:
            raise RuntimeError("malformed worker kernel mount")
        n = f.index("-")
        if (n < 6 or len(f) < n + 4 or not f[0].isdecimal()
                or not f[1].isdecimal()
                or not f[2].replace(":", "").isdecimal()
                or f[2].count(":") != 1
                or not f[3].startswith("/") or "\\" in f[3]
                or not f[4].startswith("/") or "\\" in f[4]
                or int(f[0]) in entries):
            raise RuntimeError("invalid native worker mount")
        flags = frozenset(f[5].split(","))
        super_flags = frozenset(f[n + 3].split(","))
        if not (flags & {"rw", "ro"}) or not (super_flags & {"rw", "ro"}):
            raise RuntimeError("worker mount missing read/write attributes")
        row = {"id": int(f[0]), "parent": int(f[1]),
               "device": f[2], "flags": flags, "super_flags": super_flags,
               "fstype": f[n + 1], "point": f[4]}
        entries[row["id"]] = row
        by_point.setdefault(f[4], []).append(row)
        if len(entries) > 512:
            raise RuntimeError("worker mount inventory exceeds limit")
    if "/" not in by_point:
        raise RuntimeError("worker root mount missing")
    visible = {}
    for point, layers in by_point.items():
        ids = {x["id"] for x in layers}
        parents = {x["parent"] for x in layers if x["parent"] in ids}
        top = [x for x in layers if x["id"] not in parents]
        if len(top) != 1:
            raise RuntimeError("ambiguous native mount stack: " + point)
        visited = set()
        cursor = top[0]
        while cursor["id"] not in visited:
            visited.add(cursor["id"])
            if cursor["parent"] not in ids:
                break
            cursor = entries[cursor["parent"]]
        if visited != ids:
            raise RuntimeError("disconnected native mount stack: " + point)
        visible[point] = top[0]
    return visible, tuple(entries.values())


def _writable(mount):
    return "rw" in mount["flags"] and "rw" in mount["super_flags"]

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
    # A /proc/<PID>/root symlink string is not an inode witness. The host
    # imported directory and the live process root must be the *same* object.
    expected_st = expected.stat()
    root_st = root.stat()
    if (expected.is_symlink() or not stat.S_ISDIR(expected_st.st_mode)
            or not stat.S_ISDIR(root_st.st_mode)
            or (root_st.st_dev, root_st.st_ino) !=
               (expected_st.st_dev, expected_st.st_ino)
            or root_st.st_dev != FRESH_COMPILER_BUILD_MOUNT.stat().st_dev):
        raise RuntimeError("live RootDirectory inode differs from quota-backed import")
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
    mounts, all_mounts = _mount_inventory(
        _read(Path("/proc") / str(pid) / "mountinfo"))
    for target in _TARGETS:
        m = mounts.get(target)
        if not m or m["device"] != majmin or not _writable(m):
            raise RuntimeError("native worker has unbounded writable path: " + target)
        st = (root / target.lstrip("/")).stat()
        if not stat.S_ISDIR(st.st_mode) or st.st_dev != dev:
            raise RuntimeError("worker writable mount redirected: " + target)
    # Consider every mount layer, not just the visible mount at a duplicate
    # point. A hidden writable non-quota mount is not evidence of containment.
    for m in all_mounts:
        if not _writable(m):
            continue
        target = m["point"]
        if m["fstype"] == "hugetlbfs" or target == "/dev/hugepages" or target.startswith("/dev/hugepages/"):
            raise RuntimeError("writable hugepage mount has no dedicated quota: " + target)
        if m["device"] != majmin and m["fstype"] not in _ALLOWED_PSEUDO.get(target, ()):
            raise RuntimeError("native worker has foreign writable mount: " + target)
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
        "mount_count": len(all_mounts), "future_workers_verified": False,
    }
