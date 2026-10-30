"""Fresh-only kernel worker witness: explicit negative and live-source contract."""
import os
from pathlib import Path
import stat
from types import SimpleNamespace
import inspect

import pytest

from zog.root_control import fresh_native_worker_witness as witness
from zog.root_control.build import BuildBackend, FRESH_COMPILER_PARENT_SLICE


def _fixture():
    expected = witness.FRESH_COMPILER_BUILD_MOUNT / (
        "controller-build-resources/a/b/root")
    class Backend:
        parent_slice = FRESH_COMPILER_PARENT_SLICE
        def _pid1_resource_path(self, path, *, fresh):
            assert fresh
            return expected
    project = "/home/zog-cross-owner/fresh-cross-bootstrap-oct25"
    info = {"job_id": "a"*32,
            "request": {"build_root_id": "b"*32,
                        "execution_user_id": 24302,
                        "execution_group_id": 24302}}
    observation = {"exists": True, "active_state": "active",
                   "main_pid": 411,
                   "control_group": f"/{FRESH_COMPILER_PARENT_SLICE}/worker.slice/worker.service",
                   "invocation_id": "native-invocation"}
    return Backend(), project, expected.parent, info, observation, expected


def test_role_and_mainpid_are_obligatory():
    backend, project, path, info, observed, _ = _fixture()
    backend.parent_slice = None
    with pytest.raises(PermissionError, match="fresh build-only"):
        witness.inspect(backend=backend, project_root=project, path=path,
                        info=info, observed=observed)
    backend.parent_slice = FRESH_COMPILER_PARENT_SLICE
    with pytest.raises(RuntimeError, match="not actually running"):
        witness.inspect(backend=backend, project_root=project, path=path,
                        info=info, observed={**observed, "main_pid": 0})
    with pytest.raises(RuntimeError, match="not actually running"):
        witness.inspect(backend=backend, project_root="/old/Project",
                        path=path, info=info, observed=observed)


def _native(monkeypatch, *, wrong_root=False, foreign=False, bad_swap=False):
    backend, project, path, info, obs, expected = _fixture()
    dev = os.makedev(7, 5)
    original_stat = Path.stat
    def fake_stat(self, *args, **kwargs):
        if str(self) == str(witness.FRESH_COMPILER_BUILD_MOUNT):
            return SimpleNamespace(st_dev=dev)
        if str(self) == str(expected):
            return SimpleNamespace(st_dev=dev, st_ino=1400,
                                   st_mode=stat.S_IFDIR | 0o700)
        if str(self).startswith("/proc/411/root"):
            return SimpleNamespace(st_dev=dev,
                                   st_ino=1401 if wrong_root else 1400,
                                   st_mode=stat.S_IFDIR | 0o700)
        return original_stat(self, *args, **kwargs)
    monkeypatch.setattr(Path, "stat", fake_stat)
    monkeypatch.setattr(witness.os, "readlink", lambda p:
                        "/old/Project/root" if wrong_root else str(expected))
    entries = {"/": ("7:5", "ro", "ext4")}
    for target in witness._TARGETS:
        entries[target] = ("7:5", "rw", "ext4")
    entries["/dev"] = ("0:13", "rw", "tmpfs")
    if foreign:
        entries["/foreign"] = ("8:1", "rw", "ext4")
    mountinfo = "\n".join(
        f"{10 + index} {1 if target == '/' else 10} {d} / {target} {flags},relatime - {fstype} source rw"
        for index, (target,(d,flags,fstype)) in enumerate(entries.items()))+"\n"
    def fake_read(p, limit=262144):
        p = str(p)
        if p.endswith("/cgroup"):
            return "0::" + obs["control_group"] + "\n"
        if p.endswith("/status"):
            return "Uid:\t24302\t24302\t24302\t24302\nGid:\t24302\t24302\t24302\t24302\n"
        if p.endswith("/mountinfo"):
            return mountinfo
        if p.endswith("memory.swap.max"):
            return "1" if bad_swap else "0"
        if p.endswith("memory.max"):
            return "100000"
        if p.endswith("/boot_id"):
            return "boot-exact"
        pytest.fail("unapproved fixed kernel read "+p)
    monkeypatch.setattr(witness, "_read", fake_read)
    return backend, project, path, info, obs


def test_positive_witness_is_evidence_not_admission(monkeypatch):
    b, project, path, info, observed = _native(monkeypatch)
    result = witness.inspect(backend=b, project_root=project, path=path,
                             info=info, observed=observed)
    assert result["status"] == "live-process-only-not-admission"
    assert result["main_pid"] == 411
    assert result["future_workers_verified"] is False
    assert result["boot_id"] == "boot-exact"


@pytest.mark.parametrize("tamper", ["wrong_root", "foreign", "bad_swap"])
def test_native_witness_rejects_foreign_backing_or_swap(monkeypatch, tamper):
    b, project, path, info, observed = _native(
        monkeypatch, **{tamper: True})
    with pytest.raises(RuntimeError):
        witness.inspect(backend=b, project_root=project, path=path,
                        info=info, observed=observed)


def test_build_backend_exposes_only_observed_durable_worker():
    code = inspect.getsource(BuildBackend.inspect_fresh_worker_native)
    assert "self.load(project_root, build_root_id)" in code
    assert "self.observe(project_root=project_root" in code
    assert "from .fresh_native_worker_witness import inspect" in code
    assert ".start(" not in code


def test_stacked_mounts_choose_kernel_top_and_reject_unaccounted_layers():
    lines = [
        "10 1 7:5 / / ro - ext4 image ro",
        "20 10 7:5 / /tmp rw - ext4 image rw",
        "22 20 7:5 / /tmp rw - ext4 image rw",
        "23 10 0:12 / /dev rw - tmpfs tmpfs rw",
    ]
    visible, all_entries = witness._mount_inventory("\n".join(reversed(lines)))
    assert visible["/tmp"]["id"] == 22
    assert len(all_entries) == 4
    assert sum(m["point"] == "/tmp" for m in all_entries) == 2
    # A hidden foreign writable backing must NOT disappear from the review.
    foreign = list(lines)
    foreign[1] = "20 10 8:1 / /tmp rw - ext4 host rw"
    visible, rows = witness._mount_inventory("\n".join(foreign))
    assert visible["/tmp"]["device"] == "7:5"
    assert any(m["device"] == "8:1" and witness._writable(m) for m in rows)
    with pytest.raises(RuntimeError, match="ambiguous"):
        witness._mount_inventory(
            "\n".join(lines + ["24 10 7:5 / /tmp rw - ext4 image rw"]))
    with pytest.raises(RuntimeError, match="corrupt"):
        witness._mount_inventory(
            "\n".join(lines + ["24 24 7:5 / /tmp rw - ext4 image rw"]))


@pytest.mark.parametrize("target,fstype", [
    ("/dev/hugepages", "hugetlbfs"),
    ("/dev/hugepages/hugepages-2MB", "hugetlbfs"),
    ("/foreign-pseudomount", "tmpfs"),
])
def test_unaccounted_pseudo_writes_fail_closed(monkeypatch, target, fstype):
    b, project, path, info, observed = _native(monkeypatch)
    base = witness._read
    def extra(path, limit=262144):
        text = base(path, limit)
        if str(path).endswith("/mountinfo"):
            return text + f"199 {16 if target.startswith('/dev/') else 10} 0:45 / {target} rw - {fstype} none rw\n"
        return text
    monkeypatch.setattr(witness, "_read", extra)
    with pytest.raises(RuntimeError, match="writable|foreign"):
        witness.inspect(backend=b, project_root=project, path=path,
                        info=info, observed=observed)


def test_same_device_different_inode_never_proves_worker_root(monkeypatch):
    b, project, path, info, observed = _native(monkeypatch, wrong_root=True)
    with pytest.raises(RuntimeError, match="inode"):
        witness.inspect(backend=b, project_root=project, path=path,
                        info=info, observed=observed)

def test_ancestor_overmount_excludes_hidden_hugetlb_and_old_devpts():
    rows = "\n".join([
        "10 1 7:5 / / ro - ext4 image ro",
        "20 10 0:3 / /dev rw - devtmpfs old rw",
        "21 20 0:8 / /dev/hugepages rw - hugetlbfs huge rw",
        "22 20 0:9 / /dev/pts rw - devpts old rw",
        "30 20 0:12 / /dev rw - tmpfs new rw",
        "31 30 0:13 / /dev/shm rw - tmpfs shm rw",
    ])
    visible, all_rows = witness._mount_inventory(rows)
    assert visible["/dev"]["id"] == 30
    assert visible["/dev/shm"]["id"] == 31
    assert "/dev/hugepages" not in visible
    assert "/dev/pts" not in visible
    assert any(row["fstype"] == "hugetlbfs" for row in all_rows)


def test_fresh_unit_masks_hugetlb_without_weakening_other_workers():
    import inspect
    from zog.root_control.build import BuildBackend
    source = inspect.getsource(BuildBackend._start_after_protected_claim)
    assert "'InaccessiblePaths', 'as', 2" in source
    assert "-/dev/hugepages" in source
    assert "if self.parent_slice is not None:" in source
