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
        if str(self).startswith("/proc/411/root"):
            return SimpleNamespace(st_dev=dev, st_mode=stat.S_IFDIR | 0o700)
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
        f"10 1 {d} / {path} {flags},relatime - {fstype} source rw"
        for path,(d,flags,fstype) in entries.items())+"\n"
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
