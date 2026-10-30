"""Fresh privileged worker starts need host-owned budget, timer and claim."""
import hashlib
import json
import time
from types import SimpleNamespace

import pytest

from zog.root_control import fresh_start_gate as gate
from zog.root_control.systemd import SystemdBackendError
from zog.root_control.build import BuildBackend, FRESH_COMPILER_PARENT_SLICE


REQ = "a" * 32
JOB = "c" * 32
BIND = {"host_id": "i-exact", "boot_id": "boot-1",
        "project_root": "/home/controller/fresh-cross-bootstrap-oct25",
        "request_id": REQ, "plan_sha256": "sha256:"+"a"*64}
REQUEST = {
    "build_root_id": "b"*32,
    "source_workspace_id": "b"*32+"-source",
    "output_workspace_id": "b"*32+"-output",
    "command": ["/usr/bin/sleep", "30"],
    "environment": {"PATH": "/usr/bin:/bin"},
    "working_directory": "/", "execution_user_id": 24302,
    "execution_group_id": 24302,
    "startup_timeout_seconds": 5,
    "execution_timeout_seconds": 40,
    "termination_grace_seconds": 3,
    "resource_limits": {
        "thread-count-maximum": 16,
        "memory-maximum-bytes": 134217728,
    },
    "read_only_root": True, "network_access": False,
}


def fixture(monkeypatch, *, kind="canary"):
    now = time.monotonic_ns()
    state = {
        gate.GRANT: {
            "schema": gate.GRANT_SCHEMA, "kind": kind,
            **BIND, "budget_scope": gate.SCOPE, "job_id": JOB,
            "request_sha256": gate.digest_request(REQUEST),
            "canary_receipt_sha256": None if kind=="canary" else
                "sha256:"+"f"*64,
        },
        gate.PHASE: {
            "schema": gate.PHASE_SCHEMA, **BIND,
            "phase": "armed-idle" if kind=="canary" else "canary-clean-idle",
            "pending_job": None,
        },
        gate.BUDGET / (REQ+".json"): {
            "schema": gate.BUDGET_SCHEMA, **{k:BIND[k] for k in
                ("host_id","boot_id","project_root","request_id")},
            "sidecar_plan_sha256": BIND["plan_sha256"],
            "status": "active",
            "started_monotonic_seconds": now//1_000_000_000-10,
            "last_monotonic_seconds": now//1_000_000_000,
        },
    }
    writes = []
    def put(p, data):
        if p in state:
            raise FileExistsError(p)
        state[p] = data
        writes.append(p)
    monkeypatch.setattr(gate, "_read", lambda p: state[p])
    monkeypatch.setattr(gate, "_write_once", put)
    monkeypatch.setattr(gate, "_update_phase", lambda obj: state.__setitem__(
        gate.PHASE, obj))
    monkeypatch.setattr(gate, "_timer_active", lambda *_: None)
    monkeypatch.setattr(gate, "hugetlb_ready", lambda: True)
    monkeypatch.setattr(gate, "_boot", lambda: "boot-1")
    monkeypatch.setattr(gate.os, "geteuid", lambda: 0)
    backend = SimpleNamespace(parent_slice=FRESH_COMPILER_PARENT_SLICE,
          authorized_project_root=BIND["project_root"],
          systemd=SimpleNamespace())
    return backend, state, writes


def test_one_exact_canary_claim_is_durable_before_pid1(monkeypatch):
    backend, state, writes = fixture(monkeypatch)
    claim = gate.claim(backend=backend, project_root=BIND["project_root"],
                       job_id=JOB, request=REQUEST)
    assert writes == [gate.STATE / "fresh-canary-claim.json"]
    assert claim["request_sha256"] == gate.digest_request(REQUEST)
    assert state[gate.PHASE]["phase"] == "canary-start-attempted"
    assert state[gate.PHASE]["pending_job"] == claim
    with pytest.raises(SystemdBackendError, match="phase not idle"):
        gate.claim(backend=backend, project_root=BIND["project_root"],
                   job_id=JOB, request=REQUEST)


@pytest.mark.parametrize("change", [
    {"job_id": "d"*32},
    {"request_sha256": "sha256:"+"0"*64},
    {"boot_id": "stale"},
    {"budget_scope": "strict-host-total"},
])
def test_grant_substitution_fails_before_claim(monkeypatch, change):
    backend, state, writes = fixture(monkeypatch)
    state[gate.GRANT].update(change)
    with pytest.raises(SystemdBackendError):
        gate.claim(backend=backend, project_root=BIND["project_root"],
                   job_id=JOB, request=REQUEST)
    assert writes == []


def test_wrong_budget_and_deadline_cannot_start(monkeypatch):
    backend, state, writes = fixture(monkeypatch)
    state[gate.BUDGET / (REQ+".json")]["status"] = "stop_requested"
    with pytest.raises(SystemdBackendError, match="budget"):
        gate.claim(backend=backend, project_root=BIND["project_root"],
                   job_id=JOB, request=REQUEST)
    state[gate.BUDGET / (REQ+".json")]["status"] = "active"
    monkeypatch.setattr(gate, "_timer_active", lambda *_: (_ for _ in ()).throw(
        SystemdBackendError("expired")))
    with pytest.raises(SystemdBackendError, match="expired"):
        gate.claim(backend=backend, project_root=BIND["project_root"],
                   job_id=JOB, request=REQUEST)
    assert writes == []


def test_compiler_requires_canary_acceptance(monkeypatch):
    backend, state, writes = fixture(monkeypatch, kind="compiler")
    state[gate.GRANT]["canary_receipt_sha256"] = None
    with pytest.raises(SystemdBackendError, match="accepted canary"):
        gate.claim(backend=backend, project_root=BIND["project_root"],
                   job_id=JOB, request=REQUEST)
    assert writes == []


def test_build_start_checks_gate_before_prepare_or_pid1(monkeypatch):
    import inspect
    code = inspect.getsource(BuildBackend.start)
    assert "start_gate.claim(" in code
    assert code.index("start_gate.claim(") < code.index(
        "self._start_after_protected_claim(")
    assert "with start_gate.locked()" in code
    assert "start_attempted" in inspect.getsource(
        BuildBackend._start_after_protected_claim)


def test_hugetlb_prestart_requires_zero_limits_and_live_root_controller(tmp_path, monkeypatch):
    base = tmp_path / "cgroup"
    target = base / gate.FRESH_COMPILER_PARENT_SLICE
    target.mkdir(parents=True)
    (base / "cgroup.subtree_control").write_text("cpu hugetlb")
    (base / "cgroup.controllers").write_text("cpu hugetlb memory")
    (target / "cgroup.controllers").write_text("hugetlb memory")
    (target / "hugetlb.2MB.max").write_text("0")
    (target / "hugetlb.2MB.rsvd.max").write_text("0")
    monkeypatch.setattr(gate, "HUGETLB_ROOT", base)
    # Simulate exact native root ownership; GitHub runners are nonroot.
    from pathlib import Path
    from types import SimpleNamespace
    original_lstat = Path.lstat
    def root_owned(path, *args, **kwargs):
        st = original_lstat(path, *args, **kwargs)
        if path in (base, target):
            return SimpleNamespace(st_mode=st.st_mode, st_uid=0,
                                   st_gid=0, st_dev=st.st_dev)
        return st
    monkeypatch.setattr(Path, "lstat", root_owned)
    # The normal test tree is not the host's real cgroup2 mount.
    monkeypatch.setattr(gate, "_hugetlb_mountinfo", lambda:
        f"30 1 0:40 / {base} rw - cgroup2 cgroup rw")
    real_stat = Path.stat
    def pid1_namespace(path, *args, **kwargs):
        if str(path) in ("/proc/self/ns/cgroup", "/proc/1/ns/cgroup"):
            return SimpleNamespace(st_dev=42, st_ino=31415)
        return real_stat(path, *args, **kwargs)
    monkeypatch.setattr(Path, "stat", pid1_namespace)
    assert gate.hugetlb_ready() is True
    monkeypatch.setattr(gate, "_hugetlb_mountinfo", lambda:
        f"30 1 0:40 /foreign {base} rw - cgroup2 cgroup rw")
    with pytest.raises(gate.SystemdBackendError, match="host-root cgroup2"):
        gate.hugetlb_ready()
    monkeypatch.setattr(gate, "_hugetlb_mountinfo", lambda:
        f"30 1 0:40 / {base} rw - tmpfs none rw")
    with pytest.raises(gate.SystemdBackendError, match="host-root cgroup2"):
        gate.hugetlb_ready()
    monkeypatch.setattr(gate, "_hugetlb_mountinfo", lambda:
        f"30 1 0:40 / {base} rw - cgroup2 cgroup rw")
    def foreign_namespace(path, *args, **kwargs):
        if str(path) in ("/proc/self/ns/cgroup", "/proc/1/ns/cgroup"):
            return SimpleNamespace(st_dev=42, st_ino=(
                31416 if str(path).startswith("/proc/self/") else 31415))
        return real_stat(path, *args, **kwargs)
    monkeypatch.setattr(Path, "stat", foreign_namespace)
    with pytest.raises(gate.SystemdBackendError, match="PID1 cgroup namespace"):
        gate.hugetlb_ready()
    monkeypatch.setattr(Path, "stat", pid1_namespace)
    assert gate.hugetlb_ready() is True
    target.chmod(0o777)
    with pytest.raises(gate.SystemdBackendError, match="untrusted HugeTLB"):
        gate.hugetlb_ready()
    target.chmod(0o755)
    assert gate.hugetlb_ready() is True
    (base / "cgroup.subtree_control").write_text("cpu")
    with pytest.raises(gate.SystemdBackendError, match="ancestor"):
        gate.hugetlb_ready()
    (base / "cgroup.subtree_control").write_text("cpu hugetlb")
    (target / "hugetlb.2MB.rsvd.max").write_text("max")
    with pytest.raises(gate.SystemdBackendError, match="not zero"):
        gate.hugetlb_ready()
    (target / "hugetlb.2MB.rsvd.max").unlink()
    with pytest.raises(gate.SystemdBackendError, match="reservation"):
        gate.hugetlb_ready()


def test_hugetlb_prestart_is_checked_before_and_after_one_time_claim(monkeypatch):
    backend, state, writes = fixture(monkeypatch)
    monkeypatch.setattr(gate, "hugetlb_ready", lambda: (_ for _ in ()).throw(
        gate.SystemdBackendError("HugeTLB not ready")))
    with pytest.raises(gate.SystemdBackendError, match="HugeTLB"):
        gate.claim(backend=backend, project_root=BIND["project_root"],
                   job_id=JOB, request=REQUEST)
    assert writes == []
    monkeypatch.setattr(gate, "hugetlb_ready", lambda: True)
    gate.claim(backend=backend, project_root=BIND["project_root"],
               job_id=JOB, request=REQUEST)
    monkeypatch.setattr(gate, "hugetlb_ready", lambda: (_ for _ in ()).throw(
        gate.SystemdBackendError("HugeTLB lost before PID1")))
    with pytest.raises(gate.SystemdBackendError, match="HugeTLB"):
        gate.revalidate_before_pid1(backend=backend, job_id=JOB)
