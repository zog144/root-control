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
