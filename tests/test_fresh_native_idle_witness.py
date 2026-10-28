"""Trusted fresh idle evidence cannot be mistaken for launch authority."""
from types import SimpleNamespace

import pytest

from zog.root_control import fresh_native_idle_witness as idle
from zog.root_control.build import BuildBackend, FRESH_COMPILER_PARENT_SLICE


def backend():
    calls = []
    class S:
        def _get_unit_path(self, name):
            assert name == idle.CONTROLLER_UNIT
            return "/org/test/service"
        def _get_property(self, path, iface, key):
            if key == "MainPID":
                return 412
            if key == "ControlGroup":
                return idle.CONTROLLER_GROUP
            raise AssertionError(key)
    b = SimpleNamespace(parent_slice=FRESH_COMPILER_PARENT_SLICE,
                        authorized_project_root="/x/" + idle.FRESH_COMPILER_PROJECT,
                        systemd=S(), _verify_active_parent=lambda: calls.append("parent"))
    return b, calls


def setup(monkeypatch):
    b, calls = backend()
    monkeypatch.setattr(idle.os, "geteuid", lambda: 0)
    monkeypatch.setattr(idle, "_census", lambda: (412,))
    monkeypatch.setattr(idle, "_read", lambda path, **k: (
        "0::" + idle.CONTROLLER_GROUP if str(path).endswith("/412/cgroup")
        else "b" * 36))
    return b, calls


def test_exact_empty_lane_is_observation_only(monkeypatch):
    b, calls = setup(monkeypatch)
    result = idle.inspect(backend=b, project_root=b.authorized_project_root)
    assert result["status"] == "native-empty-only-not-admission"
    assert result["future_workers_verified"] is False
    assert result["processes"] == [412]
    assert calls == ["parent"]


@pytest.mark.parametrize("census", [(412, 500), (), (500,)])
def test_foreign_or_missing_worker_never_counts_as_idle(monkeypatch, census):
    b, _ = setup(monkeypatch)
    monkeypatch.setattr(idle, "_census", lambda: census)
    with pytest.raises(RuntimeError, match="empty fresh lane"):
        idle.inspect(backend=b, project_root=b.authorized_project_root)


def test_second_census_catches_racing_start(monkeypatch):
    b, _ = setup(monkeypatch)
    seen = iter([(412,), (412, 501)])
    monkeypatch.setattr(idle, "_census", lambda: next(seen))
    with pytest.raises(RuntimeError, match="appeared during idle"):
        idle.inspect(backend=b, project_root=b.authorized_project_root)


def test_stale_project_wrong_role_and_unprivileged_rejected(monkeypatch):
    b, _ = setup(monkeypatch)
    with pytest.raises(PermissionError):
        idle.inspect(backend=b, project_root="/old")
    b.parent_slice = None
    with pytest.raises(PermissionError):
        idle.inspect(backend=b, project_root=b.authorized_project_root)
    b.parent_slice = FRESH_COMPILER_PARENT_SLICE
    monkeypatch.setattr(idle.os, "geteuid", lambda: 1000)
    with pytest.raises(PermissionError):
        idle.inspect(backend=b, project_root=b.authorized_project_root)


def test_build_backend_entrypoint_is_not_a_launch_gate():
    import inspect
    code = inspect.getsource(BuildBackend.inspect_fresh_idle_native)
    assert "fresh_native_idle_witness" in code
    assert "start(" not in code
    assert "submit" not in code
    assert "future_workers_verified" in inspect.getsource(idle.inspect)
