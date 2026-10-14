"""Root-control must independently revalidate trusted certificate policy binds."""
from pathlib import Path

import pytest

from zog.box_control import host_bindings
from zog.root_control.systemd import BusctlSystemdBackend, SystemdBackendError


def _definition(project, policy):
    unit = f"zog-{project.name}-RUNTIME1-renew.service"
    expected = {
        "capability": "certify-policy",
        "source": "/etc/zog/certify-policy",
        "destination": "/run/zog-host/certify-policy",
        "access": "read-only",
        "source_device": 6,
        "source_inode": 7,
        "policy_digest": "sha256:" + "a" * 64,
    }
    return dict(
        application_name="certify-manage", program_name="renew",
        runtime_id="RUNTIME1", unit_name=unit,
        host_bindings=[expected],
        read_only_bind_paths=[
            ["/etc/zog/certify-policy", "/run/zog-host/certify-policy"]
        ],
    ), expected


def test_privileged_mechanism_accepts_exact_policy_snapshot(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    definition, expected = _definition(project, None)
    monkeypatch.setattr(host_bindings, "resolve", lambda *args: (expected,))
    result = BusctlSystemdBackend._validate_host_bindings(project, definition)
    assert result == [["/etc/zog/certify-policy", "/run/zog-host/certify-policy"]]


@pytest.mark.parametrize("change", [
    {"policy_digest": "sha256:" + "b" * 64},
    {"source_inode": 8},
    {"source_device": 8},
    {"source": "/etc/zog/other-policy"},
    {"access": "read-write"},
])
def test_privileged_rejects_forged_or_stale_policy_reference(tmp_path, monkeypatch, change):
    project = tmp_path / "project"
    project.mkdir()
    definition, expected = _definition(project, None)
    monkeypatch.setattr(host_bindings, "resolve", lambda *args: (expected,))
    definition["host_bindings"][0] = dict(expected, **change)
    with pytest.raises(SystemdBackendError, match="binding differs"):
        BusctlSystemdBackend._validate_host_bindings(project, definition)


def test_privileged_rejects_policy_moved_to_other_program(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    definition, expected = _definition(project, None)
    monkeypatch.setattr(host_bindings, "resolve", lambda *args: (expected,))
    definition["program_name"] = "web"
    with pytest.raises(SystemdBackendError, match="program identity"):
        BusctlSystemdBackend._validate_host_bindings(project, definition)


def test_privileged_rejects_policy_read_write_or_missing_mount(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    definition, expected = _definition(project, None)
    monkeypatch.setattr(host_bindings, "resolve", lambda *args: (expected,))
    definition["read_only_bind_paths"] = []
    with pytest.raises(SystemdBackendError, match="read-only sources"):
        BusctlSystemdBackend._validate_host_bindings(project, definition)


def test_privileged_denies_policy_removed_before_launch(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    definition, expected = _definition(project, None)
    monkeypatch.setattr(host_bindings, "resolve", lambda *args: ())
    with pytest.raises(SystemdBackendError, match="binding differs"):
        BusctlSystemdBackend._validate_host_bindings(project, definition)
