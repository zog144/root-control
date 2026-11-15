"""Managed private persistent storage must be 0700, including after reboot."""
import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from zog.root_control.systemd import BusctlSystemdBackend, SystemdBackendError


def _setup(tmp_path, monkeypatch):
    project = tmp_path / "project"
    mount = project / "state" / "mounts" / "persistent" / ("a" * 32) / "certificate-data"
    grant = {"uid": 2000010, "gid": 2000010}
    monkeypatch.setattr(BusctlSystemdBackend, "_validate_execution_binding",
                        lambda root, definition: grant)
    original_lstat = Path.lstat
    def lstat(path, *args, **kwargs):
        info = original_lstat(path, *args, **kwargs)
        if Path(path) != mount:
            return info
        return SimpleNamespace(st_mode=info.st_mode, st_uid=grant["uid"], st_gid=grant["gid"])
    monkeypatch.setattr(Path, "lstat", lstat)
    monkeypatch.setattr(os, "chown", lambda path, uid, gid: None)
    definition = {
        "persistent_storage_id": "a" * 32,
        "user": "2000010",
        "group": "2000010",
        "bind_paths": [(str(mount), "/var/lib/zog-certify-manage")],
    }
    return project, mount, definition


def test_new_controller_managed_mount_created_at_exact_private_mode(tmp_path, monkeypatch):
    project, mount, definition = _setup(tmp_path, monkeypatch)
    BusctlSystemdBackend._persistent_directories(str(project), definition)
    assert stat.S_IMODE(mount.stat().st_mode) == 0o700


@pytest.mark.parametrize("incorrect_mode", [0o750, 0o755, 0o777, 0o000, 0o600])
def test_preexisting_managed_storage_mode_drift_is_not_repaired(tmp_path, monkeypatch, incorrect_mode):
    project, mount, definition = _setup(tmp_path, monkeypatch)
    mount.mkdir(parents=True)
    mount.chmod(incorrect_mode)
    with pytest.raises(SystemdBackendError, match="mode drift"):
        BusctlSystemdBackend._persistent_directories(str(project), definition)
    assert stat.S_IMODE(mount.stat().st_mode) == incorrect_mode


def test_redirected_persistent_source_rejected_without_following(tmp_path, monkeypatch):
    project, mount, definition = _setup(tmp_path, monkeypatch)
    mount.parent.mkdir(parents=True)
    mount.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(SystemdBackendError, match="redirected|direct owned directory"):
        BusctlSystemdBackend._persistent_directories(str(project), definition)
    assert mount.is_symlink()
