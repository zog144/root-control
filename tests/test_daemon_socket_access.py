"""Trusted-controller-only privileged socket group selection."""
from pathlib import Path

import pytest

from zog.root_control import daemon


def test_root_socket_defaults_keep_ownership_unchanged(tmp_path, monkeypatch):
    changes = []
    monkeypatch.setattr(daemon.os, "chown", lambda *a: changes.append(("chown", a)))
    monkeypatch.setattr(daemon.os, "chmod", lambda *a: changes.append(("chmod", a)))
    service = daemon.RootControlDaemon(tmp_path / "root-control.sock", systemd_backend=object())
    service._protect_socket()
    assert changes == [("chmod", (service.socket_path, 0o660))]


def test_explicit_dedicated_controller_group_is_the_only_added_socket_permission(tmp_path, monkeypatch):
    changes = []
    monkeypatch.setattr(daemon.os, "chown", lambda *a: changes.append(("chown", a)))
    monkeypatch.setattr(daemon.os, "chmod", lambda *a: changes.append(("chmod", a)))
    service = daemon.RootControlDaemon(tmp_path / "root-control.sock",
                                       systemd_backend=object(), socket_group_gid=991)
    service._protect_socket()
    assert changes == [
        ("chown", (service.socket_path, -1, 991)),
        ("chmod", (service.socket_path, 0o660)),
    ]


@pytest.mark.parametrize("gid", [0, -1, True, "991", 2**31])
def test_invalid_or_unprivileged_gid_is_rejected(tmp_path, gid):
    with pytest.raises(ValueError, match="positive numeric GID"):
        daemon.RootControlDaemon(tmp_path / "root.sock",
                                 systemd_backend=object(), socket_group_gid=gid)


def test_main_applies_explicit_socket_gid_only_when_supplied(monkeypatch):
    calls = []
    class Service:
        def __init__(self, socket_path, *, journal_barrier, socket_group_gid):
            calls.append((socket_path, socket_group_gid))
        def serve(self):
            calls.append("serve")
    monkeypatch.setattr(daemon, "RootControlDaemon", Service)
    monkeypatch.setenv("ROOT_CONTROL_SOCKET", "/run/zog/root-control.sock")
    monkeypatch.setenv("ROOT_CONTROL_SOCKET_GID", "991")
    daemon.main()
    assert calls == [("/run/zog/root-control.sock", 991), "serve"]
    calls.clear()
    monkeypatch.delenv("ROOT_CONTROL_SOCKET_GID")
    daemon.main()
    assert calls == [("/run/zog/root-control.sock", None), "serve"]


@pytest.mark.parametrize("invalid", ["", "-1", " 991", "controller", "1.0", "0x10"])
def test_main_rejects_non_numeric_configuration(monkeypatch, invalid):
    monkeypatch.setenv("ROOT_CONTROL_SOCKET_GID", invalid)
    with pytest.raises(ValueError, match="numeric GID"):
        daemon.main()
