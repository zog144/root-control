"""Exact-controller-UID privileged socket authority; native ACL audit separately."""
import os
from pathlib import Path
import socket
import stat
import struct
from types import SimpleNamespace

import pytest

from zog.root_control import daemon


def test_root_only_socket_default_is_not_group_accessible(tmp_path, monkeypatch):
    changes = []
    monkeypatch.setattr(daemon.os, "chown", lambda *a: changes.append(("chown", a)))
    monkeypatch.setattr(daemon.os, "chmod", lambda *a: changes.append(("chmod", a)))
    service = daemon.RootControlDaemon(tmp_path / "root-control.sock",
                                       systemd_backend=object())
    service._protect_socket()
    assert changes == [
        ("chown", (service.socket_path, 0, 0)),
        ("chmod", (service.socket_path, 0o600)),
    ]


def test_exact_controller_uid_and_optional_dedicated_group(tmp_path, monkeypatch):
    changes = []
    monkeypatch.setattr(daemon.os, "chown", lambda *a: changes.append(("chown", a)))
    monkeypatch.setattr(daemon.os, "chmod", lambda *a: changes.append(("chmod", a)))
    monkeypatch.setattr(daemon.pwd, "getpwuid",
                        lambda uid: SimpleNamespace(pw_uid=uid, pw_gid=991))
    service = daemon.RootControlDaemon(tmp_path / "root-control.sock",
                                       systemd_backend=object(),
                                       controller_uid=20001, socket_group_gid=991)
    service._protect_socket()
    assert changes == [
        ("chown", (service.socket_path, 0, 991)),
        ("chmod", (service.socket_path, 0o660)),
    ]
    changes.clear()
    service = daemon.RootControlDaemon(tmp_path / "root-control.sock",
                                       systemd_backend=object(), controller_uid=20001)
    service._protect_socket()
    assert changes == [
        ("chown", (service.socket_path, 20001, -1)),
        ("chmod", (service.socket_path, 0o600)),
    ]


@pytest.mark.parametrize("uid", [0, 1, 999, -1, True, "1200", 2**31])
def test_invalid_or_privileged_controller_uid_is_rejected(tmp_path, uid):
    with pytest.raises(ValueError, match="controller UID"):
        daemon.RootControlDaemon(tmp_path / "root.sock",
                                 systemd_backend=object(), controller_uid=uid)


@pytest.mark.parametrize("gid", [0, -1, True, "991", 2**31])
def test_invalid_socket_group_is_rejected(tmp_path, gid):
    with pytest.raises(ValueError, match="positive numeric GID"):
        daemon.RootControlDaemon(tmp_path / "root.sock",
                                 systemd_backend=object(), controller_uid=20001,
                                 socket_group_gid=gid)


def test_group_only_authority_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="group requires"):
        daemon.RootControlDaemon(tmp_path / "root.sock",
                                 systemd_backend=object(), socket_group_gid=991)


def test_socket_peer_credential_uses_numeric_uid_not_group(tmp_path, monkeypatch):
    service = daemon.RootControlDaemon(tmp_path / "root.sock",
                                       systemd_backend=object(),
                                       controller_uid=20001, socket_group_gid=991)
    a, b = socket.socketpair()
    class Peer:
        def __init__(self, uid, gid=991):
            self.uid, self.gid = uid, gid
        def getsockopt(self, _level, _name, _length):
            return struct.pack("3i", 123, self.uid, self.gid)
    try:
        service._authorize_peer(Peer(20001))
        for uid in (0, 20002, 999):
            with pytest.raises(PermissionError, match="unauthorized"):
                service._authorize_peer(Peer(uid))
    finally:
        a.close()
        b.close()


def test_untrusted_parent_directory_denied_before_binding(tmp_path, monkeypatch):
    parent = tmp_path / "run"
    parent.mkdir()
    path = parent / "control.sock"
    service = daemon.RootControlDaemon(path, systemd_backend=object(),
                                       controller_uid=20001)
    monkeypatch.setattr(daemon.os, "getuid", lambda: 0)
    # A world-writable or substituted parent can replace a privileged listener.
    parent.chmod(0o777)
    with pytest.raises(PermissionError, match="ancestry"):
        service._prepare_socket_parent()
    parent.chmod(0o700)
    (parent / "sub").symlink_to(tmp_path)
    changed = daemon.RootControlDaemon(parent / "sub/root.sock",
                                       systemd_backend=object(), controller_uid=20001)
    with pytest.raises(PermissionError, match="ancestry"):
        changed._prepare_socket_parent()


def test_existing_regular_file_must_not_be_unlinked(tmp_path, monkeypatch):
    # Check the stale path rule independently; ancestors are intentionally
    # mocked to avoid requiring root ownership of pytest temp directories.
    service = daemon.RootControlDaemon(tmp_path / "root.sock",
                                       systemd_backend=object(), controller_uid=20001)
    service.socket_path.write_text("data")
    with pytest.raises(PermissionError, match="ancestry|existing privileged"):
        service._prepare_socket_parent()
    assert service.socket_path.read_text() == "data"


def test_main_pins_explicit_socket_owner_uid_and_gid(monkeypatch):
    calls = []
    class Service:
        def __init__(self, socket_path, *, journal_barrier,
                     socket_group_gid, controller_uid):
            calls.append((socket_path, socket_group_gid, controller_uid))
        def serve(self):
            calls.append("serve")
    monkeypatch.setattr(daemon, "RootControlDaemon", Service)
    monkeypatch.setenv("ROOT_CONTROL_SOCKET", "/run/zog/root-control.sock")
    monkeypatch.setenv("ROOT_CONTROL_SOCKET_GID", "991")
    monkeypatch.setenv("ROOT_CONTROL_CONTROLLER_UID", "20001")
    daemon.main()
    assert calls == [("/run/zog/root-control.sock", 991, 20001), "serve"]
    calls.clear()
    monkeypatch.delenv("ROOT_CONTROL_SOCKET_GID")
    monkeypatch.delenv("ROOT_CONTROL_CONTROLLER_UID")
    daemon.main()
    assert calls == [("/run/zog/root-control.sock", None, None), "serve"]


@pytest.mark.parametrize("invalid", ["", "-1", " 991", "controller", "1.0", "0x10"])
def test_main_rejects_non_numeric_configuration(monkeypatch, invalid):
    monkeypatch.setenv("ROOT_CONTROL_SOCKET_GID", invalid)
    with pytest.raises(ValueError, match="numeric GID"):
        daemon.main()


@pytest.mark.parametrize("invalid", ["", "-1", " 991", "controller", "1.0", "0x10"])
def test_main_rejects_non_numeric_uid_configuration(monkeypatch, invalid):
    monkeypatch.delenv("ROOT_CONTROL_SOCKET_GID", raising=False)
    monkeypatch.setenv("ROOT_CONTROL_CONTROLLER_UID", invalid)
    with pytest.raises(ValueError, match="numeric UID"):
        daemon.main()


def test_console_progress_consumer_never_inherits_general_privileged_socket(monkeypatch):
    """Separate consumer sockets are not alternate root-control controller UIDs."""
    from zog.root_control.daemon import RootControlDaemon
    import struct
    service = RootControlDaemon("/run/zog/root-control.sock",
                                systemd_backend=object(),
                                controller_uid=12002)
    class Peer:
        def __init__(self, uid):
            self.uid = uid
        def getsockopt(self, level, name, maximum):
            return struct.pack("3i", 100, self.uid, 12001)
    service._authorize_peer(Peer(12002))
    for consumer_uid in (12001, 12003):  # dedicated host-welcome and station
        with pytest.raises(PermissionError, match="unauthorized"):
            service._authorize_peer(Peer(consumer_uid))


def test_group_socket_denies_unreviewed_primary_gid_before_dac_changes(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(daemon.os, "chown", lambda *a: calls.append("chown"))
    monkeypatch.setattr(daemon.os, "chmod", lambda *a: calls.append("chmod"))
    service = daemon.RootControlDaemon(
        tmp_path / "root.sock", systemd_backend=object(),
        controller_uid=20001, socket_group_gid=20002,
    )
    monkeypatch.setattr(daemon.pwd, "getpwuid",
                        lambda uid: SimpleNamespace(pw_uid=uid, pw_gid=20003))
    with pytest.raises(PermissionError, match="primary group"):
        service._protect_socket()
    assert calls == []
    monkeypatch.setattr(daemon.pwd, "getpwuid",
                        lambda uid: (_ for _ in ()).throw(KeyError(uid)))
    with pytest.raises(PermissionError, match="account missing"):
        service._protect_socket()
    assert calls == []


def test_build_project_bound_to_passwd_home_and_nonroot_owner(tmp_path, monkeypatch):
    home = tmp_path / "account"
    project = home / "compiler-project"
    project.mkdir(parents=True)
    home.chmod(0o700)
    project.chmod(0o700)
    actor_uid = 20001
    monkeypatch.setattr(daemon.pwd, "getpwuid", lambda uid: SimpleNamespace(
        pw_uid=uid, pw_gid=20002, pw_dir=str(home)
    ))
    original = Path.lstat
    def owned(self):
        value = original(self)
        if self in (home, project):
            return SimpleNamespace(st_uid=actor_uid, st_gid=20002, st_mode=value.st_mode)
        return value
    monkeypatch.setattr(Path, "lstat", owned)
    class BuildSpy:
        def __init__(self): self.calls = []
        def observe(self, **kw):
            self.calls.append(kw)
            return {"state": "running"}
    service = daemon.RootControlDaemon(
        tmp_path / "root.sock", systemd_backend=object(),
        controller_uid=actor_uid, socket_group_gid=20002,
    )
    spy = BuildSpy()
    service.build = spy
    request = dict(operation="build_observe", project_root=str(project),
                   job_id="a"*32, build_root_id="b"*32)
    assert service.handle(request)["result"]["state"] == "running"
    assert len(spy.calls) == 1
    for invalid in (
        str(tmp_path / "other"),
        str(home),
        str(project / ".." / "compiler-project"),
        str(project) + "/not-present",
        None,
        12,
    ):
        with pytest.raises(PermissionError):
            service.handle(dict(request, project_root=invalid))
    assert len(spy.calls) == 1

    # Authorization must not silently follow a replacement directory,
    # accept a different non-root owner or grant write access to others.
    def drifted(self):
        value = original(self)
        if self == home:
            return SimpleNamespace(st_uid=actor_uid, st_gid=20002, st_mode=value.st_mode)
        if self == project:
            return SimpleNamespace(st_uid=actor_uid+1, st_gid=20002, st_mode=value.st_mode)
        return value
    monkeypatch.setattr(Path, "lstat", drifted)
    with pytest.raises(PermissionError, match="build Project authority unavailable"):
        service.handle(request)
    assert len(spy.calls) == 1

    def writable(self):
        value = original(self)
        if self in (home, project):
            return SimpleNamespace(st_uid=actor_uid, st_gid=20002,
                                   st_mode=value.st_mode | 0o020)
        return value
    monkeypatch.setattr(Path, "lstat", writable)
    with pytest.raises(PermissionError, match="build Project authority unavailable"):
        service.handle(request)
    assert len(spy.calls) == 1

    def group_drift(self):
        value = original(self)
        if self in (home, project):
            return SimpleNamespace(st_uid=actor_uid,
                                   st_gid=20003 if self == project else 20002,
                                   st_mode=value.st_mode)
        return value
    monkeypatch.setattr(Path, "lstat", group_drift)
    with pytest.raises(PermissionError, match="authority unavailable"):
        service.handle(request)
    assert len(spy.calls) == 1


def test_build_project_symlink_substitution_denied(tmp_path, monkeypatch):
    home = tmp_path / "account"
    home.mkdir()
    original = home / "correct"
    original.mkdir()
    replaced = home / "replaced"
    replaced.symlink_to(original, target_is_directory=True)
    monkeypatch.setattr(daemon.pwd, "getpwuid", lambda uid: SimpleNamespace(
        pw_uid=uid, pw_gid=20002, pw_dir=str(home)
    ))
    service = daemon.RootControlDaemon(tmp_path / "root.sock",
                                       systemd_backend=object(), controller_uid=20001)
    with pytest.raises(PermissionError, match="build Project authority unavailable"):
        service._authorize_build_project(str(replaced))
