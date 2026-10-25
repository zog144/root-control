"""Source gates for the dedicated root-control compiler-only Project role.

No root socket, host account, systemd unit or production state is created.
Native DAC, SO_PEERCRED and cgroup acceptance remains a separate Work gate.
"""
import os
from pathlib import Path
import socket
import stat
import struct
from types import SimpleNamespace

import pytest

from zog.root_control import daemon, protocol

ROLE = daemon.BUILD_ONLY_PROJECT_ROLE
SOCKET = "/run/zog/root-control-fresh-cross-bootstrap-oct25.sock"
OWNER_UID = 24301
OWNER_GID = 24301
WORKER_UID = 24302


@pytest.fixture
def restricted(tmp_path, monkeypatch):
    home = tmp_path / "owner"
    project = home / "compiler"
    project.mkdir(parents=True)
    home.chmod(0o700)
    project.chmod(0o700)
    account = SimpleNamespace(
        pw_uid=OWNER_UID, pw_gid=OWNER_GID, pw_dir=str(home),
    )
    monkeypatch.setattr(daemon.pwd, "getpwuid", lambda uid: account)
    original = Path.lstat

    def owned(self):
        record = original(self)
        if self in (home, project):
            return SimpleNamespace(
                st_uid=OWNER_UID, st_gid=OWNER_GID, st_mode=record.st_mode,
            )
        return record

    monkeypatch.setattr(Path, "lstat", owned)
    service = daemon.RootControlDaemon(
        SOCKET, systemd_backend=object(),
        socket_group_gid=OWNER_GID, controller_uid=OWNER_UID,
        role=ROLE, authorized_project_root=str(project),
    )
    return service, home, project


@pytest.mark.parametrize("config", [
    {"role": ROLE},
    {"authorized_project_root": "/home/owner/compiler"},
    {"role": "general", "authorized_project_root": "/home/owner/compiler"},
    {"role": ROLE, "authorized_project_root": "relative"},
    {"role": ROLE, "authorized_project_root": "/home/owner/../compiler"},
    {"role": ROLE, "authorized_project_root": "/home/owner//compiler"},
    {"role": ROLE, "authorized_project_root": "/home/owner/compiler/"},
])
def test_partial_or_noncanonical_role_configuration_denied(config):
    with pytest.raises(ValueError, match="build-only listener"):
        daemon.RootControlDaemon(
            SOCKET, systemd_backend=object(),
            controller_uid=OWNER_UID, socket_group_gid=OWNER_GID,
            **config,
        )


@pytest.mark.parametrize("socket_path", [
    "/run/zog/root-control.sock",
    "/run/zog/other.sock",
    "/run/zog/sub/root-control-fresh.sock",
    "/tmp/root-control-fresh.sock",
])
def test_role_requires_distinct_fixed_privileged_socket(socket_path):
    with pytest.raises(ValueError, match="dedicated socket"):
        daemon.RootControlDaemon(
            socket_path, systemd_backend=object(),
            controller_uid=OWNER_UID, socket_group_gid=OWNER_GID,
            role=ROLE, authorized_project_root="/home/owner/compiler",
        )


@pytest.mark.parametrize("config", [
    {"socket_group_gid": None},
    {"controller_uid": None},
])
def test_role_requires_both_explicit_numeric_ids(config):
    params = dict(
        controller_uid=OWNER_UID, socket_group_gid=OWNER_GID,
        role=ROLE, authorized_project_root="/home/owner/compiler",
    )
    params.update(config)
    with pytest.raises((ValueError, PermissionError)):
        daemon.RootControlDaemon(
            SOCKET, systemd_backend=object(), **params,
        )


def test_dedicated_socket_cannot_accidentally_start_with_full_privilege():
    with pytest.raises(ValueError, match="requires build-only role"):
        daemon.RootControlDaemon(
            SOCKET, systemd_backend=object(),
            controller_uid=OWNER_UID, socket_group_gid=OWNER_GID,
        )
    # The already-installed shared daemon keeps its original full RPC role.
    shared = daemon.RootControlDaemon(
        daemon.DEFAULT_SOCKET, systemd_backend=object(),
        controller_uid=OWNER_UID, socket_group_gid=OWNER_GID,
    )
    assert shared.role is None
    assert shared._authorize_role_request({"operation": "systemd_stop"}) == "systemd_stop"


@pytest.mark.parametrize("op", sorted(daemon._BUILD_ONLY_MUTATIONS | daemon._BUILD_ONLY_READS))
def test_exact_project_selected_build_operations_are_admitted(restricted, op):
    service, home, project = restricted
    assert service._authorize_role_request({
        "operation": op, "project_root": str(project),
    }) == op


@pytest.mark.parametrize("op", sorted(daemon._BUILD_ONLY_HEALTH))
def test_build_only_health_never_accepts_caller_chosen_project(restricted, op):
    service, home, project = restricted
    assert service._authorize_role_request({"operation": op}) == op
    for value in (str(project), "/root", None):
        with pytest.raises(PermissionError, match="cannot select Project"):
            service._authorize_role_request({
                "operation": op, "project_root": value,
            })


@pytest.mark.parametrize("op", [
    "systemd_stop", "systemd_reset_failed", "systemd_release",
    "systemd_kill", "systemd_start_service", "systemd_start_slice",
    "systemd_observe", "systemd_release_runtime_root",
    "application_logs", "application_runtime_mounts",
    "application_storage_delete", "application_storage_sync",
    "issuer_observe", "issuer_inspect_result",
    "workspace_prepare", "execution_identity_resolve",
    "mount", "unmount", "build_unreviewed",
])
def test_non_build_rpc_never_reaches_privileged_backend(restricted, op):
    service, _, project = restricted

    class Forbidden:
        def __getattr__(self, name):
            raise AssertionError("unauthorized privileged backend call: " + name)

    service.systemd = Forbidden()
    service.build = Forbidden()
    request = {
        "operation": op, "project_root": str(project),
        "unit_name": "zog-foreign-unit.service",
        "request_id": "a" * 32,
    }
    with pytest.raises(PermissionError, match="not authorized"):
        service.handle(request)
    with pytest.raises(PermissionError, match="not authorized"):
        service._dispatch(None, request, (None, None), (None, None))


def test_read_only_and_build_mutations_cannot_select_foreign_project(restricted):
    service, _, project = restricted

    class Forbidden:
        def __getattr__(self, name):
            raise AssertionError("backend was reached")

    service.systemd = Forbidden()
    service.build = Forbidden()
    for operation in sorted(daemon._BUILD_ONLY_MUTATIONS | daemon._BUILD_ONLY_READS):
        for wrong in ("/home/foreign/project", str(project) + "/..",
                      str(project) + "/child", None, 9):
            with pytest.raises(PermissionError, match="wrong Project"):
                service.handle({
                    "operation": operation,
                    "project_root": wrong,
                })


def test_project_owner_primary_gid_and_symlink_drift_rejected(restricted, monkeypatch):
    service, home, project = restricted
    original = Path.lstat

    def bad_gid(self):
        record = original(self)
        if self == project:
            return SimpleNamespace(
                st_uid=OWNER_UID, st_gid=OWNER_GID + 1,
                st_mode=record.st_mode,
            )
        return record

    monkeypatch.setattr(Path, "lstat", bad_gid)
    with pytest.raises(PermissionError, match="authority unavailable"):
        service._authorize_role_request({
            "operation": "build_observe", "project_root": str(project),
        })


def test_root_or_same_gid_other_uid_cannot_use_build_only_socket(restricted):
    service, _, _ = restricted

    class Peer:
        def __init__(self, uid):
            self.uid = uid
        def getsockopt(self, level, optname, size):
            return struct.pack("3i", 44, self.uid, OWNER_GID)

    service._authorize_peer(Peer(OWNER_UID))
    for uid in (0, WORKER_UID, OWNER_UID + 12):
        with pytest.raises(PermissionError, match="unauthorized"):
            service._authorize_peer(Peer(uid))


def test_startup_checks_bound_principal_before_touching_privileged_listener(restricted, monkeypatch):
    service, home, project = restricted
    monkeypatch.setattr(daemon.os, "geteuid", lambda: 0)
    service._validate_role_startup()
    monkeypatch.setattr(daemon.pwd, "getpwuid", lambda uid: SimpleNamespace(
        pw_uid=uid, pw_gid=OWNER_GID + 1, pw_dir=str(home),
    ))
    with pytest.raises(PermissionError):
        service._validate_role_startup()

    monkeypatch.setattr(daemon.os, "geteuid", lambda: OWNER_UID)
    with pytest.raises(PermissionError, match="root service"):
        service._validate_role_startup()


def test_dedicated_listener_will_not_unlink_existing_socket(restricted, monkeypatch, tmp_path):
    service, _, _ = restricted
    listener = tmp_path / "sidecar.sock"
    a = socket.socket(socket.AF_UNIX)
    try:
        a.bind(str(listener))
        service.socket_path = listener
        original = Path.lstat
        def parent_trusted(self):
            value = original(self)
            if self == listener:
                return SimpleNamespace(st_uid=0, st_gid=0, st_mode=value.st_mode)
            if self in listener.parents:
                return SimpleNamespace(st_uid=0, st_gid=0, st_mode=stat.S_IFDIR | 0o755)
            return value
        monkeypatch.setattr(Path, "lstat", parent_trusted)
        with pytest.raises(PermissionError, match="already exists"):
            service._prepare_socket_parent()
        assert listener.exists()
    finally:
        a.close()


def test_main_reads_frozen_role_only_from_supervisor_env(monkeypatch):
    calls = []
    class Service:
        def __init__(self, socket_path, **kwargs):
            calls.append((socket_path, kwargs))
        def serve(self):
            calls.append("serve")
    monkeypatch.setattr(daemon, "RootControlDaemon", Service)
    monkeypatch.setenv("ROOT_CONTROL_SOCKET", SOCKET)
    monkeypatch.setenv("ROOT_CONTROL_CONTROLLER_UID", str(OWNER_UID))
    monkeypatch.setenv("ROOT_CONTROL_SOCKET_GID", str(OWNER_GID))
    monkeypatch.setenv("ROOT_CONTROL_ROLE", ROLE)
    monkeypatch.setenv("ROOT_CONTROL_AUTHORIZED_PROJECT", "/home/owner/compiler")
    daemon.main()
    assert calls == [
        (SOCKET, {
            "journal_barrier": None,
            "socket_group_gid": OWNER_GID,
            "controller_uid": OWNER_UID,
            "role": ROLE,
            "authorized_project_root": "/home/owner/compiler",
        }), "serve",
    ]


def test_client_cannot_set_role_in_rpc(restricted):
    service, _, project = restricted
    for request in (
        {"operation": "systemd_stop", "role": ROLE, "project_root": str(project)},
        {"operation": "build_observe", "role": ROLE,
         "project_root": "/home/foreign"},
    ):
        with pytest.raises(PermissionError):
            service.handle(request)
