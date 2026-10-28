"""Root-only integration regression for restrictive immutable build-root imports.

Run in disposable CI under sudo: the real BuildBackend.register() performs
copytree, real chown/chmod, fsync barriers, registration commit and then tests
the transient worker's fixed read-only view without starting PID1.
"""
import json
import os
from pathlib import Path
import stat

import pytest

from zog.root_control import build as build_module
from zog.root_control.build import BuildBackend
from zog.root_control.systemd import BusctlSystemdBackend


class RecordingSystemd(BusctlSystemdBackend):
    def __init__(self):
        self.properties = None

    def version(self):
        return 252

    def start_slice(self, **kwargs):
        pass

    def _job(self, method, signature, body):
        assert method == "StartTransientUnit"
        self.properties = {name: value for name, value in body[2]}


@pytest.mark.skipif(os.geteuid() != 0, reason="real root chown and 0000 directory fsync require privileged registrar")
def test_registration_import_preserves_security_modes_ownership_durability_and_execution(tmp_path, monkeypatch):
    project = tmp_path / "project"
    attempt = project / "state/image-build/attempts/one"
    root, source, output = (attempt / part for part in ("root", "source", "output"))
    for path in (root, source, output):
        path.mkdir(parents=True)
    (root / "state").mkdir(mode=0o700)
    (root / "applications").mkdir(mode=0o700)
    (root / "private").mkdir(mode=0o700)
    (root / "usr/bin").mkdir(parents=True)
    (root / "usr/bin/compiler").write_bytes(b"#!/bin/sh\nexit 0\n")
    (root / "usr/bin/compiler").chmod(0o755)
    (root / "private/key").write_bytes(b"do-not-expose\n")
    (root / "private/key").chmod(0o600)
    (root / "applications").chmod(0o000)
    (root / "state").chmod(0o000)
    (source / "input").write_text("source")
    systemd = RecordingSystemd()
    backend = BuildBackend(systemd, tmp_path / "protected-resources")
    resource = "b" * 32
    args = {
        "project_root": project, "resource_id": resource,
        "prepared_root": root, "source_directory": source,
        "output_directory": output, "input_manifest_id": "boot-a-mode-0000",
        "execution_user_id": 24302, "execution_group_id": 24302,
    }
    # Observe the real sync barrier on each restrictive directory; wrapping
    # does NOT simulate success or replace the kernel fsync implementation.
    actual_sync = build_module.synchronize_directory
    synced = []

    def sync(path):
        actual_sync(path)
        synced.append(Path(path))

    monkeypatch.setattr(build_module, "synchronize_directory", sync)
    result = backend.register(**args)
    imported = backend.resource_path(project, resource) / "root"
    assert result["state"] == "ready"
    assert json.loads((imported.parent / "registration.json").read_text()) == result
    assert imported / "state" in synced
    assert imported / "applications" in synced
    assert imported / "private" in synced

    expected = {
        "state": 0o000, "applications": 0o000,
        "private": 0o500, "private/key": 0o400,
        "usr/bin/compiler": 0o555,
    }
    for name, mode in expected.items():
        actual = (imported / name).stat()
        assert stat.S_IMODE(actual.st_mode) == mode, name
        assert (actual.st_uid, actual.st_gid) == (0, 0), name
        assert not (actual.st_mode & 0o222), name
    assert stat.S_IMODE((root / "state").stat().st_mode) == 0o000
    assert stat.S_IMODE((root / "applications").stat().st_mode) == 0o000
    assert stat.S_IMODE((root / "private").stat().st_mode) == 0o700
    assert (source.stat().st_uid, source.stat().st_gid) == (24302, 24302)
    assert (output.stat().st_uid, output.stat().st_gid) == (24302, 24302)
    assert (root.stat().st_uid, root.stat().st_gid) == (0, 0)

    # Registration is repeatable without rewriting the frozen import.
    same = backend.register(**args)
    assert same == result
    for name, mode in expected.items():
        assert stat.S_IMODE((imported / name).stat().st_mode) == mode

    request = {
        "build_root_id": resource,
        "source_workspace_id": resource + "-source",
        "output_workspace_id": resource + "-output",
        "command": ["/usr/bin/compiler"],
        "environment": {"PATH": "/usr/bin"},
        "working_directory": "/image-build/source",
        "execution_user_id": 24302,
        "execution_group_id": 24302,
        "startup_timeout_seconds": 5,
        "execution_timeout_seconds": 8,
        "termination_grace_seconds": 2,
        "resource_limits": {
            "thread-count-maximum": 32,
            "memory-maximum-bytes": 10_000_000,
        },
        "read_only_root": True,
        "network_access": False,
    }
    backend.start(project_root=project, job_id="c" * 32, request=request)
    properties = systemd.properties
    assert properties is not None
    assert properties["RootDirectory"].value == str(imported)
    assert properties["ProtectSystem"].value == "strict"
    assert properties["PrivateNetwork"].value is True
    assert properties["User"].value == "24302"
    assert properties["Group"].value == "24302"
    assert properties["WorkingDirectory"].value == "/image-build/source"
    assert properties["BindPaths"].value is not None
    # The private resident mountpoints are not overridden by writable binds.
    bindpaths = properties["BindPaths"].value
    flat = str(bindpaths)
    assert "/state" not in flat and "/applications" not in flat
    assert properties["ExecStart"].value is not None
    for name, mode in expected.items():
        assert stat.S_IMODE((imported / name).stat().st_mode) == mode
