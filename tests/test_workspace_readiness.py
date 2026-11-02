"""Synthetic read-only Workspace stage proof; no real desktop is started."""
import json
import os
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from zog.box_control.boot import current_boot_id
from zog.box_control.model import ApplicationRuntimeState
from zog.box_control.project import Project
from zog.box_control.runtime.reference import (
    RuntimeReferenceStore, ApplicationRuntimeReference, ProgramRuntimeReference,
)
from zog.box_control.workspaces import Workspaces, VERSION
from zog.root_control.workspace import WorkspaceBackend
from zog.root_control import workspace_readiness as ready


@pytest.fixture
def model(tmp_path, monkeypatch):
    project = Project(tmp_path / "project")
    workspace = str(uuid4())
    record = Workspaces(project).register(workspace, 1)
    root = project.state_dir / "workspace-resources" / workspace / record["incarnation"]
    root.mkdir(parents=True)
    run, x11 = root / "run", root / "x11"
    run.mkdir(); x11.mkdir()
    auth = b"synthetic-private-auth"
    cookie = "ab" * 16
    (run / "Xauthority").write_bytes(auth)
    (run / "vnc.sock").touch()
    (x11 / "X1").touch()
    monkeypatch.setattr(ready.stat, "S_ISSOCK", lambda _: True)
    ns = SimpleNamespace(st_dev=101, st_ino=202)
    monkeypatch.setattr(ready, "host_namespace_stat", lambda: ns)
    monkeypatch.setattr(ready, "peer_namespace_stat", lambda pid: ns)
    monkeypatch.setattr(ready, "peer_cgroups", lambda pid: ["0::/desktop"])
    resolved = dict(display=":1", namespace_path="/proc/1/ns/net",
        namespace_device=101, namespace_inode=202,
        access_directory=str(run), x11_directory=str(x11),
        vnc_endpoint={"kind": "unix", "path": str(run / "vnc.sock")})
    desktop = dict(schema=VERSION, workspace_id=workspace, number=1,
        network="host-shared", revision=1, incarnation=record["incarnation"],
        role="desktop", desktop_runtime_id=None, boot_id=current_boot_id(), **resolved)
    binding = dict(desktop, role="client", desktop_runtime_id="desktop-id")
    (root / "mechanism.json").write_text(json.dumps(
        dict(binding=desktop, resolved=resolved, uid=os.getuid(),
             authority_hex=auth.hex(), cookie_hex=cookie)))
    unit = "zog-project-desktop-id-main.service"
    reference = ApplicationRuntimeReference(
        "desktop-id", "desktop", "desktop", "gen",
        ApplicationRuntimeState.RUNNING, boot_id=current_boot_id(),
        programs=(ProgramRuntimeReference(
            "main", unit, invocation_id="original-invocation"),),
        workspace_binding=desktop)
    RuntimeReferenceStore(project.runtime_reference_file).save(
        {"desktop-id": reference})
    backend = WorkspaceBackend(SimpleNamespace(observe=lambda **kw:
        {"exists": True, "active_state": "active",
         "invocation_id": "original-invocation", "control_group": "/desktop"}))
    return backend, project, binding, root


class FakeSocket:
    def __init__(self, *, x11_accepted=True, rfb_valid=True):
        self.x11_accepted = x11_accepted
        self.rfb_valid = rfb_valid
        self.data = b""
    def __enter__(self): return self
    def __exit__(self, *_): pass
    def settimeout(self, timeout): assert 0 < timeout <= 2
    def connect(self, path): self.path = path
    def getsockopt(self, *_):
        import struct
        return struct.pack("3i", os.getpid(), os.getuid(), os.getgid())
    def sendall(self, payload):
        self.sent = payload
    def recv(self, count):
        if not self.data:
            self.data = (b"\x01\0\x0b\0\0\0\0\0"
                         if self.x11_accepted else b"\x00\0" * 4) if self.path.endswith("/X1") else (
                            b"RFB 003.008\n" if self.rfb_valid else b"RFB 003.x08\n")
        answer, self.data = self.data[:count], self.data[count:]
        return answer


def test_separate_live_cookie_and_rfb_probes_are_bounded_and_redacted(model, monkeypatch):
    backend, project, binding, root = model
    monkeypatch.setattr(ready.socket, "socket", lambda *a, **k: FakeSocket(rfb_valid=False))
    result = ready.inspect(backend, project_root=project.path, binding=binding)
    assert result["x11"] == {"status": "confirmed", "code": "ok"}
    assert result["rfb"] == {"status": "failed", "code": "rfb-invalid"}
    assert result["boot_id"] == binding["boot_id"]
    assert result["desktop_runtime_id"] == "desktop-id"
    assert len(result["endpoint_identity"]) == 64
    dumped = repr(result)
    assert "ab" * 16 not in dumped and str(root) not in dumped
    assert "MIT-MAGIC-COOKIE" not in dumped and "RFB 003" not in dumped


def test_cookie_rotation_after_first_probe_revokes_both_stage_observations(model, monkeypatch):
    backend, project, binding, root = model
    def change(path, **kw):
        if kw["x11"]:
            (root / "run" / "Xauthority").write_bytes(b"new-private-auth")
        return {"status": "confirmed", "code": "ok"}
    monkeypatch.setattr(ready, "_probe", change)
    result = ready.inspect(backend, project_root=project.path, binding=binding)
    assert result["x11"]["status"] == result["rfb"]["status"] == "unknown"


def test_runtime_replacement_and_changed_boot_or_endpoint_are_unknown(model, monkeypatch):
    backend, project, binding, root = model
    def replace(path, **kw):
        if kw["x11"]:
            store = RuntimeReferenceStore(project.runtime_reference_file)
            refs = store.load()
            from dataclasses import replace as dataclass_replace
            refs["desktop-id"] = dataclass_replace(
                refs["desktop-id"], state=ApplicationRuntimeState.TERMINATED)
            store.save(refs)
        return {"status": "confirmed", "code": "ok"}
    monkeypatch.setattr(ready, "_probe", replace)
    assert ready.inspect(backend, project_root=project.path, binding=binding)["x11"]["status"] == "unknown"
    wrong_boot = dict(binding, boot_id="old-boot")
    assert ready.inspect(backend, project_root=project.path, binding=wrong_boot)["rfb"]["status"] == "unknown"


def test_probe_exception_and_endpoint_substitution_fail_closed(model, monkeypatch):
    backend, project, binding, root = model
    def interrupt(path, **kw):
        if kw["x11"]:
            (root / "run" / "vnc.sock").unlink()
            (root / "run" / "vnc.sock").touch()
        raise OSError("private socket path and cookie must never leak")
    monkeypatch.setattr(ready, "_probe", interrupt)
    result = ready.inspect(backend, project_root=project.path, binding=binding)
    assert result["x11"]["status"] == "unknown"
    assert "socket path" not in repr(result)


def test_root_operation_is_nonmutating_and_unknown_on_missing_endpoint(model, monkeypatch):
    backend, project, binding, root = model
    before = {p: p.read_bytes() for p in project.state_dir.rglob("*.json")}
    (root / "x11" / "X1").unlink()
    result = ready.inspect(backend, project_root=project.path, binding=binding)
    assert len(result["endpoint_identity"]) == 64
    assert result["x11"]["status"] == result["rfb"]["status"] == "unknown"
    assert before == {p: p.read_bytes() for p in project.state_dir.rglob("*.json")}


def test_rfb_socket_loss_does_not_suppress_independent_x11_confirmation(
        model, monkeypatch):
    backend, project, binding, root = model
    (root / "run" / "vnc.sock").unlink()
    monkeypatch.setattr(ready.socket, "socket", lambda *a, **k: FakeSocket())
    stage = ready.inspect(backend, project_root=project.path, binding=binding)
    assert stage["x11"] == {"status": "confirmed", "code": "ok"}
    assert stage["rfb"] == {"status": "unknown", "code": "probe-unavailable"}
    assert len(stage["endpoint_identity"]) == 64
