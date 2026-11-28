"""Exact pair with real root peer and foreign-owned disposable Project.

Fixture permissions are synthetic, not recommended changes to the real Host.
PID1 is mocked; client, daemon, local journals and socket are real.
"""
import json
import os
import socket
import shutil
import stat
from pathlib import Path
from threading import Thread, Event, BoundedSemaphore

import pytest

from zog.box_control.api import BoxControl
from zog.box_control.errors import RecoveryRequired
from zog.box_control.project import Project
from zog.box_control.build_jobs import BuildJobs
from zog.box_control.locking import ProjectLock
from zog.box_control.runtime.root_control import RootControlSystemdTransport
from zog.root_control.build import BuildBackend
from zog.root_control.daemon import RootControlDaemon
from zog.root_control.protocol import decode
from .test_build_backend import Systemd
from .test_build_rpc_envelope import JOB, RID


@pytest.mark.skipif((os.geteuid(), os.getegid()) != (0, 0),
                    reason="requires actual root 0:0 CI process")
def test_exact_pair_selected_foreign_owned_project(tmp_path, monkeypatch):
    home = tmp_path / "home" / "certbot-build-owner"
    project = home / "certbot-seed"
    attempt = project / "state/image-build/attempts/pair"
    prepared, source, output = (attempt / name for name in ("root", "source", "output"))
    (prepared / "bin").mkdir(parents=True)
    source.mkdir()
    output.mkdir()
    (prepared / "bin/cc").write_text("mock executable")
    (prepared / "bin/cc").chmod(0o755)
    (source / "input").write_text("original data")
    for path in (home, *home.rglob("*")):
        os.chown(path, 24201, 24201)
        if path.is_dir():
            path.chmod(0o755)
    output.chmod(0o777)
    original = {p: (p.stat().st_uid, p.stat().st_gid,
                    stat.S_IMODE(p.stat().st_mode), p.stat().st_ino)
                for p in (home, *home.rglob("*"))}
    assert not project.is_relative_to(Path.home().resolve())
    assert project.stat().st_uid == 24201

    sys = Systemd()
    sys.version = lambda: 252
    backend = BuildBackend(sys, tmp_path / "privileged")
    path = tmp_path / "pair.sock"
    daemon = RootControlDaemon(path)
    daemon.build = backend
    operations, failure = [], []
    done = Event()
    unloaded = set()

    def observe(*, project_root, unit_name):
        if unit_name in unloaded or not unit_name.endswith(".service"):
            return {"exists": False}
        records = list((backend.resource_path(project, RID) / "jobs").glob("*.json"))
        assert len(records) == 1
        info = json.loads(records[0].read_text())
        return dict(exists=True, unit_name=unit_name, transient=True,
                    active_state="inactive", control_group=None,
                    properties=backend.expected_properties(backend.resource_path(project, RID), info),
                    result="success", invocation_id="a"*32)
    sys.observe = observe
    sys._get_unit_path = lambda unit: "/fake/systemd/unit"
    values = dict(PrivateNetwork=True, NoNewPrivileges=True,
                  CapabilityBoundingSet=0, RuntimeMaxUSec=8_000_000,
                  ExecMainCode=1, ExecMainStatus=0,
                  ExecMainExitTimestampMonotonic=1234)
    sys._get_property = lambda unit, interface, key: values[key]
    sys.stop = lambda **kw: None
    sys.reset_failed = lambda **kw: None
    sys.release = lambda **kw: unloaded.add(kw["unit_name"])

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(str(path))
        server.listen(4)
        server.settimeout(0.2)
        def serve():
            try:
                while not done.is_set():
                    try:
                        conn, _ = server.accept()
                    except socket.timeout:
                        continue
                    with conn:
                        peer = daemon._kernel_peer(conn)
                        assert peer == (0, 0)
                        request = decode(conn)
                        operations.append(request["operation"])
                        slot = BoundedSemaphore(1)
                        slot.acquire()
                        daemon._serve_request(conn, request, slot, peer=peer)
            except BaseException as exc:
                failure.append(exc)
        thread = Thread(target=serve, daemon=True)
        thread.start()
        try:
            transport = RootControlSystemdTransport(path, timeout_seconds=10)
            control = BoxControl(Project(project), systemd_transport=transport)
            fields = dict(resource_id=RID, prepared_root=str(prepared),
                          source_directory=str(source), output_directory=str(output),
                          input_manifest_id="pair-fixture")
            result = control.register_build_root(**fields)
            assert result["state"] == "ready"
            assert result["execution_contract"] == "zog-build-inherited-peer-v2"
            remote = control.inspect_build_root(RID)
            assert remote["execution_identity"] == {"uid": 0, "gid": 0}
            assert remote["schema"] == 2 and remote["state"] == "ready"
            request = dict(JOB, command=["cc", "$IMAGE_BUILD_SOURCE", "awk '{print $1}'"])
            request_id = control.issue_build_request_id()
            job = control.submit_build_job(request_id=request_id, **request)
            assert job["outcome"] == "success" and job["process_cleanup_complete"]
            assert control.submit_build_job(request_id=request_id, **request) == job
            assert operations.count("build_start") == 1
            props = sys.properties
            assert props["User"].value == props["Group"].value == "0"
            assert props["PrivateNetwork"].value and props["NoNewPrivileges"].value
            assert props["CapabilityBoundingSet"].value == 0
            assert props["MemoryMax"].value == request["resource_limits"]["memory-maximum-bytes"]
            assert props["ExecStart"].value == [[
                "/bin/cc", ["/bin/cc", "$$IMAGE_BUILD_SOURCE", "awk '{print $$1}'"], False]]
            transport.build_call("cancel", project_root=project, job_id=job["job_id"],
                                 build_root_id=RID, expected_invocation_id=job["invocation_id"])
            control.release_build_job(job["job_id"])
            control.release_build_root(RID)
            monkeypatch.setattr("time.time", lambda: job["completed_at"] + 49*3600)
            resource = backend.resource_path(project, RID)
            journal = control.project.state_dir / "build-pruning.json"
            original_remove = shutil.rmtree
            original_respond = daemon._respond
            faults = []
            def interrupt_remove(target, *args, **kwargs):
                if target == resource and not faults:
                    (resource / "registration.json").unlink()
                    faults.append("registration-removed")
                    raise OSError("injected partial privileged deletion")
                return original_remove(target, *args, **kwargs)
            def lose_reply(conn, response, **kwargs):
                if (operations[-1] == "build_forget" and response.get("ok")
                        and faults == ["registration-removed"]):
                    faults.append("reply-lost")
                    return  # The actual server closes the socket without replying.
                return original_respond(conn, response, **kwargs)
            monkeypatch.setattr(shutil, "rmtree", interrupt_remove)
            monkeypatch.setattr(daemon, "_respond", lose_reply)
            for boundary in ("registration-removed", "reply-lost"):
                with ProjectLock(control.project.lock_file):
                    with pytest.raises(RecoveryRequired):
                        BuildJobs(control).prune()
                assert faults[-1] == boundary
                entry = json.loads(journal.read_text())["deletions"][0]
                assert entry["resource_id"] == RID and entry["forgotten"] is False
                assert BuildJobs(control).path("resource:" + RID).exists()
                assert BuildJobs(control).path("job:" + job["job_id"]).exists()
                if boundary == "registration-removed":
                    assert resource.exists() and not (resource / "registration.json").exists()
                    assert list((resource / "jobs").glob("*.json"))
                    assert json.loads(backend._forget_path(resource).read_text())["state"] == "deleting"
                else:
                    assert not resource.exists()
                    assert json.loads(backend._forget_path(resource).read_text())["state"] == "forgotten"
                # Reconstruct the privileged backend: recovery must depend on disk.
                backend = BuildBackend(sys, backend.directory)
                daemon.build = backend
            with ProjectLock(control.project.lock_file):
                BuildJobs(control).prune()
            assert not resource.exists() and not journal.exists()
            assert not BuildJobs(control).path("resource:" + RID).exists()
            assert not BuildJobs(control).path("job:" + job["job_id"]).exists()
            assert operations.count("build_forget") == 3
            assert set(operations) == {"build_" + op for op in (
                "register", "registration_status", "prepare", "start", "observe",
                "cleanup", "cancel", "release", "forget")}
            assert operations.count("build_start") == 1
            for p, before in original.items():
                info = p.stat()
                assert (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode),
                        info.st_ino) == before, str(p)
            assert (source / "input").read_text() == "original data"
        finally:
            done.set()
            thread.join(timeout=12)
        assert not thread.is_alive() and not failure
