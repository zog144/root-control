"""Regression tests for immutable-runtime kernel credential observation."""
from dataclasses import replace
from types import SimpleNamespace
import json
from pathlib import Path

import pytest

from zog.box_control.model import ApplicationRuntimeState
from zog.box_control.project import Project
from zog.box_control.runtime.reference import (
    ApplicationRuntimeReference, ProgramRuntimeReference, RuntimeReferenceStore,
)
from zog.root_control import credentials as c
from zog.root_control.daemon import RootControlDaemon


def _stat(pid, start=123):
    return f"{pid} (process name) with ) S 1 " + "0 " * 17 + str(start) + " 0\n"


def _proc(root, pid=50, *, uid=29001, gid=29002, groups=None):
    folder = root / str(pid)
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "stat").write_text(_stat(pid))
    (folder / "cgroup").write_text("0::/app.service\n")
    if groups is None:
        groups = (gid,)
    (folder / "status").write_text(
        f"Name:\tprocess\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n"
        f"Gid:\t{gid}\t{gid}\t{gid}\t{gid}\n"
        "Groups:\t" + " ".join(map(str, groups)) + "\n"
    )


def _setup(tmp_path, monkeypatch, *, bound=True):
    project = Project(tmp_path / "project")
    proc = tmp_path / "proc"
    _proc(proc)
    uid, gid = 29001, 29002
    grant = (dict(schema="zog-execution-identity-v1",
                  grant_id="a" * 32, version=1,
                  project=str(project.path), application="portal",
                  uid=uid, gid=gid) if bound else None)
    program = ProgramRuntimeReference(
        program="web", unit_name="zog-portal.service", invocation_id="i" * 32,
        expected_properties=(("User", str(uid)), ("Group", str(gid))),
    )
    ref = ApplicationRuntimeReference(
        "ABCDEF", "portal", "portal", "image",
        ApplicationRuntimeState.RUNNING, boot_id="b" * 32,
        execution_binding=grant, programs=(program,),
    )
    RuntimeReferenceStore(project.runtime_reference_file).save({"ABCDEF": ref})
    monkeypatch.setattr(c, "current_boot_id", lambda: "b" * 32)
    monkeypatch.setattr(c, "_unit", lambda *args: ("i" * 32, "/app.service"))
    monkeypatch.setattr(c, "_scan", lambda *args, **kwargs: {
        "processes": [{"pid": 50, "start_time_ticks": 123}],
        "skipped_processes": 0, "truncated": False,
    })
    args = dict(project_root=str(project.path), runtime_id="ABCDEF",
                proc_root=proc, backend=SimpleNamespace())
    return project, proc, args, ref


def test_kernel_four_uid_gid_fields_and_supplementary_group_match(tmp_path, monkeypatch):
    _project, _procdir, args, _ref = _setup(tmp_path, monkeypatch)
    result = c.inspect_runtime_credentials(**args)
    assert result["status"] == "observed"
    program = result["programs"][0]
    assert program["status"] == "observed"
    assert program["recorded_invocation_id"] == "i" * 32
    assert program["control_group"] == "/app.service"
    record = program["processes"][0]
    assert record["uid"] == [29001] * 4
    assert record["gid"] == [29002] * 4
    assert record["supplementary_groups"] == [29002]
    assert record["start_time_ticks"] == 123
    assert record["comparison"] == "match"
    json.dumps(result)


@pytest.mark.parametrize("uid,gid,groups", [
    (29003, 29002, (29002,)),
    (29001, 29003, (29003,)),
    (29001, 29002, (29002, 0)),
])
def test_mismatched_process_credentials_detected(tmp_path, monkeypatch, uid, gid, groups):
    _project, proc, args, _ref = _setup(tmp_path, monkeypatch)
    _proc(proc, uid=uid, gid=gid, groups=groups)
    outcome = c.inspect_runtime_credentials(**args)
    assert outcome["status"] == "credential-mismatch"
    assert outcome["programs"][0]["processes"][0]["comparison"] == "mismatch"


def test_legacy_unbound_never_claims_verified(tmp_path, monkeypatch):
    _project, _procdir, args, _ref = _setup(tmp_path, monkeypatch, bound=False)
    result = c.inspect_runtime_credentials(**args)
    assert result["status"] == "legacy-unbound"
    assert result["programs"][0]["processes"][0]["comparison"] == "unbound"


@pytest.mark.parametrize("change", ["missing-invocation", "different-boot", "foreign-invocation",
                                    "unit-unloaded", "altered-expectation", "wrong-grant-scope"])
def test_identity_guards_fail_closed(tmp_path, monkeypatch, change):
    project, proc, args, ref = _setup(tmp_path, monkeypatch)
    if change == "missing-invocation":
        ref = replace(ref, programs=(replace(ref.programs[0], invocation_id=None),))
    elif change == "different-boot":
        monkeypatch.setattr(c, "current_boot_id", lambda: "other-boot")
    elif change == "foreign-invocation":
        monkeypatch.setattr(c, "_unit", lambda *args: ("x" * 32, "/app.service"))
    elif change == "unit-unloaded":
        monkeypatch.setattr(c, "_unit", lambda *args: None)
    elif change == "altered-expectation":
        ref = replace(ref, programs=(replace(ref.programs[0],
            expected_properties=(("User", "29090"), ("Group", "29002"))),))
    elif change == "wrong-grant-scope":
        ref = replace(ref, execution_binding=dict(ref.execution_binding, application="foreign"))
    RuntimeReferenceStore(project.runtime_reference_file).save({"ABCDEF": ref})
    result = c.inspect_runtime_credentials(**args)
    # A missing invocation can aggregate as partial; neither state claims verified identity.
    assert result["status"] in {"identity-unavailable", "previous-boot", "integrity-fault", "absent", "partial"}
    assert not any(p.get("status") == "observed" for p in result["programs"])


def test_process_pid_start_tick_reuse_and_cgroup_migration_are_not_accepted(tmp_path, monkeypatch):
    project, proc, args, _ref = _setup(tmp_path, monkeypatch)
    (proc / "50" / "stat").write_text(_stat(50, 456))
    result = c.inspect_runtime_credentials(**args)
    assert result["status"] == "partial"
    assert result["programs"][0]["processes"] == []
    (proc / "50" / "stat").write_text(_stat(50))
    (proc / "50" / "cgroup").write_text("0::/foreign.service\n")
    assert c.inspect_runtime_credentials(**args)["status"] == "partial"


def test_changing_process_credentials_between_reads_is_partial(tmp_path, monkeypatch):
    _project, proc, args, _ref = _setup(tmp_path, monkeypatch)
    original = c._read
    count = 0
    def read(directory, name, maximum=16384):
        nonlocal count
        data = original(directory, name, maximum)
        if name == "status":
            count += 1
            if count == 2:
                return data[0].replace(b"29001", b"29003"), data[1]
        return data
    monkeypatch.setattr(c, "_read", read)
    outcome = c.inspect_runtime_credentials(**args)
    assert outcome["status"] == "partial"
    assert outcome["programs"][0]["processes"] == []


def test_changing_systemd_invocation_discards_all_rows(tmp_path, monkeypatch):
    _project, _procdir, args, _ref = _setup(tmp_path, monkeypatch)
    seen = iter([("i" * 32, "/app.service"), ("different", "/app.service")])
    monkeypatch.setattr(c, "_unit", lambda *args: next(seen))
    result = c.inspect_runtime_credentials(**args)
    assert result["status"] == "changed-during-read"
    assert result["programs"][0]["processes"] == []


def test_incomplete_scan_does_not_claim_authoritative_success(tmp_path, monkeypatch):
    _project, _procdir, args, _ref = _setup(tmp_path, monkeypatch)
    monkeypatch.setattr(c, "_scan", lambda *args, **kw: {
        "processes": [{"pid": 50, "start_time_ticks": 123}],
        "skipped_processes": 2, "truncated": False,
    })
    assert c.inspect_runtime_credentials(**args)["status"] == "partial"
    monkeypatch.setattr(c, "_scan", lambda *args, **kw: {
        "processes": [], "skipped_processes": 0, "truncated": False,
    })
    assert c.inspect_runtime_credentials(**args)["status"] == "absent"


def test_read_only_daemon_api_and_untrusted_pid_arguments(tmp_path, monkeypatch):
    project, _procdir, args, _ref = _setup(tmp_path, monkeypatch)
    before = {str(p): p.read_bytes() for p in project.path.rglob("*") if p.is_file()}
    actual_inspect = c.inspect_runtime_credentials
    monkeypatch.setattr(c, "inspect_runtime_credentials",
                        lambda **kwargs: {"schema": c.SCHEMA, "runtime_id": kwargs["runtime_id"],
                                          "status": "absent", "programs": []})
    daemon = RootControlDaemon(project.path / "unused", systemd_backend=object())
    output = daemon.handle(dict(operation="application_runtime_credentials",
                                project_root=str(project.path), runtime_id="ABCDEF"))
    assert output["ok"] and output["result"]["status"] == "absent"
    assert {str(p): p.read_bytes() for p in project.path.rglob("*") if p.is_file()} == before
    with pytest.raises(ValueError):
        daemon.handle(dict(operation="application_runtime_credentials",
                           project_root=str(project.path), runtime_id="ABCDEF", pid=1))
    with pytest.raises(ValueError):
        actual_inspect(project_root=str(project.path),
                       runtime_id="ABCDEF", limit=65)



def test_empty_record_never_claims_absent_processes(tmp_path, monkeypatch):
    project, _procdir, args, ref = _setup(tmp_path, monkeypatch)
    no_members = replace(ref, programs=())
    RuntimeReferenceStore(project.runtime_reference_file).save({"ABCDEF": no_members})
    assert c.inspect_runtime_credentials(**args)["status"] == "identity-unavailable"


def test_malformed_grant_id_rejected_without_claiming_success(tmp_path, monkeypatch):
    project, _procdir, args, ref = _setup(tmp_path, monkeypatch)
    poisoned = replace(ref, execution_binding=dict(ref.execution_binding, grant_id="invalid"))
    RuntimeReferenceStore(project.runtime_reference_file).save({"ABCDEF": poisoned})
    assert c.inspect_runtime_credentials(**args)["status"] == "integrity-fault"
