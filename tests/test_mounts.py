import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from zog.box_control import Project
from zog.box_control.model import ApplicationRuntimeState
from zog.box_control.runtime.reference import (
    ApplicationRuntimeReference,
    ProgramRuntimeReference,
    RuntimeReferenceStore,
)
from zog.root_control import mounts as m
from zog.root_control.daemon import RootControlDaemon


BOOT = "b" * 32
INVOCATION = "a" * 32


def _stat(pid, started=123):
    return f"{pid} (mount probe) S 1 " + "0 " * 17 + str(started) + " 0\n"


def _mount_line(number, destination, access="ro"):
    return (
        f"{number} 1 8:1 / {destination} {access},relatime - ext4 /dev/root {access}\n"
    )


def _write_process(proc, pid, group, namespace, mountinfo, namespace_root):
    path = proc / str(pid)
    path.mkdir(parents=True)
    (path / "stat").write_text(_stat(pid))
    (path / "cgroup").write_text("0::" + group + "\n")
    (path / "mountinfo").write_text(mountinfo)
    (path / "ns").mkdir()
    (path / "ns/mnt").symlink_to(namespace)
    (path / "root").symlink_to(namespace_root, target_is_directory=True)


def _reference(project, root_source, artifact_source, view_source, data_source, *, members=1, inventory=True):
    programs = []
    for index in range(members):
        name = "web" if index == 0 else f"helper-{index}"
        properties = (
            ("RootDirectory", str(root_source)),
            ("ProtectSystem", "strict"),
            ("BindReadOnlyPaths", [
                [str(artifact_source), "/applications/.store/" + "c" * 64],
                [str(view_source), "/applications/station-access"],
            ]),
            ("BindPaths", [[str(data_source), "/data"]]),
        )
        mount_inventory = None if not inventory else {
            "mounts": [
                {
                    "destination": "/applications/.store/" + "c" * 64,
                    "access": "read-only",
                    "kind": "application-software-artifact",
                },
                {
                    "destination": "/applications/station-access",
                    "access": "read-only",
                    "kind": "application-software-view",
                },
                {
                    "destination": "/data",
                    "access": "read-write",
                    "kind": "application-data",
                },
            ]
        }
        programs.append(
            ProgramRuntimeReference(
                program=name,
                unit_name=f"zog-{name}.service",
                invocation_id=INVOCATION,
                expected_properties=properties,
                mount_inventory=mount_inventory,
            )
        )
    reference = ApplicationRuntimeReference(
        runtime_id="ABCDEF",
        application="station-access",
        instance_id="station-access",
        generation="generation",
        state=ApplicationRuntimeState.RUNNING,
        boot_id=BOOT,
        programs=tuple(programs),
    )
    RuntimeReferenceStore(project.runtime_reference_file).save({"ABCDEF": reference})
    return reference


@pytest.fixture
def observed(tmp_path, monkeypatch):
    project = Project(tmp_path / "project")
    project.state_dir.mkdir(parents=True)
    root_source = tmp_path / "runtime-root"
    artifact_source = tmp_path / "artifact"
    view_source = tmp_path / "view"
    data_source = tmp_path / "data"
    for path in (root_source, artifact_source, view_source, data_source):
        path.mkdir()
    (root_source / "applications/.store").mkdir(parents=True)
    (root_source / ("applications/.store/" + "c" * 64)).symlink_to(
        artifact_source, target_is_directory=True
    )
    (root_source / "applications/station-access").symlink_to(
        view_source, target_is_directory=True
    )
    (root_source / "data").symlink_to(data_source, target_is_directory=True)

    reference = _reference(project, root_source, artifact_source, view_source, data_source)
    proc = tmp_path / "proc"
    cg = tmp_path / "cg"
    (cg / "unit").mkdir(parents=True)
    (cg / "unit/cgroup.procs").write_text("10\n")
    mountinfo = (
        _mount_line(1, "/", "ro")
        + _mount_line(2, "/applications/.store/" + "c" * 64, "ro")
        + _mount_line(3, "/applications/station-access", "ro")
        + _mount_line(4, "/data", "rw")
    )
    _write_process(proc, 10, "/unit", "mnt:[4026532000]", mountinfo, root_source)
    monkeypatch.setattr(m, "current_boot_id", lambda: BOOT)
    monkeypatch.setattr(m, "_unit", lambda backend, project, unit: (INVOCATION, "/unit"))
    backend = SimpleNamespace(deadline=None)
    return SimpleNamespace(
        project=project,
        reference=reference,
        proc=proc,
        cg=cg,
        backend=backend,
        root_source=root_source,
        artifact_source=artifact_source,
        view_source=view_source,
        data_source=data_source,
    )


def inspect(fixture):
    return m.inspect_runtime_mounts(
        project_root=fixture.project.path,
        runtime_id="ABCDEF",
        _proc_root=fixture.proc,
        _cgroup_root=fixture.cg,
        _backend=fixture.backend,
    )


def test_exact_expected_mounts_and_backing_are_observed(observed):
    result = inspect(observed)
    assert result["schema"] == "zog-runtime-mount-observation-v1"
    assert result["basis"] == "kernel-mount-namespace"
    assert result["snapshot"] == "non-atomic"
    assert result["status"] == "observed"
    program = result["programs"][0]
    assert program["status"] == "observed"
    assert program["mount_namespace"] == "mnt:[4026532000]"
    assert program["multiple_mount_namespaces"] is False
    mounts = {item["destination"]: item for item in program["mounts"]}
    assert mounts["/"]["observed_access"] == "read-only"
    assert mounts["/"]["backing_identity"] == "verified"
    artifact = mounts["/applications/.store/" + "c" * 64]
    assert artifact["kind"] == "application-software-artifact"
    assert artifact["observed_access"] == "read-only"
    assert artifact["backing_identity"] == "verified"
    assert mounts["/applications/station-access"] == {
        "destination": "/applications/station-access",
        "kind": "application-software-view",
        "expected_access": "read-only",
        "observed_presence": "present",
        "observed_access": "read-only",
        "backing_identity": "verified",
    }
    assert mounts["/data"]["expected_access"] == "read-write"
    assert mounts["/data"]["observed_access"] == "read-write"
    assert mounts["/data"]["backing_identity"] == "verified"
    encoded = json.dumps(result)
    assert str(observed.root_source) not in encoded
    assert str(observed.artifact_source) not in encoded
    assert str(observed.view_source) not in encoded
    assert str(observed.data_source) not in encoded


@pytest.mark.parametrize(
    "destination,access",
    [
        ("/applications/station-access", "rw"),
        ("/data", "ro"),
    ],
)
def test_wrong_access_is_integrity_fault(observed, destination, access):
    path = observed.proc / "10/mountinfo"
    lines = path.read_text().splitlines()
    changed = []
    for line in lines:
        fields = line.split()
        if fields[4] == destination:
            fields[5] = access + ",relatime"
            fields[-1] = access
            line = " ".join(fields)
        changed.append(line)
    path.write_text("\n".join(changed) + "\n")
    result = inspect(observed)
    assert result["status"] == "integrity-fault"
    item = next(
        mount
        for mount in result["programs"][0]["mounts"]
        if mount["destination"] == destination
    )
    assert item["observed_access"] == (
        "read-write" if access == "rw" else "read-only"
    )


def test_missing_expected_mount_is_integrity_fault(observed):
    path = observed.proc / "10/mountinfo"
    path.write_text(
        _mount_line(1, "/", "ro")
        + _mount_line(2, "/applications/.store/" + "c" * 64, "ro")
        + _mount_line(3, "/applications/station-access", "ro")
    )
    result = inspect(observed)
    assert result["status"] == "integrity-fault"
    data = next(
        item for item in result["programs"][0]["mounts"]
        if item["destination"] == "/data"
    )
    assert data["observed_presence"] == "missing"


def test_wrong_backing_identity_is_integrity_fault(observed):
    replacement = observed.root_source / "applications/station-access"
    replacement.unlink()
    wrong = observed.root_source.parent / "wrong-view"
    wrong.mkdir()
    replacement.symlink_to(wrong, target_is_directory=True)
    result = inspect(observed)
    assert result["status"] == "integrity-fault"
    view = next(
        item for item in result["programs"][0]["mounts"]
        if item["destination"] == "/applications/station-access"
    )
    assert view["backing_identity"] == "mismatch"


def test_invocation_and_boot_identity_fail_closed(observed, monkeypatch):
    monkeypatch.setattr(
        m, "_unit", lambda backend, project, unit: ("c" * 32, "/unit")
    )
    assert inspect(observed)["status"] == "integrity-fault"
    monkeypatch.setattr(m, "_unit", lambda backend, project, unit: (INVOCATION, "/unit"))
    monkeypatch.setattr(m, "current_boot_id", lambda: "d" * 32)
    assert inspect(observed)["status"] == "previous-boot"


def test_process_disappearance_and_pid_reuse_are_changed_during_read(observed, monkeypatch):
    original = m._read
    stat_reads = 0

    def reused(directory, name, maximum=16384):
        nonlocal stat_reads
        data, cut = original(directory, name, maximum)
        if name == "stat":
            stat_reads += 1
            if stat_reads >= 2:
                return _stat(10, 999).encode(), False
        return data, cut

    monkeypatch.setattr(m, "_read", reused)
    assert inspect(observed)["status"] == "changed-during-read"

    monkeypatch.setattr(m, "_read", original)
    (observed.proc / "10").rename(observed.proc / "gone")
    assert inspect(observed)["status"] == "changed-during-read"


def test_distinct_mount_namespaces_are_reported_explicitly(observed):
    (observed.cg / "unit/cgroup.procs").write_text("10\n11\n")
    _write_process(
        observed.proc,
        11,
        "/unit",
        "mnt:[4026532001]",
        (observed.proc / "10/mountinfo").read_text(),
        observed.root_source,
    )
    result = inspect(observed)
    program = result["programs"][0]
    assert program["status"] == "observed"
    assert program["multiple_mount_namespaces"] is True
    assert program["mount_namespace"] is None
    assert [item["mount_namespace"] for item in program["mount_namespaces"]] == [
        "mnt:[4026532000]",
        "mnt:[4026532001]",
    ]


def test_legacy_mount_inventory_and_missing_runtime(observed):
    _reference(
        observed.project,
        observed.root_source,
        observed.artifact_source,
        observed.view_source,
        observed.data_source,
        inventory=False,
    )
    result = inspect(observed)
    assert result["status"] == "legacy-unrecorded"
    with pytest.raises(ValueError, match="unknown or pruned"):
        m.inspect_runtime_mounts(
            project_root=observed.project.path,
            runtime_id="ZZZZZZ",
            _proc_root=observed.proc,
            _cgroup_root=observed.cg,
            _backend=observed.backend,
        )


def test_multiple_services_are_observed_independently(observed, monkeypatch):
    _reference(
        observed.project,
        observed.root_source,
        observed.artifact_source,
        observed.view_source,
        observed.data_source,
        members=2,
    )
    (observed.cg / "helper").mkdir()
    (observed.cg / "helper/cgroup.procs").write_text("11\n")
    _write_process(
        observed.proc,
        11,
        "/helper",
        "mnt:[4026532002]",
        (observed.proc / "10/mountinfo").read_text(),
        observed.root_source,
    )

    def unit(_backend, _project, name):
        return (INVOCATION, "/helper" if "helper" in name else "/unit")

    monkeypatch.setattr(m, "_unit", unit)
    result = inspect(observed)
    assert result["status"] == "observed"
    assert [(item["program"], item["mount_namespace"]) for item in result["programs"]] == [
        ("web", "mnt:[4026532000]"),
        ("helper-1", "mnt:[4026532002]"),
    ]


def test_malformed_mountinfo_is_unavailable(observed):
    (observed.proc / "10/mountinfo").write_text("not mountinfo\n")
    assert inspect(observed)["status"] == "unavailable"


def test_truncated_mountinfo_preserves_unknown_not_false_missing(observed, monkeypatch):
    original = m._read

    def truncated(directory, name, maximum=16384):
        if name == "mountinfo":
            return _mount_line(1, "/", "ro").encode(), True
        return original(directory, name, maximum)

    monkeypatch.setattr(m, "_read", truncated)
    result = inspect(observed)
    assert result["status"] == "partial"
    view = next(
        item for item in result["programs"][0]["mounts"]
        if item["destination"] == "/applications/station-access"
    )
    assert view["observed_presence"] == "unknown"
    assert view["backing_identity"] == "inconclusive"


def test_mountinfo_escape_validation():
    parsed, truncated = m._parse_mountinfo(
        b"1 0 8:1 / /applications/a\\040b ro - ext4 /dev/root ro\n"
    )
    assert "/applications/a b" in parsed
    assert not truncated
    with pytest.raises(ValueError, match="escape"):
        m._parse_mountinfo(
            b"1 0 8:1 / /applications/bad\\xyz ro - ext4 /dev/root ro\n"
        )


def test_read_only_rpc_accepts_only_runtime_identity(observed, monkeypatch):
    marker = observed.project.state_dir / "mutation-incomplete.json"
    marker.write_text("{}")
    before = {
        str(path): path.read_bytes()
        for path in observed.project.path.rglob("*")
        if path.is_file()
    }
    expected = {
        "schema": m.SCHEMA,
        "runtime_id": "ABCDEF",
        "basis": "kernel-mount-namespace",
        "snapshot": "non-atomic",
        "observed_at": 0.0,
        "recorded_boot_id": BOOT,
        "status": "observed",
        "programs": [],
        "truncated": False,
    }
    monkeypatch.setattr(m, "inspect_runtime_mounts", lambda **kwargs: expected)
    daemon = RootControlDaemon(observed.project.path / "unused", systemd_backend=object())
    assert daemon.handle(
        {
            "operation": "application_runtime_mounts",
            "project_root": str(observed.project.path),
            "runtime_id": "ABCDEF",
        }
    )["result"] == expected
    with pytest.raises(ValueError, match="unsupported"):
        daemon.handle(
            {
                "operation": "application_runtime_mounts",
                "project_root": str(observed.project.path),
                "runtime_id": "ABCDEF",
                "pid": 10,
            }
        )
    assert {
        str(path): path.read_bytes()
        for path in observed.project.path.rglob("*")
        if path.is_file()
    } == before


def test_mount_namespace_change_and_timeout_are_explicit(observed, monkeypatch):
    original_namespace = m._namespace
    calls = 0

    def changing(directory):
        nonlocal calls
        calls += 1
        if calls >= 2:
            return "mnt:[4026532999]"
        return original_namespace(directory)

    monkeypatch.setattr(m, "_namespace", changing)
    assert inspect(observed)["status"] == "changed-during-read"

    monkeypatch.setattr(m, "_namespace", original_namespace)
    monkeypatch.setattr(
        m,
        "_observe_namespace",
        lambda *args, **kwargs: (_ for _ in ()).throw(TimeoutError("deadline")),
    )
    result = inspect(observed)
    assert result["status"] == "partial"
    assert result["programs"][0]["truncated"] is True



def test_unverifiable_backing_is_partial_not_healthy(observed):
    observed.view_source.rmdir()
    result = inspect(observed)
    assert result["status"] == "partial"
    view = next(
        item for item in result["programs"][0]["mounts"]
        if item["destination"] == "/applications/station-access"
    )
    assert view["observed_presence"] == "present"
    assert view["observed_access"] == "read-only"
    assert view["backing_identity"] == "inconclusive"


def test_duplicate_observed_mount_destination_is_integrity_fault(observed):
    path = observed.proc / "10/mountinfo"
    path.write_text(
        path.read_text()
        + _mount_line(99, "/applications/station-access", "ro")
    )
    result = inspect(observed)
    assert result["status"] == "integrity-fault"
    view = next(
        item for item in result["programs"][0]["mounts"]
        if item["destination"] == "/applications/station-access"
    )
    assert view["observed_presence"] == "inconsistent"
    assert view["backing_identity"] == "inconclusive"
