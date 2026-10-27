"""Exact fresh compiler containment under the host-owned parent slice.

This file uses a fake PID1 adapter and does not start a native service.
"""
import json
import os
import stat
from pathlib import Path

import pytest

from zog.root_control.build import (
    BuildBackend, FRESH_COMPILER_PARENT_SLICE, FRESH_COMPILER_PROJECT,
)
from zog.root_control.systemd import BusctlSystemdBackend, SystemdBackendError


class ParentSystemd(BusctlSystemdBackend):
    def __init__(self):
        self.job_calls = []
        self.slice_requests = []
        self.parent_active = True
        self.parent_load_state = "loaded"
        self.parent_group = "/" + FRESH_COMPILER_PARENT_SLICE
        self.worker = None

    def version(self):
        return 252

    def _get_unit_path(self, unit):
        if unit == FRESH_COMPILER_PARENT_SLICE:
            return "/org/freedesktop/systemd1/unit/parent" if self.parent_active else None
        if self.worker and unit == self.worker["unit_name"]:
            return "/org/freedesktop/systemd1/unit/worker"
        return None

    def _get_property(self, obj, iface, name, **kwargs):
        if obj.endswith("parent"):
            return {
                "LoadState": self.parent_load_state,
                "ActiveState": "active" if self.parent_active else "inactive",
                "ControlGroup": self.parent_group,
            }[name]
        return {"PrivateNetwork": True, "NoNewPrivileges": True,
                "CapabilityBoundingSet": 0, "RuntimeMaxUSec": 8_000_000,
                "LogNamespace": "zogfreshcrossbootstrapoct25",
                "PrivateTmp": False, "PrivateMounts": True,
                "ProtectControlGroups": True, "Delegate": False,
                "ProtectKernelTunables": True, "RestrictNamespaces": 0, "LimitCORE": 0,
                "ExecMainCode": 1, "ExecMainStatus": 0,
                "ExecMainExitTimestampMonotonic": 1}.get(name)

    def start_slice(self, **kwargs):
        self._validate_unit(kwargs["project_root"], kwargs["slice_name"])
        self.slice_requests.append(kwargs)

    def _property(self, name, signature, *args):
        from dbus_next import Variant
        if signature == "a(sasb)":
            value = [[args[1], list(args[3:-1]), args[-1] == "true"]]
        elif signature == "as":
            value = list(args[1:])
        elif signature == "a(ssbt)":
            value = [[args[i], args[i+1], args[i+2] in (True, 'true'), args[i+3]]
                     for i in range(1, len(args), 4)]
        else:
            value = args[0]
            if signature == "b":
                value = value == "true" if isinstance(value, str) else bool(value)
        return [name, Variant(signature, value)]

    def _job(self, method, signature, body):
        self.job_calls.append((method, body))

    def observe(self, *, project_root, unit_name):
        self._validate_unit(project_root, unit_name)
        if self.worker and unit_name == self.worker["unit_name"]:
            return dict(self.worker)
        return {"exists": False}


@pytest.fixture
def bound(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "chown", lambda *args, **kwargs: None)
    owner = tmp_path / "owner"
    project = owner / FRESH_COMPILER_PROJECT
    attempt = project / "state/image-build/attempts/one"
    attempt.mkdir(parents=True)
    root, source, output = [attempt / name for name in ("root", "source", "output")]
    for path in (root, source, output):
        path.mkdir()
    (root / "bin").mkdir()
    (root / "bin/cc").write_text("fake")
    (root / "bin/cc").chmod(0o755)
    systemd = ParentSystemd()
    from types import SimpleNamespace
    from zog.root_control import build as build_mod
    fixed_work = tmp_path / "trusted-work"
    fixed_work.mkdir()
    monkeypatch.setattr(build_mod, "FRESH_COMPILER_BUILD_MOUNT", fixed_work)
    original_lstat = Path.lstat
    def trusted_scratch(self):
        actual = original_lstat(self)
        if self == fixed_work / ".zog-runtime" or self == fixed_work / ".zog-runtime" / ("c" * 32):
            return SimpleNamespace(st_mode=actual.st_mode, st_uid=0, st_gid=0,
                                   st_dev=actual.st_dev)
        return actual
    monkeypatch.setattr(Path, "lstat", trusted_scratch)
    backend = BuildBackend(
        systemd, tmp_path / "privileged",
        parent_slice=FRESH_COMPILER_PARENT_SLICE,
        authorized_project_root=str(project),
    )
    # The independent mount/identity cases exercise the real native guard;
    # this PID1 mock focuses only on typed worker properties.
    backend.directory = tmp_path / "privileged"
    backend.directory.mkdir()
    # CI simulates a second PID1-visible spelling of the same fixed source,
    # while the real code still rejects arbitrary/non-source paths.
    monkeypatch.setattr(build_mod, "FRESH_COMPILER_RESOURCES", backend.directory)
    monkeypatch.setattr(build_mod, "FRESH_COMPILER_RESOURCES_SOURCE",
                        fixed_work / "controller-build-resources")
    (fixed_work / "controller-build-resources").mkdir()
    backend._test_scratch_mount = fixed_work
    monkeypatch.setattr(backend, "_verify_fresh_storage", lambda *args, **kwargs: None)
    # PID1 path/inode tests below exercise the live verifier separately.
    monkeypatch.setattr(backend, "_verify_pid1_resource_visibility",
                        lambda *args, **kwargs: None)
    rid = "b" * 32
    jid = "c" * 32
    arguments = {
        "project_root": str(project), "resource_id": rid,
        "prepared_root": root, "source_directory": source,
        "output_directory": output, "input_manifest_id": "verified",
        "execution_user_id": 24302, "execution_group_id": 24302,
    }
    backend.register(**arguments)
    request = {
        "build_root_id": rid, "source_workspace_id": rid + "-source",
        "output_workspace_id": rid + "-output", "command": ["cc", "-v"],
        "environment": {"PATH": "/bin"}, "working_directory": "/image-build/source",
        "execution_user_id": 24302, "execution_group_id": 24302,
        "startup_timeout_seconds": 5, "execution_timeout_seconds": 8,
        "termination_grace_seconds": 2,
        "resource_limits": {
            "thread-count-maximum": 32, "memory-maximum-bytes": 10_000_000,
        },
        "read_only_root": True, "network_access": False,
    }
    return backend, systemd, arguments, request, jid


def test_fresh_parent_role_cannot_target_arbitrary_slice_or_project(tmp_path):
    for parent in ("system.slice", "zog.slice", "other.slice",
                   "zogfreshcrossbootstrapoct25-build" + "f" * 32 + ".slice"):
        with pytest.raises(SystemdBackendError, match="invalid bound"):
            BuildBackend(
                ParentSystemd(), tmp_path / "priv", parent_slice=parent,
                authorized_project_root="/home/owner/fresh-cross-bootstrap-oct25",
            )
    with pytest.raises(SystemdBackendError, match="invalid bound"):
        BuildBackend(
            ParentSystemd(), tmp_path / "priv",
            parent_slice=FRESH_COMPILER_PARENT_SLICE,
            authorized_project_root="/home/owner/not-the-fresh-project",
        )
    with pytest.raises(SystemdBackendError, match="unbound"):
        BuildBackend(ParentSystemd(), tmp_path / "priv",
                     authorized_project_root="/home/owner/fresh-cross-bootstrap-oct25")


def test_parent_binding_is_durable_before_worker_start(bound):
    backend, systemd, arguments, request, job = bound
    project = arguments["project_root"]
    path = backend.resource_path(project, arguments["resource_id"])
    registration = json.loads((path / "registration.json").read_text())
    assert registration["intent"]["parent_slice"] == FRESH_COMPILER_PARENT_SLICE
    assert registration["intent"]["log_namespace"] == "zogfreshcrossbootstrapoct25"
    prepared = backend.prepare(project_root=project, job_id=job, request=request)
    expected_child = "zogfreshcrossbootstrapoct25-build" + job + ".slice"
    assert prepared["parent_slice"] == FRESH_COMPILER_PARENT_SLICE
    assert prepared["log_namespace"] == "zogfreshcrossbootstrapoct25"
    assert prepared["slice_name"] == expected_child
    assert backend.prepare(project_root=project, job_id=job, request=request) == prepared
    assert systemd.job_calls == []
    backend.start(project_root=project, job_id=job, request=request)
    assert systemd.slice_requests[0]["slice_name"] == expected_child
    launched = systemd.job_calls[0]
    assert launched[0] == "StartTransientUnit"
    props = dict(launched[1][2])
    assert props["Slice"].value == expected_child
    assert props["LogNamespace"].value == "zogfreshcrossbootstrapoct25"
    assert props["StandardOutput"].value == "journal"
    assert props["StandardError"].value == "journal"
    assert props["PrivateTmp"].value is False
    assert props["PrivateMounts"].value is True
    assert props["ProtectControlGroups"].value is True
    assert props["Delegate"].value is False
    assert props["RestrictNamespaces"].value == 0
    assert props["LimitCORE"].value == 0
    binds = props["BindPaths"].value
    assert {b[1] for b in binds} >= {"/tmp", "/var/tmp", "/run", "/image-build/source", "/image-build/output"}
    assert all(b[0].startswith(str(backend._test_scratch_mount) + "/")
               for b in binds if b[1] in {"/tmp", "/var/tmp", "/run"})
    assert expected_child.startswith(FRESH_COMPILER_PARENT_SLICE[:-6] + "-")
    assert props["ExitType"].value == "cgroup"
    assert props["KillMode"].value == "control-group"
    assert props["Restart"].value == "no"
    assert json.loads((path / "jobs" / (job + ".json")).read_text())["start_attempted"] is True


@pytest.mark.parametrize("active,group", [
    (False, "/" + FRESH_COMPILER_PARENT_SLICE),
    (True, "/system.slice"),
    (True, "/zog.slice"),
])
def test_bad_parent_prevents_start_before_irreversible_attempt(bound, active, group):
    backend, systemd, args, request, job = bound
    systemd.parent_active = active
    systemd.parent_group = group
    path = backend.resource_path(args["project_root"], args["resource_id"])
    with pytest.raises(SystemdBackendError, match="parent slice"):
        backend.start(project_root=args["project_root"], job_id=job, request=request)
    saved = json.loads((path / "jobs" / (job + ".json")).read_text())
    assert "start_attempted" not in saved
    assert not systemd.slice_requests and not systemd.job_calls


def test_prepared_slice_and_registration_mismatch_fail_closed(bound):
    backend, systemd, args, request, job = bound
    project = args["project_root"]
    path = backend.resource_path(project, args["resource_id"])
    info = backend.prepare(project_root=project, job_id=job, request=request)
    target = path / "jobs" / (job + ".json")
    changed = dict(info, slice_name="zog-" + FRESH_COMPILER_PROJECT + "-build" + job + ".slice")
    target.write_text(json.dumps(changed))
    with pytest.raises(SystemdBackendError, match="slice differs"):
        backend.prepare(project_root=project, job_id=job, request=request)
    assert systemd.job_calls == []

    record = json.loads((path / "registration.json").read_text())
    record["intent"].pop("parent_slice")
    (path / "registration.json").write_text(json.dumps(record))
    with pytest.raises(SystemdBackendError, match="parent/logging binding"):
        backend.registration_status(project_root=project, resource_id=args["resource_id"])


def _active_worker(backend, systemd, args, request, jid):
    info = backend.start(project_root=args["project_root"], job_id=jid, request=request)
    path = backend.resource_path(args["project_root"], args["resource_id"])
    properties = backend.expected_properties(path, info)
    worker = {
        "exists": True, "unit_name": info["unit_name"], "active_state": "active",
        "control_group": "/" + FRESH_COMPILER_PARENT_SLICE + "/" + info["slice_name"]
                         + "/" + info["unit_name"],
        "invocation_id": "d" * 32,
        "properties": list(properties.items()),
    }
    systemd.worker = worker
    return info, path, worker


def test_worker_observe_checks_slice_property_and_real_cgroup(bound):
    backend, systemd, args, request, jid = bound
    info, path, worker = _active_worker(backend, systemd, args, request, jid)
    before = (path / "jobs" / (jid + ".json")).read_bytes()
    observation = backend.observe(project_root=args["project_root"], job_id=jid,
                                  build_root_id=args["resource_id"])
    assert observation["control_group"].startswith("/" + FRESH_COMPILER_PARENT_SLICE + "/")
    assert (path / "jobs" / (jid + ".json")).read_bytes() == before

    for changed in (
        "/system.slice/" + info["unit_name"],
        "/zog.slice/" + info["slice_name"] + "/" + info["unit_name"],
        "/" + FRESH_COMPILER_PARENT_SLICE + "/" + info["slice_name"] + "-other/" + info["unit_name"],
        None,
    ):
        worker["control_group"] = changed
        with pytest.raises(SystemdBackendError, match="protected (parent )?cgroup|lacks protected"):
            backend.observe(project_root=args["project_root"], job_id=jid,
                            build_root_id=args["resource_id"])
    worker["control_group"] = "/" + FRESH_COMPILER_PARENT_SLICE + "/" + info["slice_name"] + "/" + info["unit_name"]
    worker["properties"] = [(k, "other.slice" if k == "Slice" else v)
                             for k, v in worker["properties"]]
    with pytest.raises(SystemdBackendError, match="property mismatch: Slice"):
        backend.observe(project_root=args["project_root"], job_id=jid,
                        build_root_id=args["resource_id"])
    assert (path / "jobs" / (jid + ".json")).read_bytes() == before


def test_cleanup_fails_closed_on_escaped_worker_without_mutation(bound):
    backend, systemd, args, request, jid = bound
    info, path, worker = _active_worker(backend, systemd, args, request, jid)
    job_path = path / "jobs" / (jid + ".json")
    original = job_path.read_bytes()
    worker["control_group"] = "/system.slice/" + info["unit_name"]
    with pytest.raises(SystemdBackendError, match="outside bound parent"):
        backend.cleanup(project_root=args["project_root"], job_id=jid,
                        build_root_id=args["resource_id"])
    assert job_path.read_bytes() == original
    assert len(systemd.job_calls) == 1


def test_exact_fresh_slice_validator_never_grants_parent_or_other_project(tmp_path):
    validator = ParentSystemd()
    job = "a" * 32
    child = "zogfreshcrossbootstrapoct25-build" + job + ".slice"
    fresh = tmp_path / FRESH_COMPILER_PROJECT
    validator._validate_unit(fresh, child)
    for project in (tmp_path / "unrelated", tmp_path / "fresh-cross-bootstrap-oct24"):
        with pytest.raises(SystemdBackendError, match="does not belong"):
            validator._validate_unit(project, child)
    for unit in (FRESH_COMPILER_PARENT_SLICE, "system.slice",
                 "zogfreshcrossbootstrapoct25-build" + "g"*32 + ".slice",
                 "zogfreshcrossbootstrapoct25-build" + job + ".service",
                 "zogfreshcrossbootstrapoct25-build" + job + "x.slice"):
        with pytest.raises(SystemdBackendError, match="does not belong"):
            validator._validate_unit(fresh, unit)


def test_unscoped_shared_controller_retains_historical_worker_slice_names(tmp_path):
    legacy = BuildBackend(ParentSystemd(), tmp_path / "priv")
    assert legacy.parent_slice is None
    info = {
        "request": {"execution_user_id": 2, "execution_group_id": 2},
        "slice_name": "zog-old-build" + "a"*32 + ".slice",
    }
    assert "Slice" not in legacy.expected_properties(tmp_path, {
        **info, "resolved_executable": "/bin/sh", "request": {
            **info["request"], "command": ["/bin/sh"], "working_directory": "/",
            "execution_timeout_seconds": 1,
        },
    })


def test_parent_load_state_bad_setting_blocks_new_start_without_touching_job(bound):
    backend, systemd, args, request, jid = bound
    systemd.parent_load_state = "bad-setting"
    path = backend.resource_path(args["project_root"], args["resource_id"])
    with pytest.raises(SystemdBackendError, match="parent slice"):
        backend.start(project_root=args["project_root"], job_id=jid, request=request)
    saved = json.loads((path / "jobs" / (jid + ".json")).read_text())
    assert "start_attempted" not in saved
    assert not systemd.job_calls


def test_frozen_log_namespace_cannot_be_removed_or_changed(bound):
    backend, systemd, args, request, jid = bound
    project = args["project_root"]
    path = backend.resource_path(project, args["resource_id"])
    prepared = backend.prepare(project_root=project, job_id=jid, request=request)
    jpath = path / "jobs" / (jid + ".json")
    baseline = jpath.read_bytes()
    for namespace in (None, "default", "other-logs"):
        changed = dict(prepared)
        if namespace is None:
            changed.pop("log_namespace")
        else:
            changed["log_namespace"] = namespace
        jpath.write_text(json.dumps(changed))
        with pytest.raises(SystemdBackendError, match="logging binding"):
            backend.prepare(project_root=project, job_id=jid, request=request)
        with pytest.raises(SystemdBackendError, match="logging binding"):
            backend.observe(project_root=project, job_id=jid,
                            build_root_id=args["resource_id"])
        assert not systemd.job_calls
    jpath.write_bytes(baseline)
    assert backend.prepare(project_root=project, job_id=jid, request=request) == prepared


def test_worker_log_namespace_readback_must_match_real_service(bound):
    backend, systemd, args, request, jid = bound
    info, path, worker = _active_worker(backend, systemd, args, request, jid)
    saved = (path / "jobs" / (jid + ".json")).read_bytes()
    backend.observe(project_root=args["project_root"], job_id=jid,
                    build_root_id=args["resource_id"])
    original = systemd._get_property

    def corrupted(obj, iface, name, **kwargs):
        if name == "LogNamespace":
            return "default"
        return original(obj, iface, name, **kwargs)
    systemd._get_property = corrupted
    with pytest.raises(SystemdBackendError, match="property mismatch: LogNamespace"):
        backend.observe(project_root=args["project_root"], job_id=jid,
                        build_root_id=args["resource_id"])
    assert (path / "jobs" / (jid + ".json")).read_bytes() == saved


def test_namespaced_worker_requires_explicitly_supported_barrier(tmp_path):
    backend = ParentSystemd()
    with pytest.raises(SystemdBackendError, match="namespaced synchronization"):
        BuildBackend(
            backend, tmp_path / "priv",
            journal_barrier=object(),
            parent_slice=FRESH_COMPILER_PARENT_SLICE,
            authorized_project_root="/home/owner/" + FRESH_COMPILER_PROJECT,
        )




def test_pid1_worker_root_and_null_bind_are_host_visible_not_sidecar_private(bound):
    backend, systemd, args, request, jid = bound
    from zog.root_control import build as build_mod
    private = build_mod.FRESH_COMPILER_RESOURCES
    host = build_mod.FRESH_COMPILER_RESOURCES_SOURCE
    info = backend.prepare(project_root=args["project_root"], job_id=jid, request=request)
    root = backend.resource_path(args["project_root"], args["resource_id"]) / "root"
    expected = host / root.relative_to(private)
    assert backend._pid1_resource_path(root, fresh=True) == expected
    assert backend.expected_properties(root.parent, info)["RootDirectory"] == str(expected)
    assert backend._pid1_resource_path(root, fresh=False) == root
    with pytest.raises(SystemdBackendError, match="not a registered fresh resource"):
        backend._pid1_resource_path(Path("/tmp/arbitrary/root"), fresh=True)
    # Even the optional private device is translated to a PID1-host path.
    request = dict(request, device_profile="private-null-permission-test")
    fresh = "d" * 32
    # Device creation itself needs root and is separately covered; this case
    # verifies only that PID1 receives the host-visible source path.
    test_null = backend.resource_path(args["project_root"], args["resource_id"]) / "permission-test-null"
    test_null.touch()
    backend.private_null = lambda path: test_null
    info = backend.start(project_root=args["project_root"], job_id=fresh, request=request)
    assert info["start_attempted"]
    properties = dict(systemd.job_calls[-1][1][2])
    bind_values = properties["BindPaths"].value
    assert any(entry[0].startswith(str(host) + "/")
               and entry[1] == "/dev/null" for entry in bind_values)
    assert not any(entry[0].startswith(str(private) + "/")
                   for entry in bind_values)


def test_pid1_root_inode_must_match_quota_host_view_before_start(tmp_path, monkeypatch):
    from zog.root_control import build as build_mod
    from types import SimpleNamespace
    owner = tmp_path / "owner"
    project = owner / FRESH_COMPILER_PROJECT
    project.mkdir(parents=True)
    bound_build = tmp_path / "work"
    visible = bound_build / "controller-build-resources" / ("a" * 64) / ("b" * 32) / "root"
    private = tmp_path / "private" / ("a" * 64) / ("b" * 32) / "root"
    private.mkdir(parents=True)
    visible.mkdir(parents=True)
    monkeypatch.setattr(build_mod, "FRESH_COMPILER_BUILD_MOUNT", bound_build)
    monkeypatch.setattr(build_mod, "FRESH_COMPILER_RESOURCES_SOURCE",
                        bound_build / "controller-build-resources")
    monkeypatch.setattr(build_mod, "FRESH_COMPILER_RESOURCES",
                        tmp_path / "private")
    backend = BuildBackend(ParentSystemd(), tmp_path / "ignore",
                           parent_slice=FRESH_COMPILER_PARENT_SLICE,
                           authorized_project_root=str(project))
    original = Path.stat
    correct = True
    def mapped(self, *args, **kwargs):
        value = original(self, *args, **kwargs)
        if self == private and correct:
            target = original(visible)
            return SimpleNamespace(st_mode=value.st_mode, st_dev=target.st_dev,
                                   st_ino=target.st_ino)
        return value
    monkeypatch.setattr(Path, "stat", mapped)
    backend._verify_pid1_resource_visibility(private)
    correct = False
    with pytest.raises(SystemdBackendError, match="not PID1-visible"):
        backend._verify_pid1_resource_visibility(private)
    # Even a matching inode must not bless a symlink redirection.
    private.rmdir()
    private.symlink_to(visible, target_is_directory=True)
    with pytest.raises(SystemdBackendError, match="redirected"):
        backend._verify_pid1_resource_visibility(private)

def test_fresh_quota_backing_is_required_before_any_registration_mutation(tmp_path):
    """Missing protected mounts must refuse registration before a host write."""
    project = tmp_path / "owner" / FRESH_COMPILER_PROJECT
    project.mkdir(parents=True)
    backend = BuildBackend(ParentSystemd(), tmp_path / "ignored",
        parent_slice=FRESH_COMPILER_PARENT_SLICE,
        authorized_project_root=str(project))
    assert str(backend.directory) == "/var/lib/zog/build-resources"
    with pytest.raises(SystemdBackendError, match="quota mount"):
        backend._verify_fresh_storage(str(project))


def test_exact_state_and_registration_mount_inode_and_nested_guards(tmp_path, monkeypatch):
    """Host-deploy's actual binds are Project/state and private registration."""
    from zog.root_control import build as build_mod
    from types import SimpleNamespace
    build_mount, external = tmp_path / "work", tmp_path / "external"
    state = tmp_path / "owner" / FRESH_COMPILER_PROJECT / "state"
    attempts = state / "image-build/attempts"
    source = attempts / "one/source"
    work_state = build_mount / "state"
    work_resources = build_mount / "controller-build-resources"
    resources = tmp_path / "namespace" / "build-resources"
    for p in (external, source, work_state, work_resources, resources):
        p.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(build_mod, "FRESH_COMPILER_BUILD_MOUNT", build_mount)
    monkeypatch.setattr(build_mod, "FRESH_COMPILER_EXTERNAL_MOUNT", external)
    monkeypatch.setattr(build_mod, "FRESH_COMPILER_STATE_SOURCE", work_state)
    monkeypatch.setattr(build_mod, "FRESH_COMPILER_RESOURCES_SOURCE", work_resources)
    monkeypatch.setattr(build_mod, "FRESH_COMPILER_RESOURCES", resources)
    backend = BuildBackend(ParentSystemd(), tmp_path / "ignored",
        parent_slice=FRESH_COMPILER_PARENT_SLICE,
        authorized_project_root=str(state.parent))
    monkeypatch.setattr(os.path, "ismount", lambda p: Path(p) in (build_mount, external))
    original_read = Path.read_text
    rows = []
    def read(self, *args, **kwargs):
        if self == Path("/proc/self/mountinfo"):
            return "\n".join(rows)
        return original_read(self, *args, **kwargs)
    monkeypatch.setattr(Path, "read_text", read)
    with pytest.raises(SystemdBackendError, match="state or privileged resource bind mount"):
        backend._verify_fresh_storage(str(state.parent), [source])
    rows.extend((
        f"101 100 7:1 /state {state} rw - ext4 /dev/loop1 rw",
        f"102 100 7:1 /controller-build-resources {resources} rw - ext4 /dev/loop1 rw",
    ))
    # Test runner's nonroot mount roots must fail even with matching mount names.
    with pytest.raises(SystemdBackendError, match="mount root ownership"):
        backend._verify_fresh_storage(str(state.parent), [source])
    original_stat = Path.stat
    same_inodes = True
    def trusted(self, *args, **kwargs):
        value = original_stat(self, *args, **kwargs)
        if self in (build_mount, external):
            return SimpleNamespace(st_mode=value.st_mode, st_uid=0, st_gid=0,
                                   st_dev=value.st_dev, st_ino=value.st_ino)
        if self == resources:
            base = original_stat(work_resources)
            return SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=0, st_gid=0,
                                   st_dev=value.st_dev,
                                   st_ino=base.st_ino if same_inodes else value.st_ino)
        if self == state:
            base = original_stat(work_state)
            return SimpleNamespace(st_mode=value.st_mode, st_uid=value.st_uid,
                                   st_gid=value.st_gid, st_dev=value.st_dev,
                                   st_ino=base.st_ino if same_inodes else value.st_ino)
        return value
    monkeypatch.setattr(Path, "stat", trusted)
    backend._verify_fresh_storage(str(state.parent), [source])
    same_inodes = False
    with pytest.raises(SystemdBackendError, match="backing differs"):
        backend._verify_fresh_storage(str(state.parent), [source])
    same_inodes = True
    rows.append(f"103 101 8:1 / {source / 'submount'} rw - ext4 /dev/sda rw")
    with pytest.raises(SystemdBackendError, match="nested worker"):
        backend._verify_fresh_storage(str(state.parent), [source])


def test_private_registration_directory_must_remain_root_only(tmp_path, monkeypatch):
    """Never chmod the 30-GiB imported rootfs staging directory to 0755."""
    from zog.root_control import build as build_mod
    project = tmp_path / "owner" / FRESH_COMPILER_PROJECT
    project.mkdir(parents=True)
    service = BuildBackend(ParentSystemd(), tmp_path / "ignored",
                           parent_slice=FRESH_COMPILER_PARENT_SLICE,
                           authorized_project_root=str(project))
    assert service.directory == build_mod.FRESH_COMPILER_RESOURCES
    assert service.directory == Path("/var/lib/zog/build-resources")



def test_fresh_scratch_symlink_refusal_before_start_marker(bound, tmp_path):
    backend, systemd, args, request, jid = bound
    output = args["output_directory"]
    outsider = tmp_path / "unbounded"
    outsider.mkdir()
    (backend._test_scratch_mount / ".zog-runtime").symlink_to(outsider, target_is_directory=True)
    path = backend.resource_path(args["project_root"], args["resource_id"])
    with pytest.raises(SystemdBackendError, match="fresh scratch"):
        backend.start(project_root=args["project_root"], job_id=jid, request=request)
    saved = json.loads((path / "jobs" / (jid + ".json")).read_text())
    assert "start_attempted" not in saved
    assert not systemd.job_calls
    assert not any(outsider.iterdir())


@pytest.mark.parametrize("key, bad", [
    ("PrivateTmp", True), ("ProtectControlGroups", False),
    ("Delegate", True), ("RestrictNamespaces", 65535),
    ("LimitCORE", 1024), ("PrivateMounts", False),
])
def test_fresh_worker_pid1_isolation_properties_cannot_be_relaxed(bound, key, bad):
    backend, systemd, args, request, jid = bound
    info, path, worker = _active_worker(backend, systemd, args, request, jid)
    original = systemd._get_property
    def tampered(obj, iface, name, **kwargs):
        return bad if name == key else original(obj, iface, name, **kwargs)
    systemd._get_property = tampered
    with pytest.raises(SystemdBackendError, match="build property mismatch: " + key):
        backend.observe(project_root=args["project_root"], job_id=jid,
                        build_root_id=args["resource_id"])


def test_quota_mount_loss_blocks_inspection_cleanup_release_and_cancel(bound, monkeypatch):
    backend, systemd, args, request, jid = bound
    backend.prepare(project_root=args["project_root"], job_id=jid, request=request)
    path = backend.resource_path(args["project_root"], args["resource_id"])
    original = (path / 'registration.json').read_bytes()
    job_record = (path / 'jobs' / (jid + '.json')).read_bytes()
    def lost(*args, **kwargs):
        raise SystemdBackendError("fresh compiler quota mount is missing")
    monkeypatch.setattr(backend, "_verify_fresh_storage", lost)
    actions = (
        lambda: backend.registration_status(
            project_root=args["project_root"], resource_id=args["resource_id"]),
        lambda: backend.observe(
            project_root=args["project_root"], job_id=jid,
            build_root_id=args["resource_id"]),
        lambda: backend.cancel(
            project_root=args["project_root"], job_id=jid,
            build_root_id=args["resource_id"]),
        lambda: backend.cleanup(
            project_root=args["project_root"], job_id=jid,
            build_root_id=args["resource_id"]),
        lambda: backend.release(
            project_root=args["project_root"], build_root_id=args["resource_id"]),
        lambda: backend.forget(
            project_root=args["project_root"], build_root_id=args["resource_id"]),
    )
    for action in actions:
        with pytest.raises(SystemdBackendError, match="quota mount"):
            action()
    assert (path / 'registration.json').read_bytes() == original
    assert (path / 'jobs' / (jid + '.json')).read_bytes() == job_record
    assert not systemd.job_calls
