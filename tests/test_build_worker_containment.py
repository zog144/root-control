"""Exact fresh compiler containment under the host-owned parent slice.

This file uses a fake PID1 adapter and does not start a native service.
"""
import json
import os
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
            value = []
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
    backend = BuildBackend(
        systemd, tmp_path / "privileged",
        parent_slice=FRESH_COMPILER_PARENT_SLICE,
        authorized_project_root=str(project),
    )
    # The independent mount/identity cases exercise the real native guard;
    # this PID1 mock focuses only on typed worker properties.
    monkeypatch.setattr(backend, "_verify_fresh_storage", lambda *args, **kwargs: None)
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
    assert all(b[0].startswith(str(arguments["output_directory"]) + "/")
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
