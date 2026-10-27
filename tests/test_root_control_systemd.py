import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from zog.box_control.model import ApplicationSpec, ProgramSpec
from zog.box_control.project import Project
from zog.box_control.runtime.systemd import service_definition
from zog.root_control.systemd import BusctlSystemdBackend, SystemdBackendError


class RecordingRunner:
    def __init__(self):
        self.commands = []

    def __call__(self, args, **kwargs):
        self.commands.append(args)
        return SimpleNamespace(returncode=0, stdout="", stderr="")


def _definition(tmp_path):
    project = Project(tmp_path / "demo")
    generation = "generation-1"
    root = project.rootfs_dir / "generations" / generation / "root"
    root.mkdir(parents=True)
    for target in ("var/lib/browser", "tmp/.X11-unix"):
        (root / target).mkdir(parents=True)
    (root / ".box-control-rootfs.json").write_text(
        json.dumps({"fingerprint": generation}), encoding="utf-8"
    )
    application = ApplicationSpec(
        name="desktop",
        programs=(ProgramSpec(name="browser", command=("/usr/bin/browser",), mounts=(("data", "/var/lib/browser"),)),),
    )
    definition = service_definition(
        project, application, "A7K3Q2", application.programs[0], generation_root=root
    )
    definition.bind_paths[0][0].mkdir(parents=True)
    return project, generation, definition


def test_root_control_uses_typed_start_job_and_retains_unit(tmp_path):
    project, generation, definition = _definition(tmp_path)
    calls = []
    jobs = SimpleNamespace(call=lambda *args, **kwargs: calls.append((args, kwargs)))
    backend = BusctlSystemdBackend(runner=RecordingRunner(), jobs=jobs)
    backend.start_service(project_root=project.path, generation=generation,
                          definition=definition.to_transport_dict())
    (method, signature, body), options = calls[0]
    assert method == "StartTransientUnit"
    assert signature == "ssa(sv)a(sa(sv))"
    assert options == {"job": True}
    properties = dict(body[2])
    assert properties["ExecStart"].value == [["/usr/bin/browser", ["/usr/bin/browser"], False]]
    assert properties["ExitType"].value == "cgroup"
    assert properties["AddRef"].value is True
    assert properties["BindPaths"].value == [[str(definition.bind_paths[0][0]), "/var/lib/browser", False, 0]]
    assert properties["TimeoutStopUSec"].value == 10_000_000


def test_workspace_client_sends_read_only_mounts_in_start_job(tmp_path, monkeypatch):
    from zog.root_control.workspace import WorkspaceBackend

    project, generation, definition = _definition(tmp_path)
    binding = {
        "role": "client",
        "namespace_path": "/proc/1/ns/net",
        "access_directory": str(tmp_path / "workspace" / "access"),
        "x11_directory": str(tmp_path / "workspace" / "x11"),
    }
    raw = definition.to_transport_dict()
    raw["workspace_binding"] = binding
    raw["read_only_bind_paths"] = [
        [binding["access_directory"], "/run/zog-workspace"],
        [binding["x11_directory"], "/tmp/.X11-unix"],
    ]
    raw.pop("mount_inventory", None)
    verified = []
    monkeypatch.setattr(WorkspaceBackend, "verify",
                        lambda self, **kwargs: verified.append(kwargs))
    calls = []
    jobs = SimpleNamespace(call=lambda *args, **kwargs: calls.append((args, kwargs)))
    backend = BusctlSystemdBackend(runner=RecordingRunner(), jobs=jobs)

    backend.start_service(project_root=project.path, generation=generation, definition=raw)

    assert verified == [{"project_root": project.path, "binding": binding}]
    (method, signature, body), options = calls[0]
    assert method == "StartTransientUnit"
    assert signature == "ssa(sv)a(sa(sv))"
    assert options == {"job": True}
    properties = dict(body[2])
    mounts = properties["BindReadOnlyPaths"]
    assert mounts.signature == "a(ssbt)"
    assert mounts.value == [
        *[
            [str(source.resolve()), target, False, 0]
            for source, target in definition.rootfs_bind_paths
        ],
        [binding["access_directory"], "/run/zog-workspace", False, 0],
        [binding["x11_directory"], "/tmp/.X11-unix", False, 0],
    ]
    assert properties["NetworkNamespacePath"].value == "/proc/1/ns/net"
    # Workspace sources must not leak into writable mounts.
    assert properties["BindPaths"].value == [
        [str(definition.bind_paths[0][0]), "/var/lib/browser", False, 0]
    ]


def test_root_control_rejects_writable_bind_outside_project_state(tmp_path):
    project, generation, definition = _definition(tmp_path)
    raw = definition.to_transport_dict()
    raw["bind_paths"] = [[str(tmp_path / "foreign"), "/var/lib/browser"]]
    backend = BusctlSystemdBackend(runner=RecordingRunner())
    with pytest.raises(SystemdBackendError, match="outside state/mounts"):
        backend.start_service(
            project_root=project.path, generation=generation, definition=raw
        )


def test_observe_reads_cgroup_properties_from_service_interface(tmp_path):
    project = Project(tmp_path / "demo")
    backend = BusctlSystemdBackend(runner=RecordingRunner())
    backend._get_unit_path = lambda unit_name: "/org/freedesktop/systemd1/unit/test"
    calls = []

    values = {
        "Transient": True,
        "FragmentPath": "",
        "DropInPaths": [],
        "InvocationID": [0] * 15 + [1],
        "ActiveState": "active",
        "SubState": "running",
        "ControlGroup": "/zog-demo-A.service",
        "Slice": "zog-demo-A.slice",
        "TasksMax": 2**64 - 1,
        "TimeoutStopUSec": 10_000_000,
        "RuntimeMaxUSec": 2**64 - 1,
        "NetworkNamespacePath": "",
        "Result": "success",
        "MainPID": 1234,
        "Type": "exec",
        "ExitType": "cgroup",
        "KillMode": "control-group",
        "Restart": "no",
        "RemainAfterExit": False,
        "RootDirectory": "/root",
        "ExecStart": [["/usr/bin/example", ["/usr/bin/example"], False]],
        "Environment": [],
        "WorkingDirectory": "/",
        "BindPaths": [],
        "BindReadOnlyPaths": [],
        "ProtectSystem": "strict",
        "PrivateTmp": True,
        "PrivateMounts": True,
        "MountAPIVFS": True,
        "StandardOutput": "journal",
        "StandardError": "journal",
        "User": "regular",
        "Group": "",
    }

    def get_property(object_path, interface, name, *, optional=False):
        calls.append((interface, name))
        return values[name]

    backend._get_property = get_property
    observed = backend.observe(
        project_root=project.path, unit_name="zog-demo-A-example.service"
    )
    service_interface = "org.freedesktop.systemd1.Service"
    assert (service_interface, "Slice") in calls
    assert (service_interface, "ControlGroup") in calls
    assert (service_interface, "TasksMax") in calls
    assert observed["control_group"] == "/zog-demo-A.service"


def test_backend_subprocess_timeout_is_explicit_and_reported():
    import subprocess

    def blocked(arguments, **options):
        assert options["timeout"] == .01
        raise subprocess.TimeoutExpired(arguments, options["timeout"])

    backend = BusctlSystemdBackend(runner=blocked, command_timeout_seconds=.01)
    with pytest.raises(SystemdBackendError, match="timed out"):
        backend.version()


def test_protocol_deadline_cannot_be_extended_by_partial_messages():
    import struct
    from zog.root_control.protocol import decode

    class SlowPeer:
        timeouts = []
        def settimeout(self, timeout):
            self.timeouts.append(timeout)
        def recv(self, size):
            return struct.pack("!I", 2) if size == 4 else b"{}"

    import time
    peer = SlowPeer()
    assert decode(peer, deadline=time.monotonic() + 1) == {}
    assert 0 < peer.timeouts[1] <= peer.timeouts[0] <= 1
    with pytest.raises(TimeoutError):
        decode(peer, deadline=time.monotonic() - 1)


def test_zero_invocation_is_not_launch_evidence():
    assert BusctlSystemdBackend._invocation_id([0] * 16) is None


def test_nested_lifecycle_deadline_is_not_extended_and_expires_before_socket():
    import time
    from zog.box_control.runtime.root_control import RootControlSystemdTransport
    from zog.box_control.errors import RuntimeOperationError
    transport = RootControlSystemdTransport(Path("/not-used.sock"))
    with transport.operation_budget(1):
        outer = transport.operation_deadline
        with transport.operation_budget(100):
            assert transport.operation_deadline == outer
        transport.operation_deadline = time.monotonic() - 1
        with pytest.raises(RuntimeOperationError, match="lifecycle operation deadline"):
            transport.version()
    assert transport.operation_deadline is None


def test_finite_program_sets_runtime_limit(tmp_path):
    from dataclasses import replace
    project, generation, definition = _definition(tmp_path)
    definition = replace(definition, execution_timeout_seconds=12)
    calls = []
    backend = BusctlSystemdBackend(jobs=SimpleNamespace(call=lambda *a, **kw: calls.append(a)))
    backend.start_service(project_root=project.path, generation=generation, definition=definition.to_transport_dict())
    assert dict(calls[0][2][2])['RuntimeMaxUSec'].value == 12_000_000


def test_persistent_directory_ownership_never_repairs_existing_data(tmp_path, monkeypatch):
    import os
    import pwd
    import zog.root_control.systemd as module
    account = SimpleNamespace(pw_uid=1234, pw_gid=1234)
    monkeypatch.setattr(pwd, 'getpwnam', lambda _: account)
    calls = []
    monkeypatch.setattr(os, 'chown', lambda *a: calls.append(a))
    base = tmp_path / 'state' / 'mounts' / 'persistent' / ('a' * 32)
    definition = {'persistent_storage_id': 'a' * 32, 'user': 'regular', 'bind_paths': [[str(base / 'data'), '/data']]}
    BusctlSystemdBackend._persistent_directories(tmp_path, definition)
    assert len(calls) == 1
    # Chown was stubbed, so existing ownership now disagrees. Do not repair it.
    with pytest.raises(SystemdBackendError, match='ownership'):
        BusctlSystemdBackend._persistent_directories(tmp_path, definition)
    assert len(calls) == 1
    (base / 'data').rmdir()
    (base / 'data').symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(SystemdBackendError, match='direct owned'):
        BusctlSystemdBackend._persistent_directories(tmp_path, definition)


@pytest.mark.parametrize('message', [
    'Call failed: Unit zog-demo-buildabc.slice not loaded.',
    'org.freedesktop.systemd1.NoSuchUnit',
])
def test_reset_failed_tolerates_unit_collected_after_stop(tmp_path, message):
    runner = lambda *args, **kwargs: SimpleNamespace(returncode=1, stdout='', stderr=message)
    backend = BusctlSystemdBackend(runner=runner)
    backend.reset_failed(project_root=tmp_path/'demo', unit_name='zog-demo-buildabc.slice')


def test_reset_failed_preserves_transport_failure(tmp_path):
    runner = lambda *args, **kwargs: SimpleNamespace(returncode=1, stdout='', stderr='Access denied')
    backend = BusctlSystemdBackend(runner=runner)
    with pytest.raises(SystemdBackendError, match='Access denied'):
        backend.reset_failed(project_root=tmp_path/'demo', unit_name='zog-demo-buildabc.slice')



def _compatibility(*, version="3.12.7", libraries=()):
    return {
        "schema": 1,
        "mount_contract": "applications-v1",
        "architecture": "x86_64",
        "python": {
            "implementation": "cpython",
            "version": version,
            "soabi": "cpython-312-x86_64-linux-gnu",
        },
        "libraries": list(libraries),
    }


def test_application_software_uses_one_flat_read_only_bind_vector(tmp_path):
    from zog.box_control.application_software import resolve_binding
    from zog.box_control.images import ImageSelection
    from zog.image_build.application_software import ApplicationSoftwareStore
    from zog.image_build.application_views import ApplicationSoftwareViewStore

    project, generation, _ = _definition(tmp_path)
    store = ApplicationSoftwareStore(project.state_dir)

    def publish(operation, files):
        prepared = store.begin(
            operation,
            application="desktop",
            revision="git:" + operation[0] * 40,
            compatibility_requirements=_compatibility(libraries=("libc.so.6",)),
            notices=(),
            provenance={},
        )
        for name, value in files.items():
            path = prepared.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(value)
            if name.startswith("bin/"):
                path.chmod(0o755)
        return store.finalize(operation)

    backend = publish("backend-a", {"bin/browser": "#!/bin/sh\n"})
    frontend = publish("frontend-b", {"share/desktop/app.js": "fixture\n"})
    view = ApplicationSoftwareViewStore(project.state_dir).publish(
        "desktop-view",
        application="desktop",
        artifacts=[backend.artifact, frontend.artifact],
    )
    root = project.rootfs_dir / "generations" / generation / "root"
    selection = ImageSelection(
        generation,
        root,
        {
            "kind": "image",
            "application_software_compatibility": _compatibility(
                libraries=("libc.so.6",)
            ),
        },
        reused=True,
    )
    application = ApplicationSpec(
        name="desktop",
        programs=(
            ProgramSpec(
                name="browser",
                command=("/applications/desktop/bin/browser",),
                mounts=(("data", "/var/lib/browser"),),
            ),
        ),
        software_view=view.view,
    )
    bound = resolve_binding(project, application, selection)
    definition = service_definition(
        project, bound, "B8L4R3", bound.programs[0], generation_root=root
    )
    definition.bind_paths[0][0].mkdir(parents=True)
    calls = []
    backend_systemd = BusctlSystemdBackend(
        runner=RecordingRunner(),
        jobs=SimpleNamespace(call=lambda *args, **kwargs: calls.append((args, kwargs))),
    )
    backend_systemd.start_service(
        project_root=project.path,
        generation=generation,
        definition=definition.to_transport_dict(),
    )
    (_method, _signature, body), _options = calls[0]
    properties = dict(body[2])
    read_only = properties["BindReadOnlyPaths"]
    assert read_only.signature == "a(ssbt)"
    expected = [
        [str(source.resolve()), target, False, 0]
        for source, target in (
            definition.rootfs_bind_paths + definition.read_only_bind_paths
        )
    ]
    assert read_only.value == expected
    assert all(
        isinstance(entry, list)
        and len(entry) == 4
        and isinstance(entry[0], str)
        and isinstance(entry[1], str)
        for entry in read_only.value
    )
    assert properties["BindPaths"].value == [
        [str(definition.bind_paths[0][0]), "/var/lib/browser", False, 0]
    ]
    assert properties["PrivateMounts"].value is True


def test_root_control_rejects_tampered_application_software_mount_list(tmp_path):
    from zog.box_control.application_software import resolve_binding
    from zog.box_control.images import ImageSelection
    from zog.image_build.application_software import ApplicationSoftwareStore
    from zog.image_build.application_views import ApplicationSoftwareViewStore

    project, generation, _ = _definition(tmp_path)
    store = ApplicationSoftwareStore(project.state_dir)
    prepared = store.begin(
        "software-a",
        application="desktop",
        revision="git:" + "a" * 40,
        compatibility_requirements=_compatibility(),
        notices=(),
        provenance={},
    )
    (prepared.root / "bin").mkdir()
    (prepared.root / "bin/browser").write_text("#!/bin/sh\n")
    (prepared.root / "bin/browser").chmod(0o755)
    artifact = store.finalize("software-a")
    view = ApplicationSoftwareViewStore(project.state_dir).publish(
        "view-a", application="desktop", artifacts=[artifact.artifact]
    )
    root = project.rootfs_dir / "generations" / generation / "root"
    selection = ImageSelection(
        generation, root,
        {"kind": "image", "application_software_compatibility": _compatibility()},
        reused=True,
    )
    application = resolve_binding(
        project,
        ApplicationSpec(
            name="desktop",
            programs=(ProgramSpec(name="browser", command=("/applications/desktop/bin/browser",)),),
            software_view=view.view,
        ),
        selection,
    )
    definition = service_definition(
        project, application, "C9M5S4", application.programs[0], generation_root=root
    ).to_transport_dict()
    definition["read_only_bind_paths"][0][1] = "/applications/.store/" + "f" * 64
    with pytest.raises(SystemdBackendError, match="read-only mount list"):
        BusctlSystemdBackend(runner=RecordingRunner()).start_service(
            project_root=project.path,
            generation=generation,
            definition=definition,
        )



def _tree_snapshot(root):
    result = []
    for path in sorted(root.rglob("*"), key=lambda value: value.as_posix()):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            result.append((relative, "symlink", path.readlink().as_posix()))
        elif path.is_dir():
            result.append((relative, "directory", path.stat().st_mode & 0o7777))
        elif path.is_file():
            result.append((relative, "file", path.read_bytes()))
    return result


def test_start_service_uses_private_runtime_scaffold_without_mutating_generation(tmp_path):
    project, generation, definition = _definition(tmp_path)
    root = definition.generation_root
    before = _tree_snapshot(root)
    assert not (root / "applications").exists()

    calls = []
    backend = BusctlSystemdBackend(
        runner=RecordingRunner(),
        jobs=SimpleNamespace(call=lambda *args, **kwargs: calls.append((args, kwargs))),
    )
    backend.start_service(
        project_root=project.path,
        generation=generation,
        definition=definition.to_transport_dict(),
    )

    assert _tree_snapshot(root) == before
    runtime_root = (
        project.mounts_dir / "runtime-roots" / definition.runtime_id / "root"
    )
    assert definition.root_directory == runtime_root
    assert runtime_root.is_dir()
    assert (runtime_root / "applications").is_dir()
    assert not (root / "applications").exists()
    for _source, target in definition.rootfs_bind_paths:
        assert (runtime_root / target.lstrip("/")).exists()

    (_method, _signature, body), _options = calls[0]
    properties = dict(body[2])
    assert properties["RootDirectory"].value == str(runtime_root)
    assert properties["BindReadOnlyPaths"].value[:len(definition.rootfs_bind_paths)] == [
        [str(source.resolve()), target, False, 0]
        for source, target in definition.rootfs_bind_paths
    ]


def test_runtime_scaffold_supplies_application_targets_not_generation(tmp_path):
    from zog.box_control.application_software import resolve_binding
    from zog.box_control.images import ImageSelection
    from zog.image_build.application_software import ApplicationSoftwareStore
    from zog.image_build.application_views import ApplicationSoftwareViewStore

    project, generation, _definition_value = _definition(tmp_path)
    root = project.rootfs_dir / "generations" / generation / "root"
    compatibility = {
        "schema": 1,
        "mount_contract": "applications-v1",
        "architecture": "x86_64",
        "python": None,
        "libraries": [],
    }
    store = ApplicationSoftwareStore(project.state_dir)
    prepared = store.begin(
        "scaffold-artifact",
        application="desktop",
        revision="git:" + "a" * 40,
        compatibility_requirements=compatibility,
        notices=(),
        provenance={},
    )
    (prepared.root / "bin").mkdir()
    (prepared.root / "bin/browser").write_text("#!/bin/sh\n")
    (prepared.root / "bin/browser").chmod(0o755)
    artifact = store.finalize("scaffold-artifact")
    view = ApplicationSoftwareViewStore(project.state_dir).publish(
        "scaffold-view",
        application="desktop",
        artifacts=[artifact.artifact],
    )
    selection = ImageSelection(
        generation,
        root,
        {"kind": "image", "application_software_compatibility": compatibility},
        reused=True,
    )
    application = resolve_binding(
        project,
        ApplicationSpec(
            name="desktop",
            programs=(ProgramSpec(name="browser", command=("/applications/desktop/bin/browser",)),),
            software_view=view.view,
        ),
        selection,
    )
    definition = service_definition(
        project, application, "B8L4R3", application.programs[0], generation_root=root
    )
    before = _tree_snapshot(root)
    calls = []
    backend = BusctlSystemdBackend(
        runner=RecordingRunner(),
        jobs=SimpleNamespace(call=lambda *args, **kwargs: calls.append((args, kwargs))),
    )
    # A hardened daemon commonly runs with UMask=0077. The namespace root
    # still needs traversal permissions after systemd switches to the app UID.
    import os
    import stat
    previous_umask = os.umask(0o077)
    try:
        backend.start_service(
            project_root=project.path,
            generation=generation,
            definition=definition.to_transport_dict(),
        )
    finally:
        os.umask(previous_umask)
    assert stat.S_IMODE(definition.root_directory.stat().st_mode) == 0o755
    assert stat.S_IMODE(definition.root_directory.parent.stat().st_mode) == 0o700
    for directory in (definition.root_directory / "applications").rglob("*"):
        assert stat.S_IMODE(directory.stat().st_mode) == 0o755
    assert stat.S_IMODE((definition.root_directory / "applications").stat().st_mode) == 0o755
    assert _tree_snapshot(root) == before
    assert not (root / "applications").exists()

    runtime_root = definition.root_directory
    expected_targets = [
        target for _source, target in definition.read_only_bind_paths
        if target.startswith("/applications/")
    ]
    for target in expected_targets:
        assert (runtime_root / target.lstrip("/")).is_dir()

    (_method, _signature, body), _options = calls[0]
    properties = dict(body[2])
    assert properties["BindReadOnlyPaths"].value == [
        *[
            [str(source.resolve()), target, False, 0]
            for source, target in definition.rootfs_bind_paths
        ],
        *[
            [str(source.resolve()), target, False, 0]
            for source, target in definition.read_only_bind_paths
        ],
    ]


def test_release_runtime_root_requires_unloaded_slice_and_removes_only_scaffold(tmp_path, monkeypatch):
    project, generation, definition = _definition(tmp_path)
    backend = BusctlSystemdBackend(
        runner=RecordingRunner(),
        jobs=SimpleNamespace(call=lambda *args, **kwargs: None),
    )
    backend.start_service(
        project_root=project.path,
        generation=generation,
        definition=definition.to_transport_dict(),
    )
    runtime_parent = definition.root_directory.parent
    assert runtime_parent.is_dir()

    monkeypatch.setattr(
        backend,
        "observe",
        lambda **kwargs: {"exists": True, "active_state": "inactive"},
    )
    with pytest.raises(SystemdBackendError, match="slice to be unloaded"):
        backend.release_runtime_root(
            project_root=project.path, runtime_id=definition.runtime_id
        )
    assert runtime_parent.is_dir()

    monkeypatch.setattr(backend, "observe", lambda **kwargs: {"exists": False})
    backend.release_runtime_root(
        project_root=project.path, runtime_id=definition.runtime_id
    )
    assert not runtime_parent.exists()
    assert definition.generation_root.is_dir()


def test_distinct_runtime_scaffolds_do_not_share_generation_mutations(tmp_path):
    project, generation, first = _definition(tmp_path)
    root = first.generation_root
    application = ApplicationSpec(
        name="other",
        programs=(ProgramSpec(name="worker", command=("/usr/bin/worker",)),),
    )
    second = service_definition(
        project, application, "C9M5S4", application.programs[0], generation_root=root
    )
    before = _tree_snapshot(root)
    backend = BusctlSystemdBackend(
        runner=RecordingRunner(),
        jobs=SimpleNamespace(call=lambda *args, **kwargs: None),
    )
    backend.start_service(
        project_root=project.path,
        generation=generation,
        definition=first.to_transport_dict(),
    )
    backend.start_service(
        project_root=project.path,
        generation=generation,
        definition=second.to_transport_dict(),
    )
    assert first.root_directory != second.root_directory
    assert first.root_directory.is_dir()
    assert second.root_directory.is_dir()
    assert _tree_snapshot(root) == before



def test_interrupted_runtime_scaffold_candidate_is_discarded_and_rebuilt(tmp_path):
    project, generation, definition = _definition(tmp_path)
    backend = BusctlSystemdBackend(
        runner=RecordingRunner(),
        jobs=SimpleNamespace(call=lambda *args, **kwargs: None),
    )
    parent, runtime, _root = backend._runtime_root_paths(
        project.path, definition.runtime_id
    )
    parent.mkdir(mode=0o700, exist_ok=True)
    candidate = parent / ("." + definition.runtime_id + ".candidate")
    candidate.mkdir()
    (candidate / "partial").write_text("interrupted")

    backend.start_service(
        project_root=project.path,
        generation=generation,
        definition=definition.to_transport_dict(),
    )

    assert not candidate.exists()
    assert runtime.is_dir()
    assert (runtime / "scaffold.json").is_file()
    assert definition.generation_root.is_dir()


def test_dangling_candidate_symlink_is_integrity_fault(tmp_path):
    project, generation, definition = _definition(tmp_path)
    backend = BusctlSystemdBackend(runner=RecordingRunner())
    parent, _runtime, _root = backend._runtime_root_paths(
        project.path, definition.runtime_id
    )
    parent.mkdir(mode=0o700, exist_ok=True)
    candidate = parent / ("." + definition.runtime_id + ".candidate")
    candidate.symlink_to(tmp_path / "missing-candidate", target_is_directory=True)

    with pytest.raises(SystemdBackendError, match="cannot safely discard"):
        backend.start_service(
            project_root=project.path,
            generation=generation,
            definition=definition.to_transport_dict(),
        )
    assert candidate.is_symlink()


def test_dangling_published_scaffold_symlink_is_not_repaired(tmp_path):
    project, generation, definition = _definition(tmp_path)
    backend = BusctlSystemdBackend(runner=RecordingRunner())
    parent, runtime, _root = backend._runtime_root_paths(
        project.path, definition.runtime_id
    )
    parent.mkdir(mode=0o700, exist_ok=True)
    runtime.symlink_to(tmp_path / "missing-runtime", target_is_directory=True)

    with pytest.raises(SystemdBackendError, match="RootDirectory|missing or redirected"):
        backend.start_service(
            project_root=project.path,
            generation=generation,
            definition=definition.to_transport_dict(),
        )
    assert runtime.is_symlink()


def test_published_scaffold_survives_parent_sync_failure_and_is_reused(
    tmp_path, monkeypatch
):
    import zog.box_control.durability as durability

    project, generation, definition = _definition(tmp_path)
    backend = BusctlSystemdBackend(
        runner=RecordingRunner(),
        jobs=SimpleNamespace(call=lambda *args, **kwargs: None),
    )
    parent, runtime, _root = backend._runtime_root_paths(
        project.path, definition.runtime_id
    )
    original = durability.synchronize_directory
    calls = []

    def failing_sync(path):
        path = Path(path)
        calls.append(path)
        if path == parent and runtime.exists():
            raise OSError("simulated parent directory barrier failure")
        return original(path)

    monkeypatch.setattr(durability, "synchronize_directory", failing_sync)
    with pytest.raises(OSError, match="barrier failure"):
        backend.start_service(
            project_root=project.path,
            generation=generation,
            definition=definition.to_transport_dict(),
        )

    assert runtime.is_dir()
    manifest_before = (runtime / "scaffold.json").read_bytes()
    candidate = parent / ("." + definition.runtime_id + ".candidate")
    assert not candidate.exists()
    monkeypatch.setattr(durability, "synchronize_directory", original)

    backend.start_service(
        project_root=project.path,
        generation=generation,
        definition=definition.to_transport_dict(),
    )
    assert (runtime / "scaffold.json").read_bytes() == manifest_before


def test_existing_scaffold_tampering_blocks_recovery(tmp_path):
    project, generation, definition = _definition(tmp_path)
    backend = BusctlSystemdBackend(
        runner=RecordingRunner(),
        jobs=SimpleNamespace(call=lambda *args, **kwargs: None),
    )
    backend.start_service(
        project_root=project.path,
        generation=generation,
        definition=definition.to_transport_dict(),
    )
    unexpected = definition.root_directory / "applications" / "unexpected"
    unexpected.mkdir()

    with pytest.raises(SystemdBackendError, match="unexpected paths"):
        backend.start_service(
            project_root=project.path,
            generation=generation,
            definition=definition.to_transport_dict(),
        )
    assert unexpected.is_dir()


def test_multiple_programs_reuse_only_exact_matching_scaffold(tmp_path):
    project, generation, first = _definition(tmp_path)
    application = ApplicationSpec(
        name="desktop",
        programs=(
            ProgramSpec(name="browser", command=("/usr/bin/browser",)),
            ProgramSpec(name="helper", command=("/usr/bin/helper",)),
        ),
    )
    browser = service_definition(
        project, application, "A7K3Q2", application.programs[0],
        generation_root=first.generation_root,
    )
    helper = service_definition(
        project, application, "A7K3Q2", application.programs[1],
        generation_root=first.generation_root,
    )
    backend = BusctlSystemdBackend(
        runner=RecordingRunner(),
        jobs=SimpleNamespace(call=lambda *args, **kwargs: None),
    )

    backend.start_service(
        project_root=project.path,
        generation=generation,
        definition=browser.to_transport_dict(),
    )
    manifest = (browser.root_directory.parent / "scaffold.json").read_bytes()
    backend.start_service(
        project_root=project.path,
        generation=generation,
        definition=helper.to_transport_dict(),
    )

    assert browser.root_directory == helper.root_directory
    assert (browser.root_directory.parent / "scaffold.json").read_bytes() == manifest


def test_release_runtime_root_rejects_dangling_symlink(tmp_path, monkeypatch):
    project, _generation, definition = _definition(tmp_path)
    backend = BusctlSystemdBackend(runner=RecordingRunner())
    parent, runtime, _root = backend._runtime_root_paths(
        project.path, definition.runtime_id
    )
    parent.mkdir(mode=0o700, exist_ok=True)
    runtime.symlink_to(tmp_path / "missing-runtime", target_is_directory=True)
    monkeypatch.setattr(backend, "observe", lambda **kwargs: {"exists": False})

    with pytest.raises(SystemdBackendError, match="cannot be removed safely"):
        backend.release_runtime_root(
            project_root=project.path,
            runtime_id=definition.runtime_id,
        )
    assert runtime.is_symlink()



def test_exact_top_level_writable_override_has_one_effective_mount(tmp_path):
    project = Project(tmp_path / "demo")
    generation = "generation-1"
    root = project.rootfs_dir / "generations" / generation / "root"
    (root / "usr/bin").mkdir(parents=True)
    (root / "usr/bin/probe").write_text("fixture")
    (root / "root").mkdir()
    (root / ".box-control-rootfs.json").write_text(
        json.dumps({"fingerprint": generation}), encoding="utf-8"
    )
    application = ApplicationSpec(
        name="desktop",
        programs=(
            ProgramSpec(
                name="probe",
                command=("/usr/bin/probe",),
                mounts=(("state", "/root"),),
            ),
        ),
    )
    definition = service_definition(
        project,
        application,
        "F4Q8V7",
        application.programs[0],
        generation_root=root,
    )
    definition.bind_paths[0][0].mkdir(parents=True)

    calls = []
    backend = BusctlSystemdBackend(
        runner=RecordingRunner(),
        jobs=SimpleNamespace(call=lambda *args, **kwargs: calls.append((args, kwargs))),
    )
    before = _tree_snapshot(root)
    backend.start_service(
        project_root=project.path,
        generation=generation,
        definition=definition.to_transport_dict(),
    )

    assert _tree_snapshot(root) == before
    (_method, _signature, body), _options = calls[0]
    properties = dict(body[2])
    read_only_destinations = [
        item[1] for item in properties["BindReadOnlyPaths"].value
    ]
    writable_destinations = [
        item[1] for item in properties["BindPaths"].value
    ]
    assert "/root" not in read_only_destinations
    assert writable_destinations == ["/root"]
    assert len(read_only_destinations + writable_destinations) == len(
        set(read_only_destinations + writable_destinations)
    )
    assert (definition.root_directory / "root").is_dir()


def test_nested_writable_overlay_keeps_parent_read_only(tmp_path):
    project, generation, _base = _definition(tmp_path)
    root = project.rootfs_dir / "generations" / generation / "root"
    (root / "var/lib/nested").mkdir()
    application = ApplicationSpec(
        name="nested",
        programs=(
            ProgramSpec(
                name="probe",
                command=("/usr/bin/probe",),
                mounts=(("state", "/var/lib/nested"),),
            ),
        ),
    )
    definition = service_definition(
        project,
        application,
        "G5R9W8",
        application.programs[0],
        generation_root=root,
    )
    definition.bind_paths[0][0].mkdir(parents=True)
    calls = []
    backend = BusctlSystemdBackend(
        runner=RecordingRunner(),
        jobs=SimpleNamespace(call=lambda *args, **kwargs: calls.append((args, kwargs))),
    )
    backend.start_service(
        project_root=project.path,
        generation=generation,
        definition=definition.to_transport_dict(),
    )
    properties = dict(calls[0][0][2][2])
    read_only_destinations = [
        item[1] for item in properties["BindReadOnlyPaths"].value
    ]
    assert "/var" in read_only_destinations
    assert properties["BindPaths"].value == [
        [str(definition.bind_paths[0][0]), "/var/lib/nested", False, 0]
    ]


def test_runtime_facilities_exist_only_in_private_scaffold(tmp_path):
    project, generation, definition = _definition(tmp_path)
    root = definition.generation_root
    before = _tree_snapshot(root)
    backend = BusctlSystemdBackend(
        runner=RecordingRunner(),
        jobs=SimpleNamespace(call=lambda *args, **kwargs: None),
    )
    backend.start_service(
        project_root=project.path,
        generation=generation,
        definition=definition.to_transport_dict(),
    )

    assert _tree_snapshot(root) == before
    for target in ("run", "proc", "sys", "dev", "applications"):
        assert (definition.root_directory / target).is_dir()
        assert not (root / target).exists()


def test_workspace_run_target_is_scaffold_owned_not_image_owned(tmp_path, monkeypatch):
    from zog.root_control.workspace import WorkspaceBackend

    project, generation, definition = _definition(tmp_path)
    root = definition.generation_root
    binding = {
        "role": "client",
        "namespace_path": "/proc/1/ns/net",
        "access_directory": str(tmp_path / "workspace" / "access"),
        "x11_directory": str(tmp_path / "workspace" / "x11"),
    }
    raw = definition.to_transport_dict()
    raw["workspace_binding"] = binding
    raw["read_only_bind_paths"] = [
        [binding["access_directory"], "/run/zog-workspace"],
        [binding["x11_directory"], "/tmp/.X11-unix"],
    ]
    raw.pop("mount_inventory", None)
    monkeypatch.setattr(WorkspaceBackend, "verify", lambda self, **kwargs: None)
    backend = BusctlSystemdBackend(
        runner=RecordingRunner(),
        jobs=SimpleNamespace(call=lambda *args, **kwargs: None),
    )
    backend.start_service(
        project_root=project.path, generation=generation, definition=raw
    )

    assert not (root / "run").exists()
    assert (
        Path(raw["root_directory"]) / "run/zog-workspace"
    ).is_dir()


def test_root_control_rejects_duplicate_exact_effective_destination(tmp_path):
    project = Project(tmp_path / "demo")
    generation = "generation-1"
    root = project.rootfs_dir / "generations" / generation / "root"
    (root / "usr/bin").mkdir(parents=True)
    (root / "usr/bin/probe").write_text("fixture")
    (root / "root").mkdir()
    (root / ".box-control-rootfs.json").write_text(
        json.dumps({"fingerprint": generation}), encoding="utf-8"
    )
    application = ApplicationSpec(
        name="probe",
        programs=(
            ProgramSpec(
                name="probe",
                command=("/usr/bin/probe",),
                mounts=(("state", "/root"),),
            ),
        ),
    )
    definition = service_definition(
        project,
        application,
        "H6S2X9",
        application.programs[0],
        generation_root=root,
    )
    definition.bind_paths[0][0].mkdir(parents=True)
    raw = definition.to_transport_dict()
    raw["rootfs_bind_paths"].append([str((root / "root").resolve()), "/root"])

    with pytest.raises(
        SystemdBackendError,
        match="rootfs read-only projection|conflicting effective mount",
    ):
        BusctlSystemdBackend(runner=RecordingRunner()).start_service(
            project_root=project.path,
            generation=generation,
            definition=raw,
        )


def test_nonempty_generation_run_is_rejected_before_service_start(tmp_path):
    project, generation, definition = _definition(tmp_path)
    root = definition.generation_root
    (root / "run/systemd").mkdir(parents=True)
    (root / "run/systemd/payload").write_text("not ephemeral")

    with pytest.raises(SystemdBackendError, match="empty directory scaffold"):
        BusctlSystemdBackend(runner=RecordingRunner()).start_service(
            project_root=project.path,
            generation=generation,
            definition=definition.to_transport_dict(),
        )



def test_systemd_run_setup_mutates_only_private_scaffold(tmp_path):
    project, generation, definition = _definition(tmp_path)
    root = definition.generation_root
    before = _tree_snapshot(root)
    backend = BusctlSystemdBackend(
        runner=RecordingRunner(),
        jobs=SimpleNamespace(call=lambda *args, **kwargs: None),
    )
    backend.start_service(
        project_root=project.path,
        generation=generation,
        definition=definition.to_transport_dict(),
    )

    incoming = definition.root_directory / "run/systemd/incoming"
    incoming.mkdir(parents=True)
    assert incoming.is_dir()
    assert not (root / "run").exists()
    assert _tree_snapshot(root) == before

    # A subsequent program/recovery pass may encounter systemd-created private
    # /run content. It must validate the durable scaffold without requiring
    # runtime /run to remain empty.
    backend.start_service(
        project_root=project.path,
        generation=generation,
        definition=definition.to_transport_dict(),
    )
    assert incoming.is_dir()
    assert _tree_snapshot(root) == before


def test_published_run_dbus_scaffold_is_private_and_recoverable(tmp_path):
    project, generation, definition = _definition(tmp_path)
    root = definition.generation_root
    (root / "run/dbus").mkdir(parents=True)
    (root / "run/dbus").chmod(0o755)
    before = _tree_snapshot(root)
    backend = BusctlSystemdBackend(
        runner=RecordingRunner(),
        jobs=SimpleNamespace(call=lambda *args, **kwargs: None),
    )
    backend.start_service(
        project_root=project.path, generation=generation,
        definition=definition.to_transport_dict(),
    )
    runtime_root = definition.root_directory
    assert (runtime_root / "run/dbus").is_dir()
    assert (runtime_root.parent / "scaffold.json").is_file()
    assert json.loads((runtime_root.parent / "scaffold.json").read_text())["schema"] == 3
    assert _tree_snapshot(root) == before
    (runtime_root / "run/systemd/incoming").mkdir(parents=True)
    backend.start_service(
        project_root=project.path, generation=generation,
        definition=definition.to_transport_dict(),
    )
    assert (runtime_root / "run/dbus").is_dir()
    assert _tree_snapshot(root) == before


def test_published_run_file_rejected_before_runtime_scaffold_creation(tmp_path):
    project, generation, definition = _definition(tmp_path)
    root = definition.generation_root
    (root / "run/dbus").mkdir(parents=True)
    (root / "run/dbus/socket-file").write_bytes(b"must not be shadowed")
    before = _tree_snapshot(root)
    with pytest.raises(SystemdBackendError, match="empty directory scaffold"):
        BusctlSystemdBackend(runner=RecordingRunner()).start_service(
            project_root=project.path, generation=generation,
            definition=definition.to_transport_dict(),
        )
    assert not definition.root_directory.exists()
    assert _tree_snapshot(root) == before


def test_authorized_host_capability_is_read_only_and_survives_child_renewal(tmp_path, monkeypatch):
    from zog.box_control import host_bindings

    project, generation, old = _definition(tmp_path)
    source = tmp_path / "mirror-export"
    source.mkdir()
    (source / "intent.json").write_text("old")
    policy = tmp_path / "host-policy.json"
    monkeypatch.setattr(host_bindings, "POLICY_PATH", policy)
    monkeypatch.setattr(host_bindings, "_require_privileged_policy", lambda value: None)
    monkeypatch.setattr(host_bindings, "_ALLOWED_SOURCE_ROOTS", (str(tmp_path) + "/",))
    policy.write_text(json.dumps(dict(schema=1, bindings=[
        dict(project=str(project.path), application="desktop", program="browser",
             capability="mirror-live", source=str(source))
    ])))
    application = ApplicationSpec(name="desktop", programs=(
        ProgramSpec(name="browser", command=("/usr/bin/browser",),
                    mounts=(("data", "/var/lib/browser"),)),
    ))
    definition = service_definition(
        project, application, "A7K3Q2", application.programs[0],
        generation_root=old.generation_root)
    definition.bind_paths[0][0].mkdir(parents=True, exist_ok=True)
    calls = []
    backend = BusctlSystemdBackend(
        runner=RecordingRunner(),
        jobs=SimpleNamespace(call=lambda *args, **kwargs: calls.append((args, kwargs))),
    )
    backend.start_service(project_root=project.path, generation=generation,
                          definition=definition.to_transport_dict())
    props = dict(calls[0][0][2][2])
    assert props["BindReadOnlyPaths"].value[-1] == [
        str(source), "/run/zog-host/mirror-live", False, 0]
    assert "host-capability" in {
        entry["kind"] for entry in definition.mount_inventory()["mounts"]
    }

    incoming = source / "incoming.json"
    incoming.write_text("new")
    incoming.replace(source / "intent.json")
    backend.start_service(project_root=project.path, generation=generation,
                          definition=definition.to_transport_dict())
    assert (source / "intent.json").read_text() == "new"


def test_root_control_rejects_forged_host_capability_and_source_replacement(tmp_path, monkeypatch):
    from zog.box_control import host_bindings

    project, generation, old = _definition(tmp_path)
    source = tmp_path / "mirror-export"
    source.mkdir()
    policy = tmp_path / "host-policy.json"
    monkeypatch.setattr(host_bindings, "POLICY_PATH", policy)
    monkeypatch.setattr(host_bindings, "_require_privileged_policy", lambda value: None)
    monkeypatch.setattr(host_bindings, "_ALLOWED_SOURCE_ROOTS", (str(tmp_path) + "/",))
    policy.write_text(json.dumps(dict(schema=1, bindings=[
        dict(project=str(project.path), application="desktop", program="browser",
             capability="mirror-live", source=str(source))
    ])))
    application = ApplicationSpec(name="desktop", programs=(
        ProgramSpec(name="browser", command=("/usr/bin/browser",),
                    mounts=(("data", "/var/lib/browser"),)),
    ))
    definition = service_definition(project, application, "A7K3Q2",
        application.programs[0], generation_root=old.generation_root)
    definition.bind_paths[0][0].mkdir(parents=True, exist_ok=True)
    backend = BusctlSystemdBackend(runner=RecordingRunner(),
        jobs=SimpleNamespace(call=lambda *args, **kwargs: None))
    raw = definition.to_transport_dict()
    original_source = raw["host_bindings"][0]["source"]
    raw["host_bindings"][0]["source"] = str(tmp_path / "foreign")
    with pytest.raises(SystemdBackendError, match="administrator policy"):
        backend.start_service(project_root=project.path, generation=generation, definition=raw)
    raw = definition.to_transport_dict()
    raw["read_only_bind_paths"][-1][0] = str(tmp_path / "foreign")
    with pytest.raises(SystemdBackendError, match="host capability"):
        backend.start_service(project_root=project.path, generation=generation, definition=raw)
    raw = definition.to_transport_dict()
    source.rename(tmp_path / "old-directory")
    source.mkdir()
    with pytest.raises(SystemdBackendError, match="administrator policy"):
        backend.start_service(project_root=project.path, generation=generation, definition=raw)
    assert raw["host_bindings"][0]["source"] == original_source



def test_separate_program_grants_reuse_one_runtime_scaffold(tmp_path, monkeypatch):
    from zog.box_control import host_bindings

    project, generation, base = _definition(tmp_path)
    source = tmp_path / "mirror-export"
    source.mkdir()
    policy = tmp_path / "host-policy.json"
    monkeypatch.setattr(host_bindings, "POLICY_PATH", policy)
    monkeypatch.setattr(host_bindings, "_require_privileged_policy", lambda value: None)
    monkeypatch.setattr(host_bindings, "_ALLOWED_SOURCE_ROOTS", (str(tmp_path) + "/",))
    policy.write_text(json.dumps(dict(schema=1, bindings=[
        dict(project=str(project.path), application="desktop", program="scheduler",
             capability="mirror-live", source=str(source))
    ])))
    web = ProgramSpec(name="browser", command=("/usr/bin/browser",),
                      mounts=(("data", "/var/lib/browser"),))
    scheduler = ProgramSpec(name="scheduler", command=("/usr/bin/browser",),
                            mounts=(("data", "/var/lib/browser"),))
    application = ApplicationSpec(name="desktop", programs=(web, scheduler))
    first = service_definition(project, application, "A7K3Q2", web,
                               generation_root=base.generation_root)
    second = service_definition(project, application, "A7K3Q2", scheduler,
                                generation_root=base.generation_root)
    assert first.host_bindings == ()
    assert len(second.host_bindings) == 1
    backend = BusctlSystemdBackend(
        runner=RecordingRunner(),
        jobs=SimpleNamespace(call=lambda *args, **kwargs: None),
    )
    first.bind_paths[0][0].mkdir(parents=True, exist_ok=True)
    second.bind_paths[0][0].mkdir(parents=True, exist_ok=True)
    backend.start_service(project_root=project.path, generation=generation,
                          definition=first.to_transport_dict())
    manifest = (first.root_directory.parent / "scaffold.json").read_bytes()
    backend.start_service(project_root=project.path, generation=generation,
                          definition=second.to_transport_dict())
    assert (second.root_directory.parent / "scaffold.json").read_bytes() == manifest



def test_persistent_missing_host_user_blocks_before_creating_storage(tmp_path, monkeypatch):
    import pwd
    def missing(_):
        raise KeyError("not installed")
    monkeypatch.setattr(pwd, "getpwnam", missing)
    base = tmp_path / "state/mounts/persistent" / ("a" * 32)
    definition = {
        "persistent_storage_id": "a" * 32,
        "user": "regular",
        "group": None,
        "bind_paths": [[str(base / "data"), "/data"]],
    }
    with pytest.raises(SystemdBackendError, match="not provisioned in the host account database"):
        BusctlSystemdBackend._persistent_directories(tmp_path, definition)
    assert not base.exists()


def test_persistent_numeric_user_uses_host_passwd_uid_and_requested_gid(tmp_path, monkeypatch):
    import pwd
    import os
    account = SimpleNamespace(pw_uid=30991, pw_gid=30992)
    requested = []
    def resolve(uid):
        requested.append(uid)
        return account
    monkeypatch.setattr(pwd, "getpwuid", resolve)
    chown = []
    monkeypatch.setattr(os, "chown", lambda *args: chown.append(args))
    base = tmp_path / "state/mounts/persistent" / ("a" * 32)
    definition = {
        "persistent_storage_id": "a" * 32,
        "user": "30991",
        "group": "30993",
        "bind_paths": [[str(base / "data"), "/data"]],
    }
    BusctlSystemdBackend._persistent_directories(tmp_path, definition)
    assert requested == [30991]
    assert chown == [(base / "data", 30991, 30993)]


def test_persistent_named_group_unavailable_fails_before_mutating_storage(tmp_path, monkeypatch):
    import pwd
    import grp
    monkeypatch.setattr(pwd, "getpwnam", lambda _: SimpleNamespace(pw_uid=30991, pw_gid=30992))
    monkeypatch.setattr(grp, "getgrnam", lambda _: (_ for _ in ()).throw(KeyError("missing")))
    base = tmp_path / "state/mounts/persistent" / ("b" * 32)
    definition = {
        "persistent_storage_id": "b" * 32,
        "user": "application-service",
        "group": "unprovisioned-group",
        "bind_paths": [[str(base / "data"), "/data"]],
    }
    with pytest.raises(SystemdBackendError, match="not provisioned in the host group database"):
        BusctlSystemdBackend._persistent_directories(tmp_path, definition)
    assert not base.exists()


def test_persistent_root_alias_rejected_by_resolved_host_uid(tmp_path, monkeypatch):
    import pwd
    monkeypatch.setattr(pwd, "getpwnam", lambda _: SimpleNamespace(pw_uid=0, pw_gid=1001))
    base = tmp_path / "state/mounts/persistent" / ("c" * 32)
    definition = {
        "persistent_storage_id": "c" * 32,
        "user": "looks-nonroot",
        "group": None,
        "bind_paths": [[str(base / "data"), "/data"]],
    }
    with pytest.raises(SystemdBackendError, match="must be unprivileged"):
        BusctlSystemdBackend._persistent_directories(tmp_path, definition)
    assert not base.exists()


def test_start_service_reports_bounded_preparation_vs_job_phases(tmp_path, monkeypatch):
    from zog.root_control import events

    project, generation, definition = _definition(tmp_path)
    emitted = []
    monkeypatch.setattr(events, "emit", lambda event, **fields:
                        emitted.append((event, fields)))
    backend = BusctlSystemdBackend(
        runner=RecordingRunner(),
        jobs=SimpleNamespace(call=lambda *a, **kw: "/job/42"))
    raw = definition.to_transport_dict()
    backend.start_service(project_root=project.path, generation=generation, definition=raw)
    assert [name for name, _ in emitted] == [
        "systemd-start-service-validated",
        "systemd-start-service-job-submitted",
        "systemd-start-service-job-completed",
    ]
    assert all(fields["unit_name"] == raw["unit_name"] for _, fields in emitted)
    assert all("command" not in fields and "policy" not in fields
               for _, fields in emitted)
    assert emitted[1][1]["preparation_seconds"] >= 0

    emitted.clear()
    def lost(*args, **kwargs):
        from zog.root_control.jobs import JobError
        raise JobError("job deadline exceeded; outcome unknown")
    backend.jobs.call = lost
    with pytest.raises(SystemdBackendError, match="deadline exceeded"):
        backend.start_service(project_root=project.path,
                              generation=generation, definition=raw)
    assert [name for name, _ in emitted][-1] == "systemd-start-service-job-unconfirmed"
    assert not any(name == "systemd-start-service-job-completed"
                   for name, _ in emitted)
