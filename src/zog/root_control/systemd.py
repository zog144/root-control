from __future__ import annotations

import hashlib
import json
import os
import pwd
import grp
import re
import stat
import shutil
import subprocess
import time
from functools import wraps

from dbus_next import Variant
from .jobs import SystemdJobConnection, JobError
from pathlib import Path

_SYSTEMD_DEST = "org.freedesktop.systemd1"
_SYSTEMD_MANAGER_PATH = "/org/freedesktop/systemd1"
_SYSTEMD_MANAGER_IFACE = "org.freedesktop.systemd1.Manager"
_UNIT_IFACE = "org.freedesktop.systemd1.Unit"
_SERVICE_IFACE = "org.freedesktop.systemd1.Service"
_SLICE_IFACE = "org.freedesktop.systemd1.Slice"
_MANIFEST_NAME = ".box-control-rootfs.json"
_COMPONENT = re.compile(r"^[A-Za-z0-9-]+$")


class SystemdBackendError(RuntimeError):
    pass


def _under(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def bounded_observation(method):
    @wraps(method)
    def wrapped(self, *args, **kwargs):
        previous = self.deadline
        self.deadline = time.monotonic() + self.observation_timeout_seconds
        try:
            return method(self, *args, **kwargs)
        finally:
            self.deadline = previous
    return wrapped


class BusctlSystemdBackend:
    """Privileged mechanism adapter using systemd's manager D-Bus API directly."""

    def __init__(self, *, runner=subprocess.run, jobs=None,
                 command_timeout_seconds=5.0, observation_timeout_seconds=15.0):
        self.runner = runner
        self._jobs = jobs
        self.command_timeout_seconds = command_timeout_seconds
        self.observation_timeout_seconds = observation_timeout_seconds
        self.deadline = None

    @property
    def jobs(self):
        if self._jobs is None:
            self._jobs = SystemdJobConnection()
        return self._jobs

    def _run(self, args: list[str], *, allow_missing_unit: bool = False) -> str | None:
        timeout = self.command_timeout_seconds
        if self.deadline is not None:
            timeout = min(timeout, self.deadline - time.monotonic())
        if timeout <= 0:
            raise SystemdBackendError("systemd observation deadline exceeded")
        try:
            completed = self.runner(
                args, check=False, text=True, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=timeout,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            raise SystemdBackendError(f"systemd command failed or timed out: {exc}") from exc
        if completed.returncode:
            error = (completed.stderr or completed.stdout or "busctl failed").strip()
            if allow_missing_unit and (
                "NoSuchUnit" in error
                or "Unit " in error and "not loaded" in error
                or "Unknown object" in error
            ):
                return None
            raise SystemdBackendError(error)
        return completed.stdout.strip()

    def _manager_call(self, method: str, signature: str, *arguments: object, allow_missing_unit: bool = False) -> str:
        command = [
            "busctl", "--system", "call", _SYSTEMD_DEST, _SYSTEMD_MANAGER_PATH,
            _SYSTEMD_MANAGER_IFACE, method, signature,
        ]
        command.extend(str(value) for value in arguments)
        return self._run(command, allow_missing_unit=allow_missing_unit) or ""

    @staticmethod
    def _json_data(text: str):
        try:
            raw = json.loads(text)
            signature = str(raw.get("type", ""))
            data = raw["data"]
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise SystemdBackendError(f"cannot parse busctl JSON: {text!r}") from exc
        # busctl represents method/property values as a JSON array on some
        # releases even when the D-Bus signature has one scalar output. Keep
        # actual D-Bus arrays intact, but unwrap one scalar result.
        if signature and not signature.startswith("a") and isinstance(data, list) and len(data) == 1:
            return data[0]
        return data

    def version(self) -> int:
        output = self._run(
            ["busctl", "--system", "--json=short", "get-property", _SYSTEMD_DEST,
             _SYSTEMD_MANAGER_PATH, _SYSTEMD_MANAGER_IFACE, "Version"]
        )
        value = self._json_data(output or "")
        match = re.search(r"(\d+)", str(value))
        if not match:
            raise SystemdBackendError(f"cannot parse systemd version: {value!r}")
        return int(match.group(1))

    @staticmethod
    def _project(project_root: str | Path) -> tuple[Path, str, str]:
        root = Path(project_root).resolve()
        identity = root.name
        if not _COMPONENT.fullmatch(identity):
            raise SystemdBackendError(f"invalid project identity: {identity!r}")
        return root, identity, f"zog-{identity}-"

    @classmethod
    def _validate_unit(cls, project_root: str | Path, unit_name: str) -> Path:
        root, identity, prefix = cls._project(project_root)
        # The *only* alternate slice prefix is the reviewed fresh compiler
        # child of host-deploy's protected parent. PID1's hierarchical slice
        # naming requires this prefix; the ordinary Project prefix cannot
        # represent a descendant of zogfreshcrossbootstrapoct25.slice.
        fresh_child = (
            identity == "fresh-cross-bootstrap-oct25"
            and re.fullmatch(
                r"zogfreshcrossbootstrapoct25-build[0-9a-f]{32}\.slice", unit_name
            ) is not None
        )
        if not fresh_child and (
                not unit_name.startswith(prefix)
                or not unit_name.endswith((".service", ".slice"))):
            raise SystemdBackendError(
                f"unit does not belong to project {root.name!r}: {unit_name!r}"
            )
        return root

    @staticmethod
    def _manifest_digest(path):
        path = Path(path)
        if path.is_symlink() or not path.is_file():
            raise SystemdBackendError(f"application software manifest is unavailable: {path}")
        try:
            return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError as exc:
            raise SystemdBackendError(f"cannot read application software manifest {path}: {exc}") from exc

    @staticmethod
    def _validate_execution_binding(project_root, definition):
        binding = definition.get("execution_binding")
        if binding is None:
            return None  # Explicitly retained legacy contract; never inferred.
        from .identities import verify, ExecutionIdentityError
        try:
            verified = verify(
                project_root,
                str(definition.get("application_name", "")),
                binding,
                storage_id=definition.get("persistent_storage_id"),
            )
        except ExecutionIdentityError as exc:
            raise SystemdBackendError(f"invalid protected execution identity: {exc}") from exc
        if (definition.get("persistent_storage_id") is None
                or definition.get("user") != str(verified["uid"])
                or definition.get("group") != str(verified["gid"])):
            raise SystemdBackendError("numeric User/Group differs from protected execution grant")
        return verified

    @classmethod
    def _validate_host_bindings(cls, project_root, definition):
        """Never trust caller-supplied host sources or capability identities."""
        from zog.box_control.host_bindings import resolve
        try:
            permitted = list(resolve(
                Path(project_root),
                str(definition.get("application_name", "")),
                str(definition.get("program_name", "")),
            ))
        except Exception as exc:
            raise SystemdBackendError(f"host capability policy validation failed: {exc}") from exc
        supplied = definition.get("host_bindings", ())
        if not isinstance(supplied, (list, tuple)) or list(supplied) != permitted:
            raise SystemdBackendError("host capability binding differs from administrator policy")
        if permitted:
            root, identity, _prefix = cls._project(project_root)
            application = str(definition.get("application_name", ""))
            program = str(definition.get("program_name", ""))
            runtime_id = str(definition.get("runtime_id", ""))
            if (definition.get("unit_name")
                    != f"zog-{identity}-{runtime_id}-{program}.service"
                    or not re.fullmatch(r"[A-Za-z0-9-]+", application)
                    or not re.fullmatch(r"[A-Za-z0-9-]+", program)):
                raise SystemdBackendError("host capability program identity does not match its service")
        expected = [
            [item["source"], item["destination"]] for item in permitted
        ]
        read_only = [
            [str(source), str(target)]
            for source, target in definition.get("read_only_bind_paths", ())
        ]
        if expected and read_only[-len(expected):] != expected:
            raise SystemdBackendError("host capability mounts do not match approved read-only sources")
        return expected

    @classmethod
    def _validate_software_binding(cls, project_root, definition):
        binding = definition.get("software_binding")
        read_only = [
            [str(source), str(target)]
            for source, target in definition.get("read_only_bind_paths", ())
        ]
        host_expected = [
            [item["source"], item["destination"]]
            for item in definition.get("host_bindings", ())
        ]
        if host_expected:
            if read_only[-len(host_expected):] != host_expected:
                raise SystemdBackendError("host capability mount list was changed")
            read_only = read_only[:-len(host_expected)]
        workspace = definition.get("workspace_binding") or {}
        workspace_expected = []
        if workspace.get("role") == "client":
            workspace_expected = [
                [workspace["access_directory"], "/run/zog-workspace"],
                [workspace["x11_directory"], "/tmp/.X11-unix"],
            ]
        if binding is None:
            if read_only != workspace_expected:
                raise SystemdBackendError("unexpected read-only mount without application software binding")
            return
        if not isinstance(binding, dict) or binding.get("controller_contract") != "box-control-application-software-v1":
            raise SystemdBackendError("unsupported application software binding")
        state = Path(project_root).resolve() / "state"
        software_root = state / "image-build" / "application-software"
        if software_root.is_symlink() or not software_root.is_dir():
            raise SystemdBackendError("application software store is unavailable or redirected")
        try:
            from zog.image_build.application_views import ApplicationSoftwareViewStore
            expected = ApplicationSoftwareViewStore(state).consumer_manifest(
                binding["view"], binding["rootfs_compatibility"]
            )
        except Exception as exc:
            raise SystemdBackendError(f"cannot validate application software binding: {exc}") from exc
        consumer_keys = (
            "schema", "contract", "mount_contract", "view", "application", "profile",
            "root", "manifest", "mount_point", "objects", "rootfs_compatibility",
            "visibility", "reclamation_protection", "binding_digest",
        )
        if {key: binding.get(key) for key in consumer_keys} != expected:
            raise SystemdBackendError("application software consumer binding changed")
        if binding.get("application") != definition.get("application_name"):
            raise SystemdBackendError("application software binding belongs to another application")
        if binding.get("mount_point") != "/applications/" + str(definition.get("application_name")):
            raise SystemdBackendError("application software view mount point is not canonical")
        if cls._manifest_digest(binding["manifest"]) != binding.get("view_manifest_digest"):
            raise SystemdBackendError("application software view manifest digest changed")
        expected_digests = {
            item["artifact"]: cls._manifest_digest(item["manifest"])
            for item in binding["objects"]
        }
        saved_digests = {
            item["artifact"]: item["manifest_digest"]
            for item in binding.get("object_manifest_digests", ())
            if isinstance(item, dict) and set(item) == {"artifact", "manifest_digest"}
        }
        if expected_digests != saved_digests:
            raise SystemdBackendError("application software artifact manifest digest changed")
        software_expected = [
            [item["root"], item["mount_point"]]
            for item in binding["objects"]
        ] + [[binding["root"], binding["mount_point"]]]
        if read_only != software_expected + workspace_expected:
            raise SystemdBackendError("read-only mount list disagrees with verified application software binding")
        destinations = [target for _source, target in software_expected]
        if len(destinations) != len(set(destinations)):
            raise SystemdBackendError("duplicate application software mount destination")
        for source, target in software_expected:
            source_path = Path(source)
            if source_path.is_symlink() or not source_path.is_dir() or source_path.resolve() != source_path.absolute():
                raise SystemdBackendError("application software source is missing or redirected")
            if not target.startswith("/applications/") or ".." in Path(target).parts:
                raise SystemdBackendError("invalid application software mount destination")

    @classmethod
    def _runtime_root_paths(cls, project_root, runtime_id):
        root, _identity, _prefix = cls._project(project_root)
        if not isinstance(runtime_id, str) or not re.fullmatch(r"[A-Z2-9]{6}", runtime_id):
            raise SystemdBackendError("invalid application runtime identity")
        mounts = root / "state" / "mounts"
        if mounts.is_symlink() or not mounts.is_dir() or mounts.resolve() != mounts.absolute():
            raise SystemdBackendError("state/mounts is unavailable or redirected")
        parent = mounts / "runtime-roots"
        runtime = parent / runtime_id
        return parent, runtime, runtime / "root"

    @classmethod
    def _expected_runtime_scaffold(cls, project_root, generation_root, definition):
        from zog.box_control.runtime.scaffold import (
            rootfs_bind_paths,
            rootfs_layout,
            runtime_facility_directories,
            runtime_facility_subdirectories,
        )

        runtime_id = definition.get("runtime_id")
        parent, runtime, runtime_root = cls._runtime_root_paths(
            project_root, runtime_id
        )
        requested_root = Path(definition.get("root_directory", ""))
        if requested_root != runtime_root or requested_root.is_symlink():
            raise SystemdBackendError(
                "RootDirectory is not the deterministic runtime scaffold"
            )
        try:
            binds, symlinks = rootfs_layout(generation_root)
            expected_effective = rootfs_bind_paths(
                generation_root,
                writable_destinations=tuple(
                    str(target)
                    for _source, target in definition.get("bind_paths", ())
                ),
            )
            facilities = runtime_facility_directories()
            facility_subdirectories = runtime_facility_subdirectories(generation_root)
        except Exception as exc:
            raise SystemdBackendError(
                f"cannot derive immutable generation projection: {exc}"
            ) from exc

        supplied_binds = [
            [str(source), str(target)]
            for source, target in definition.get("rootfs_bind_paths", ())
        ]
        expected_binds = [
            [str(source), target] for source, target in expected_effective
        ]
        if supplied_binds != expected_binds:
            raise SystemdBackendError(
                "rootfs read-only projection disagrees with selected generation"
            )

        # One exact destination may have only one effective source/access mode.
        # Parent/child overlays remain valid (for example read-only /var plus
        # writable /var/lib/app).
        seen = {}
        for label, values in (
            ("read-only rootfs", definition.get("rootfs_bind_paths", ())),
            ("read-only controller", definition.get("read_only_bind_paths", ())),
            ("writable", definition.get("bind_paths", ())),
        ):
            for _source, raw_target in values:
                target = str(raw_target)
                if target in seen:
                    raise SystemdBackendError(
                        "conflicting effective mount destination "
                        f"{target}: {seen[target]} and {label}"
                    )
                seen[target] = label

        scaffold_targets = set()
        for _source, raw_target in (
            list(definition.get("read_only_bind_paths", ()))
            + list(definition.get("bind_paths", ()))
        ):
            target = str(raw_target)
            path = Path(target)
            if not path.is_absolute() or ".." in path.parts:
                raise SystemdBackendError(
                    f"invalid runtime scaffold target: {target!r}"
                )
            if any(
                target == facility or target.startswith(facility + "/")
                for facility in facilities
            ):
                # A host capability target is controller-owned private /run,
                # but per-program grants must not change the shared runtime
                # scaffold manifest. systemd creates the leaf bind target in
                # the private /run namespace as needed.
                if not target.startswith("/run/zog-host/"):
                    scaffold_targets.add(target)

        return (
            parent,
            runtime,
            runtime_root,
            binds,
            symlinks,
            facilities,
            tuple(sorted(scaffold_targets | set(facility_subdirectories))),
        )

    @staticmethod
    def _scaffold_manifest(
        generation,
        generation_root,
        definition,
        binds,
        symlinks,
        facilities,
        scaffold_targets,
    ):
        return {
            "schema": 3 if any(
                target not in facilities and target.startswith(tuple(f + "/" for f in facilities))
                for target in scaffold_targets
                if target not in {
                    str(item[1]) for item in (
                        list(definition.get("bind_paths", ()))
                        + list(definition.get("read_only_bind_paths", ()))
                    )
                }
            ) else 2,
            "runtime_id": definition["runtime_id"],
            "application": definition["application_name"],
            "generation": str(generation),
            "generation_root": str(Path(generation_root)),
            "rootfs_bind_paths": [
                [str(source), target, kind]
                for source, target, kind in binds
            ],
            "rootfs_symlinks": [list(item) for item in symlinks],
            "runtime_facilities": list(facilities),
            "scaffold_targets": list(scaffold_targets),
        }

    @staticmethod
    def _write_json_durable(path, value):
        data = (
            json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode()
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
        try:
            with os.fdopen(descriptor, "wb", closefd=False) as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            os.close(descriptor)

    @classmethod
    def _validate_runtime_scaffold(
        cls,
        runtime,
        manifest,
        binds,
        symlinks,
        facilities,
        scaffold_targets,
    ):
        manifest_path = runtime / "scaffold.json"
        root = runtime / "root"
        if (
            runtime.is_symlink()
            or root.is_symlink()
            or not root.is_dir()
            or not manifest_path.is_file()
            or manifest_path.is_symlink()
        ):
            raise SystemdBackendError(
                "runtime root scaffold is missing or redirected"
            )
        try:
            saved = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError) as exc:
            raise SystemdBackendError(
                f"invalid runtime root scaffold manifest: {exc}"
            ) from exc
        if saved != manifest:
            raise SystemdBackendError(
                "runtime root scaffold does not match prepared launch inputs"
            )

        expected_top = {facility.lstrip("/") for facility in facilities}
        for facility in facilities:
            path = root / facility.lstrip("/")
            if path.is_symlink() or not path.is_dir():
                raise SystemdBackendError(
                    f"runtime facility {facility} is missing or redirected"
                )

        for _source, target, kind in binds:
            name = target.lstrip("/")
            expected_top.add(name)
            path = root / name
            if path.is_symlink():
                raise SystemdBackendError(
                    "runtime root projection target is redirected"
                )
            if kind == "directory" and not path.is_dir():
                raise SystemdBackendError(
                    "runtime root directory projection target is missing"
                )
            if kind == "file" and not path.is_file():
                raise SystemdBackendError(
                    "runtime root file projection target is missing"
                )
        for target, link in symlinks:
            name = target.lstrip("/")
            expected_top.add(name)
            path = root / name
            if not path.is_symlink() or os.readlink(path) != link:
                raise SystemdBackendError(
                    "runtime root symlink projection changed"
                )
        actual_top = {path.name for path in root.iterdir()}
        if actual_top != expected_top:
            raise SystemdBackendError(
                "runtime root scaffold contains unexpected top-level objects"
            )

        for target in scaffold_targets:
            path = root
            for part in Path(target).parts[1:]:
                path = path / part
                if path.is_symlink() or not path.is_dir():
                    raise SystemdBackendError(
                        f"runtime scaffold target {target} is missing or redirected"
                    )

        applications = root / "applications"
        expected_application_dirs = {applications}
        for target in scaffold_targets:
            current = root / target.lstrip("/")
            while current != applications.parent and current != root:
                if applications == current or applications in current.parents:
                    expected_application_dirs.add(current)
                current = current.parent
        actual_application_dirs = set()
        for path in applications.rglob("*"):
            if path.is_symlink() or not path.is_dir():
                raise SystemdBackendError(
                    "runtime /applications scaffold contains a non-directory object"
                )
            actual_application_dirs.add(path)
        if actual_application_dirs != expected_application_dirs - {applications}:
            raise SystemdBackendError(
                "runtime /applications scaffold contains unexpected paths"
            )

    @classmethod
    def _prepare_runtime_scaffold(
        cls, project_root, generation, generation_root, definition
    ):
        from zog.box_control.durability import synchronize_directory

        (
            parent,
            runtime,
            runtime_root,
            binds,
            symlinks,
            facilities,
            scaffold_targets,
        ) = cls._expected_runtime_scaffold(
            project_root, generation_root, definition
        )
        manifest = cls._scaffold_manifest(
            generation,
            generation_root,
            definition,
            binds,
            symlinks,
            facilities,
            scaffold_targets,
        )
        if runtime.exists() or runtime.is_symlink():
            cls._validate_runtime_scaffold(
                runtime,
                manifest,
                binds,
                symlinks,
                facilities,
                scaffold_targets,
            )
            return runtime_root
        if parent.is_symlink():
            raise SystemdBackendError(
                "runtime root scaffold parent is redirected"
            )
        parent.mkdir(mode=0o700, exist_ok=True)
        if (
            not parent.is_dir()
            or parent.is_symlink()
            or parent.resolve() != parent.absolute()
        ):
            raise SystemdBackendError("runtime root scaffold parent is invalid")
        candidate = parent / ("." + definition["runtime_id"] + ".candidate")
        if candidate.exists() or candidate.is_symlink():
            if (
                candidate.is_symlink()
                or not candidate.is_dir()
                or not shutil.rmtree.avoids_symlink_attacks
            ):
                raise SystemdBackendError(
                    "cannot safely discard interrupted runtime scaffold"
                )
            shutil.rmtree(candidate)
        candidate.mkdir(mode=0o700)
        candidate_root = candidate / "root"
        candidate_root.mkdir(mode=0o755)
        try:
            for facility in facilities:
                path = candidate_root / facility.lstrip("/")
                if path.parent != candidate_root:
                    raise SystemdBackendError(
                        "runtime facility must be top-level"
                    )
                path.mkdir(mode=0o755)

            for _source, target, kind in binds:
                path = candidate_root / target.lstrip("/")
                if path.parent != candidate_root:
                    raise SystemdBackendError(
                        "rootfs projection target is not top-level"
                    )
                if kind == "directory":
                    path.mkdir(mode=0o755)
                elif kind == "file":
                    fd = os.open(
                        path,
                        os.O_WRONLY
                        | os.O_CREAT
                        | os.O_EXCL
                        | os.O_NOFOLLOW,
                        0o600,
                    )
                    os.close(fd)
                else:
                    raise SystemdBackendError(
                        "unsupported rootfs projection kind"
                    )
            for target, link in symlinks:
                path = candidate_root / target.lstrip("/")
                if path.parent != candidate_root:
                    raise SystemdBackendError(
                        "rootfs symlink target is not top-level"
                    )
                path.symlink_to(link)

            for target in scaffold_targets:
                path = candidate_root / target.lstrip("/")
                if not any(
                    path == candidate_root / facility.lstrip("/")
                    or (candidate_root / facility.lstrip("/")) in path.parents
                    for facility in facilities
                ):
                    raise SystemdBackendError(
                        "runtime mount target escapes facility scaffold"
                    )
                path.mkdir(mode=0o755, parents=True, exist_ok=True)

            # mkdir modes are filtered by the daemon's umask. After chroot,
            # an unprivileged application must traverse the namespace root and
            # runtime facility scaffolding even when the controller uses 0077.
            # The containing candidate/runtime directory remains private (0700).
            for directory in (candidate_root, *candidate_root.rglob("*")):
                if not directory.is_symlink() and directory.is_dir():
                    directory.chmod(0o755)
            cls._write_json_durable(candidate / "scaffold.json", manifest)
            synchronize_directory(candidate_root)
            synchronize_directory(candidate)
            os.replace(candidate, runtime)
            synchronize_directory(parent)
        except BaseException:
            if (
                candidate.exists()
                and not candidate.is_symlink()
                and shutil.rmtree.avoids_symlink_attacks
            ):
                shutil.rmtree(candidate)
            raise
        cls._validate_runtime_scaffold(
            runtime,
            manifest,
            binds,
            symlinks,
            facilities,
            scaffold_targets,
        )
        return runtime_root

    def release_runtime_root(self, *, project_root, runtime_id):
        from zog.box_control.durability import synchronize_directory
        parent, runtime, _runtime_root = self._runtime_root_paths(project_root, runtime_id)
        root, identity, _prefix = self._project(project_root)
        slice_name = f"zog-{identity}-{runtime_id}.slice"
        observed = self.observe(project_root=root, unit_name=slice_name)
        if observed.get("exists"):
            raise SystemdBackendError("runtime root cleanup requires the application slice to be unloaded")
        if not runtime.exists() and not runtime.is_symlink():
            return
        if (
            runtime.is_symlink()
            or not runtime.is_dir()
            or runtime.parent != parent
            or not shutil.rmtree.avoids_symlink_attacks
        ):
            raise SystemdBackendError("runtime root scaffold cannot be removed safely")
        shutil.rmtree(runtime)
        synchronize_directory(parent)

    @classmethod
    def _validate_program_selection(cls, project_root, definition):
        """Privilege-bound confirmation of a single recorded program intent.

        The caller may not select another unit/command by altering a service
        dictionary. The authoritative operation and original request have
        already been saved durably before root-control accepts a start.
        """
        selected = definition.get('selected_program')
        application = str(definition.get('application_name', ''))
        program = str(definition.get('program_name', ''))
        # The certificate issuer is a fixed managed lifecycle, not a place
        # to smuggle an ad-hoc long-running inspection service through an
        # otherwise valid execution UID or software-view binding.  Preparation
        # is a separate controller-owned workflow, not a selected action.
        if application == 'certify-manage':
            if program not in {'prepare', 'issue', 'renew', 'inspect', 'stage'}:
                raise SystemdBackendError(
                    'unsupported certificate lifecycle program'
                )
            if selected == 'prepare':
                raise SystemdBackendError(
                    'certificate preparation is not a selected runtime'
                )
            if selected is None and program != 'prepare':
                raise SystemdBackendError(
                    'certificate lifecycle command requires selected-program authority'
                )
        if selected is None:
            return
        if (not isinstance(selected, str) or selected != program
                or not re.fullmatch(r'[a-z][a-z0-9-]{0,62}', selected)):
            raise SystemdBackendError('selected program does not match service identity')
        if not definition.get('execution_binding') or not definition.get('persistent_storage_id'):
            raise SystemdBackendError('selected program requires managed persistent credentials')
        from zog.box_control.operations import OperationStore
        from zog.box_control.project import Project
        from zog.box_control.requests import ApplicationRequestStore
        project = Project(Path(project_root))
        try:
            candidates = [
                record for record in OperationStore(project).records()
                if record['new_runtime_id'] == definition.get('runtime_id')
            ]
            if len(candidates) != 1:
                raise ValueError('no unique selected-program launch record')
            record = candidates[0]
            snapshot = record['application']
            programs = snapshot['programs']
            if (record['operation'] != 'launch'
                    or record['phase'] != 'launching'
                    or not record['request_id']
                    or record.get('selected_program') != selected
                    or snapshot.get('selected_program') != selected
                    or snapshot.get('name') != application
                    or len(programs) != 1 or programs[0]['name'] != selected):
                raise ValueError('selected-program operation intent changed')
            saved = programs[0]
            if (list(saved['command']) != list(definition.get('command', ()))
                    or list(saved['environment']) != list(definition.get('environment', ()))
                    or (saved.get('working_directory') or '/') != definition.get('working_directory')
                    or saved.get('user') != definition.get('user')
                    or saved.get('group') != definition.get('group')
                    or saved.get('execution_timeout_seconds') != definition.get('execution_timeout_seconds')):
                raise ValueError('selected command differs from prepared operation')
            if (snapshot.get('execution_binding') != definition['execution_binding']
                    or snapshot.get('storage_id') != definition['persistent_storage_id']):
                raise ValueError('selected-program grant or storage identity changed')
            if (definition['unit_name'] not in record['attempted_units']
                    or len(record['attempted_units']) != 1):
                raise ValueError('selected-program start intent not recorded exactly once')
            from zog.box_control.runtime.reference import RuntimeReferenceStore
            references = RuntimeReferenceStore.decode(record['references'])
            ref = references.get(definition['runtime_id'])
            if (ref is None or ref.request_id != record['request_id']
                    or ref.application != application
                    or ref.execution_binding != definition['execution_binding']
                    or len(ref.programs) != 1
                    or ref.programs[0].program != selected
                    or ref.programs[0].unit_name != definition['unit_name']
                    or list(ref.programs[0].command) != list(definition['command'])):
                raise ValueError('selected-program runtime reference disagrees with intent')
            requests = ApplicationRequestStore(
                project.application_request_dir, project.application_request_result_dir
            )
            path = requests.request_dir / (record['request_id'] + '.json')
            queued = requests.load(path)
            if (queued.operation.value != 'launch'
                    or queued.application != application
                    or queued.program_name != selected):
                raise ValueError('saved request selector differs from operation intent')
        except (OSError, ValueError, KeyError, TypeError, IndexError, RuntimeError) as exc:
            raise SystemdBackendError('selected-program authority is unavailable or disagrees') from exc

    @staticmethod
    def _validate_local_login_manager(definition):
        """Reserved privilege boundary: no greetd/PAM seat role exists in v1.

        This is a fail-closed gate for known login-manager declarations, not
        an authorization system for differently named privileged programs.
        An eventual role must validate an exact grant, PAM/seat/VT/logind,
        software view, command, identity and controller operation here.
        """
        app = str(definition.get("application_name", ""))
        program = str(definition.get("program_name", ""))
        reserved = {"greetd", "seatd", "login-manager", "display-manager",
                    "local-login-manager", "greetd-daemon"}
        if app in reserved or program in reserved:
            raise SystemdBackendError(
                "local seat login-manager authority is not implemented"
            )

    @classmethod
    def _validate_service_definition(cls, project_root, generation, definition):
        cls._validate_local_login_manager(definition)
        root = cls._validate_unit(project_root, str(definition["unit_name"]))
        cls._validate_unit(project_root, str(definition["slice_name"]))
        generation = str(generation)
        if not generation or Path(generation).name != generation or generation in {'.', '..'}:
            raise SystemdBackendError('invalid generation identity')
        legacy_root = root / "state" / "rootfs" / "generations" / generation / "root"
        published_root = root / "state" / "image-build" / "generations" / generation / "root"
        requested_generation_root = Path(definition["generation_root"]).resolve()
        if requested_generation_root == published_root.resolve():
            from zog.box_control.images import published_selection, ImageProviderError
            try:
                published_selection(root, generation)
            except ImageProviderError as exc:
                raise SystemdBackendError(str(exc)) from exc
        elif requested_generation_root == legacy_root.resolve():
            expected_root = legacy_root.resolve()
            manifest = expected_root / _MANIFEST_NAME
            try:
                raw = json.loads(manifest.read_text(encoding="utf-8"))
            except Exception as exc:
                raise SystemdBackendError(f"cannot validate generation manifest {manifest}: {exc}") from exc
            if str(raw.get("fingerprint")) != str(generation):
                raise SystemdBackendError("generation manifest identity does not match requested generation")
        else:
            raise SystemdBackendError('generation root is outside the selected project generation')
        (
            _parent,
            _runtime,
            expected_runtime_root,
            _binds,
            _symlinks,
            _facilities,
            _scaffold_targets,
        ) = cls._expected_runtime_scaffold(
            project_root, requested_generation_root, definition
        )
        if Path(definition["root_directory"]) != expected_runtime_root:
            raise SystemdBackendError("RootDirectory does not match the runtime scaffold")

        state_mounts = root / "state" / "mounts"
        for source, target in definition.get("bind_paths", ()):
            source_path = Path(source)
            binding = definition.get('workspace_binding') or {}
            workspace_sources = {binding.get('x11_directory'), binding.get('access_directory')}
            if not _under(source_path, state_mounts) and str(source_path) not in workspace_sources:
                raise SystemdBackendError(f"writable bind source is outside state/mounts: {source}")
            if not str(target).startswith("/") or ".." in Path(str(target)).parts:
                raise SystemdBackendError(f"invalid writable bind target: {target!r}")
        cls._validate_execution_binding(project_root, definition)
        cls._validate_program_selection(project_root, definition)
        # DNS-01 requires a separate host-owner installed, issuer-private
        # Cloudflare token with a current protected authorization revision.
        # No daemon caller can select its source, token or destination.
        if (definition.get("application_name") == "certify-manage"
                and definition.get("selected_program") in ("issue", "renew")):
            from .issuer_credentials import require_installed, IssuerCredentialError
            try:
                require_installed(project_root, definition)
            except (IssuerCredentialError, OSError, ValueError) as exc:
                raise SystemdBackendError(
                    "issuer-only DNS credential installation is unavailable or revoked"
                ) from exc
        cls._validate_host_bindings(project_root, definition)
        cls._validate_software_binding(project_root, definition)
        from zog.box_control.mounts import validate, inventory
        binding = definition.get('workspace_binding') or {}
        workspace_sources = {binding.get('x11_directory'), binding.get('access_directory')}
        if binding:
            from zog.box_control.mounts import validate_workspace_targets
            validate_workspace_targets(requested_generation_root)
        ordinary = [(source, target) for source, target in definition.get('bind_paths', ())
                    if str(source) not in workspace_sources]
        validate(requested_generation_root, ordinary, definition.get('command', ()), require_targets=True)
        recorded = definition.get('mount_inventory')
        if recorded is not None and recorded != inventory(
                requested_generation_root, definition.get('bind_paths', ()),
                read_only_mounts=definition.get('read_only_bind_paths', ()),
                persistent_storage_id=definition.get('persistent_storage_id'),
                workspace_binding=binding, software_binding=definition.get('software_binding'),
                host_bindings=definition.get('host_bindings', ())):
            raise SystemdBackendError('mount inventory disagrees with service definition')
        if definition.get("protect_system") != "strict":
            raise SystemdBackendError("ProtectSystem must remain strict")
        if not bool(definition.get("private_tmp")):
            raise SystemdBackendError("PrivateTmp must remain enabled")
        if not bool(definition.get("private_mounts")):
            raise SystemdBackendError("PrivateMounts must remain enabled")
        if not bool(definition.get("mount_api_vfs")):
            raise SystemdBackendError("MountAPIVFS must remain enabled")
        if definition.get("standard_output") != "journal" or definition.get("standard_error") != "journal":
            raise SystemdBackendError("program stdout/stderr must use journald")
        if int(definition.get("tasks_max", -1)) != 2**64 - 1:
            raise SystemdBackendError("TasksMax must remain infinity in the initial runtime model")
        timeout = definition.get("execution_timeout_seconds")
        if timeout is not None and (type(timeout) is not int or not 1 <= timeout <= 86400):
            raise SystemdBackendError("invalid execution timeout")
        command = definition.get("command") or ()
        if not command or not str(command[0]).startswith("/"):
            raise SystemdBackendError("ExecStart executable must be an absolute generation path")
        if definition.get("type") != "exec" or definition.get("exit_type") != "cgroup":
            raise SystemdBackendError("unsupported service lifecycle type")
        if definition.get("restart") != "no" or definition.get("kill_mode") != "control-group":
            raise SystemdBackendError("unsupported systemd restart/kill policy")
        if bool(definition.get("remain_after_exit")):
            raise SystemdBackendError("RemainAfterExit must be disabled")
        return root

    @staticmethod
    def _property(name: str, signature: str, *values: object):
        # Convert the bounded set of property shapes to typed D-Bus values.
        if signature == "s":
            value = str(values[0])
        elif signature == "t":
            value = int(values[0])
        elif signature == "b":
            value = values[0] in (True, "true")
        elif signature == "as":
            value = list(values[1:])
        elif signature == "a(sasb)":
            count = int(values[2])
            value = [[values[1], list(values[3:3 + count]), values[-1] == "true"]]
        elif signature == "a(ssbt)":
            value = [[values[i], values[i+1], values[i+2] == "true", int(values[i+3])]
                     for i in range(1, len(values), 4)]
        else:
            raise SystemdBackendError(f"unsupported property signature: {signature}")
        return [name, Variant(signature, value)]

    def _job(self, method, signature, body):
        try:
            return self.jobs.call(method, signature, body, job=True)
        except JobError as exc:
            raise SystemdBackendError(str(exc)) from exc

    def release(self, *, project_root, unit_name):
        self._validate_unit(project_root, unit_name)
        try:
            self.jobs.release(unit_name)
        except JobError as exc:
            raise SystemdBackendError(str(exc)) from exc

    def start_slice(self, *, project_root, slice_name: str, description: str) -> None:
        self._validate_unit(project_root, slice_name)
        props = [
            self._property("Description", "s", description),
            self._property("TasksMax", "t", 2**64 - 1),
        ]
        props.append(self._property("AddRef", "b", "true"))
        self._job("StartTransientUnit", "ssa(sv)a(sa(sv))", [slice_name, "fail", props, []])

    def sync_application_storage(self, *, project_root, application, storage_id):
        """Flush completed prepared data before the controller publishes readiness."""
        import stat
        from zog.box_control.application_storage import ApplicationStorage
        from zog.box_control.project import Project
        from zog.box_control.durability import synchronize_directory
        from zog.box_control.errors import PersistenceError
        project = Project(Path(project_root).resolve())
        record = ApplicationStorage(project).load(application)
        if (not record or record['storage_id'] != storage_id
            or record['state'] not in {'preparing', 'uncertain'} or record['cleanup_pending']
            or len(record['steps']) != len(record['definition']['preparation'])
            or any(step['outcome'] != 'success' or not step['cleanup_complete'] for step in record['steps'])):
            raise SystemdBackendError('preparation has not completed safely')
        if record.get("definition", {}).get("execution_identity") is not None:
            from .identities import verify, ExecutionIdentityError
            try:
                verify(
                    project.path, application,
                    record["definition"].get("execution_binding"),
                    storage_id=storage_id,
                )
            except ExecutionIdentityError as exc:
                raise SystemdBackendError(f"prepared storage execution identity is not valid: {exc}") from exc
        base = project.mounts_dir / 'persistent' / storage_id
        if base.is_symlink() or base.resolve() != base.absolute() or not base.is_dir():
            raise SystemdBackendError('persistent storage is missing or redirected')
        for name in record['mounts']:
            path = base / name
            if not path.is_dir() or path.is_symlink() or path.resolve() != path.absolute():
                raise SystemdBackendError('prepared mount is missing or redirected')
        def fail_walk(error):
            raise error
        try:
            for directory, dirs, files, descriptor in os.fwalk(base, topdown=False, follow_symlinks=False, onerror=fail_walk):
                for name in files:
                    info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                    if stat.S_ISREG(info.st_mode):
                        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
                        try:
                            os.fsync(fd)
                        finally:
                            os.close(fd)
                os.fsync(descriptor)
            synchronize_directory(base.parent)
        except OSError as exc:
            raise PersistenceError(f'cannot synchronize prepared environment: {exc}') from exc

    def delete_application_storage(self, *, project_root, application, storage_id):
        import shutil
        from zog.box_control.application_storage import ApplicationStorage
        from zog.box_control.project import Project
        from zog.box_control.runtime.reference import RuntimeReferenceStore
        from zog.box_control.durability import synchronize_directory
        project = Project(Path(project_root).resolve())
        record = ApplicationStorage(project).load(application)
        if not record or record['storage_id'] != storage_id or record['state'] != 'deleting' or record['cleanup_pending']:
            raise SystemdBackendError('no matching durable storage deletion intent')
        references = RuntimeReferenceStore(project.runtime_reference_file).load()
        for ref in references.values():
            if ref.application == application:
                if ref.cleanup_pending:
                    raise SystemdBackendError('runtime cleanup protects persistent storage')
                for program in ref.programs:
                    observed = self.observe(project_root=project.path, unit_name=program.unit_name)
                    if observed.get('exists'):
                        raise SystemdBackendError('runtime unit still loaded; storage deletion blocked')
        base = project.mounts_dir / 'persistent' / storage_id
        if base.is_symlink() or base.resolve() != base.absolute():
            raise SystemdBackendError('persistent storage path is redirected')
        if base.exists():
            if not shutil.rmtree.avoids_symlink_attacks:
                raise SystemdBackendError('safe recursive deletion is unsupported')
            shutil.rmtree(base)
        if base.parent.exists():
            synchronize_directory(base.parent)

    @staticmethod
    def _persistent_directories(project_root, definition):
        storage_id = definition.get('persistent_storage_id')
        if storage_id is None:
            return
        if not isinstance(storage_id, str) or not re.fullmatch('[a-f0-9]{32}', storage_id):
            raise SystemdBackendError('invalid persistent storage identity')
        from zog.box_control.durability import ensure_directory, synchronize_directory
        grant = BusctlSystemdBackend._validate_execution_binding(project_root, definition)
        if grant is not None:
            uid, gid = grant["uid"], grant["gid"]
        else:
            uid = gid = None
        user = definition.get('user')
        if grant is None and (not isinstance(user, str) or not user.strip()):
            raise SystemdBackendError(
                'persistent execution requires an explicit, provisioned host user'
            )
        try:
            account = (None if grant is not None else
                       pwd.getpwuid(int(user)) if user.isdecimal() else pwd.getpwnam(user))
        except (KeyError, ValueError, OverflowError) as exc:
            raise SystemdBackendError(
                f'persistent execution user {user!r} is not provisioned in the host account database'
            ) from exc
        group = definition.get('group')
        if grant is not None:
            pass  # Root-owned grant fixes both numeric IDs; host NSS is not required.
        elif group is None:
            gid = account.pw_gid
        elif isinstance(group, str) and group.isdecimal():
            try:
                gid = int(group)
            except (ValueError, OverflowError) as exc:
                raise SystemdBackendError('invalid numeric execution group') from exc
        elif isinstance(group, str) and group:
            try:
                gid = grp.getgrnam(group).gr_gid
            except KeyError as exc:
                raise SystemdBackendError(
                    f'persistent execution group {group!r} is not provisioned in the host group database'
                ) from exc
        else:
            raise SystemdBackendError('invalid persistent execution group')
        uid = uid if grant is not None else account.pw_uid
        if uid == 0 or gid == 0:
            raise SystemdBackendError('persistent preparation must be unprivileged')
        base = Path(project_root).resolve() / 'state' / 'mounts' / 'persistent' / storage_id
        if base.resolve() != base:
            raise SystemdBackendError('persistent storage path is redirected')
        ensure_directory(base)
        for source, _target in definition.get('bind_paths', ()):
            binding = definition.get('workspace_binding') or {}
            if source in (binding.get('x11_directory'), binding.get('access_directory')):
                continue
            path = Path(source)
            if path.parent != base or path.resolve() != path or path.is_symlink():
                raise SystemdBackendError('persistent mount must be a direct owned directory')
            try:
                path.mkdir(mode=0o700)
            except FileExistsError:
                info = path.lstat()
                if (not stat.S_ISDIR(info.st_mode)
                        or (info.st_uid, info.st_gid) != (uid, gid)):
                    raise SystemdBackendError(
                        'existing persistent directory ownership disagrees; explicit repair required'
                    )
                if grant is not None and stat.S_IMODE(info.st_mode) != 0o700:
                    # Never auto-repair the permissions of an existing
                    # certificate/account/key storage directory on launch.
                    raise SystemdBackendError(
                        'managed persistent directory mode drift; explicit owner review required'
                    )
            else:
                os.chown(path, uid, gid)
                if grant is not None:
                    # Creation respects arbitrary root-control UMask. Newly
                    # issued grant storage must have exact private DAC mode.
                    os.chmod(path, 0o700)
            if grant is not None and stat.S_IMODE(path.lstat().st_mode) != 0o700:
                raise SystemdBackendError('managed persistent directory is not private 0700')
            synchronize_directory(path)
            synchronize_directory(base)

    def start_service(self, *, project_root, generation: str, definition: dict) -> None:
        self._validate_service_definition(project_root, generation, definition)
        # Timings are diagnostic only, not evidence of program completion.
        # Emit only the already validated fixed systemd unit identity; no
        # command, environment, credential, policy or writable path values.
        from .events import emit
        started_at = time.monotonic()
        unit = definition["unit_name"]
        emit("systemd-start-service-validated", unit_name=unit)
        generation_root = Path(definition["generation_root"]).resolve()
        self._prepare_runtime_scaffold(
            project_root, generation, generation_root, definition
        )
        binding = definition.get('workspace_binding')
        if binding:
            from .workspace import WorkspaceBackend
            WorkspaceBackend(self).verify(project_root=project_root, binding=binding)
        self._persistent_directories(project_root, definition)
        command = [str(item) for item in definition["command"]]
        environment = [f"{key}={value}" for key, value in definition.get("environment", ())]
        binds = definition.get("bind_paths", ())
        props: list[list[str]] = [
            self._property("Description", "s", definition.get("description") or definition["unit_name"]),
            self._property("Slice", "s", definition["slice_name"]),
            self._property("Type", "s", definition["type"]),
            self._property("ExitType", "s", definition["exit_type"]),
            self._property("KillMode", "s", definition["kill_mode"]),
            self._property("Restart", "s", definition["restart"]),
            self._property("RemainAfterExit", "b", str(bool(definition["remain_after_exit"])).lower()),
            self._property("RootDirectory", "s", definition["root_directory"]),
            self._property("ExecStart", "a(sasb)", 1, command[0], len(command), *command, "false"),
            self._property("Environment", "as", len(environment), *environment),
            self._property("WorkingDirectory", "s", definition["working_directory"]),
            self._property("ProtectSystem", "s", definition["protect_system"]),
            self._property("PrivateTmp", "b", str(bool(definition["private_tmp"])).lower()),
            self._property("PrivateMounts", "b", str(bool(definition["private_mounts"])).lower()),
            self._property("MountAPIVFS", "b", str(bool(definition["mount_api_vfs"])).lower()),
            self._property("StandardOutput", "s", definition["standard_output"]),
            self._property("StandardError", "s", definition["standard_error"]),
            self._property("User", "s", definition["user"]),
            self._property("TasksMax", "t", int(definition["tasks_max"])),
        ]
        if binding:
            props.append(self._property('NetworkNamespacePath', 's', binding['namespace_path']))
        read_only_binds = (
            list(definition.get("rootfs_bind_paths", ()))
            + list(definition.get("read_only_bind_paths", ()))
        )
        if read_only_binds:
            read_only_values: list[object] = [len(read_only_binds)]
            for source, target in read_only_binds:
                read_only_values.extend((source, target, "false", 0))
            props.append(self._property("BindReadOnlyPaths", "a(ssbt)", *read_only_values))
        if definition.get("execution_timeout_seconds") is not None:
            props.append(self._property("RuntimeMaxUSec", "t", definition["execution_timeout_seconds"] * 1_000_000))
        if definition.get("group"):
            props.append(self._property("Group", "s", definition["group"]))
        if binds:
            bind_values: list[object] = [len(binds)]
            for source, target in binds:
                bind_values.extend((source, target, "false", 0))
            props.append(self._property("BindPaths", "a(ssbt)", *bind_values))
        props.append(self._property("AddRef", "b", "true"))
        # Bound systemd's own stop escalation as well as our wait for its job.
        props.append(self._property("TimeoutStopUSec", "t", int(definition["timeout_stop_microseconds"])))
        emit("systemd-start-service-job-submitted", unit_name=unit,
             preparation_seconds=round(time.monotonic() - started_at, 6))
        try:
            self._job("StartTransientUnit", "ssa(sv)a(sa(sv))",
                      [unit, "fail", props, []])
        except Exception:
            # A failed local wait cannot prove PID1 rejected the job.
            emit("systemd-start-service-job-unconfirmed", unit_name=unit,
                 elapsed_seconds=round(time.monotonic() - started_at, 6))
            raise
        emit("systemd-start-service-job-completed", unit_name=unit,
             elapsed_seconds=round(time.monotonic() - started_at, 6))

    def _get_unit_path(self, unit_name: str) -> str | None:
        output = self._run(
            ["busctl", "--system", "--json=short", "call", _SYSTEMD_DEST,
             _SYSTEMD_MANAGER_PATH, _SYSTEMD_MANAGER_IFACE, "GetUnit", "s", unit_name],
            allow_missing_unit=True,
        )
        if output is None:
            return None
        return str(self._json_data(output))

    def _get_property(self, object_path: str, interface: str, name: str, *, optional=False):
        try:
            output = self._run(
                ["busctl", "--system", "--json=short", "get-property", _SYSTEMD_DEST,
                 object_path, interface, name]
            )
        except SystemdBackendError as exc:
            # Optional means that an older supported systemd release may not
            # expose this particular property. It must not turn unrelated bus,
            # permission, or transport failures into a fabricated None value.
            text = str(exc)
            if optional and any(
                marker in text
                for marker in ("UnknownProperty", "UnknownInterface", "No such property")
            ):
                return None
            raise
        return self._json_data(output or "")

    @staticmethod
    def _invocation_id(value) -> str | None:
        if value in (None, "", []):
            return None
        if isinstance(value, list) and all(isinstance(item, int) for item in value):
            if not any(value):
                return None
            return "".join(f"{item:02x}" for item in value)
        return str(value).replace(" ", "")

    @staticmethod
    def _normalize_exec_start(value):
        if not value:
            return []
        entry = value[0] if isinstance(value, list) and value else value
        if isinstance(entry, list) and len(entry) >= 2 and isinstance(entry[1], list):
            return [str(item) for item in entry[1]]
        return value

    @staticmethod
    def _normalize_bind_paths(value):
        result = []
        for entry in value or ():
            if isinstance(entry, list) and len(entry) >= 2:
                result.append([str(entry[0]), str(entry[1])])
        return result

    @bounded_observation
    def observe(self, *, project_root, unit_name: str) -> dict:
        self._validate_unit(project_root, unit_name)
        object_path = self._get_unit_path(unit_name)
        if object_path is None:
            return {"exists": False, "unit_name": unit_name}
        unit = lambda name, optional=False: self._get_property(object_path, _UNIT_IFACE, name, optional=optional)
        service = lambda name, optional=False: self._get_property(object_path, _SERVICE_IFACE, name, optional=optional)
        transient = unit("Transient", optional=True)
        fragment = unit("FragmentPath", optional=True) or ""
        drop_ins = unit("DropInPaths", optional=True) or []
        invocation = self._invocation_id(unit("InvocationID", optional=True))
        active = str(unit("ActiveState"))
        sub = str(unit("SubState"))
        is_service = unit_name.endswith(".service")
        is_slice = unit_name.endswith(".slice")
        typed = service if is_service else (
            (lambda name, optional=False: self._get_property(
                object_path, _SLICE_IFACE, name, optional=optional
            )) if is_slice else None
        )
        control_group = typed("ControlGroup", optional=True) if typed else None
        slice_name = typed("Slice", optional=True) if typed else None
        tasks_max = typed("TasksMax", optional=True) if typed else None
        result = service("Result", optional=True) if is_service else None
        main_pid = service("MainPID", optional=True) if is_service else None

        properties = []
        if is_service:
            mapping = {
                "Type": service("Type"),
                "ExitType": service("ExitType"),
                "KillMode": service("KillMode"),
                "Restart": service("Restart"),
                "RemainAfterExit": service("RemainAfterExit"),
                "Slice": slice_name,
                "RootDirectory": service("RootDirectory"),
                "ExecStart": self._normalize_exec_start(service("ExecStart")),
                "Environment": sorted(str(item) for item in (service("Environment") or [])),
                "WorkingDirectory": service("WorkingDirectory"),
                "BindPaths": self._normalize_bind_paths(service("BindPaths", optional=True) or []),
                "ProtectSystem": service("ProtectSystem"),
                "PrivateTmp": service("PrivateTmp"),
                "PrivateMounts": service("PrivateMounts"),
                "MountAPIVFS": service("MountAPIVFS"),
                "StandardOutput": service("StandardOutput"),
                "StandardError": service("StandardError"),
                "User": service("User"),
                "TasksMax": tasks_max,
                "TimeoutStopUSec": service("TimeoutStopUSec"),
            }
            namespace_path = service('NetworkNamespacePath', optional=True)
            if namespace_path:
                mapping['NetworkNamespacePath'] = namespace_path
            read_only_paths = self._normalize_bind_paths(
                service('BindReadOnlyPaths', optional=True) or []
            )
            if read_only_paths:
                mapping['BindReadOnlyPaths'] = read_only_paths
            maximum = service("RuntimeMaxUSec", optional=True)
            if maximum is not None:
                mapping["RuntimeMaxUSec"] = maximum
            group = service("Group", optional=True)
            if group:
                mapping["Group"] = group
            properties = list(mapping.items())

        return {
            "exists": True,
            "unit_name": unit_name,
            "transient": bool(transient) if transient is not None else not bool(fragment),
            "fragment_path": str(fragment),
            "drop_in_paths": [str(item) for item in drop_ins],
            "invocation_id": invocation,
            "active_state": active,
            "sub_state": sub,
            "result": result,
            "main_pid": int(main_pid) if main_pid else None,
            "control_group": str(control_group) if control_group else None,
            "properties": [[name, value] for name, value in properties],
        }

    def kill(self, *, project_root, unit_name: str, signal_number: int) -> None:
        self._validate_unit(project_root, unit_name)
        self._manager_call("KillUnit", "ssi", unit_name, "all", int(signal_number))

    def stop(self, *, project_root, unit_name: str) -> None:
        self._validate_unit(project_root, unit_name)
        try:
            self._job("StopUnit", "ss", [unit_name, "replace"])
        except SystemdBackendError as exc:
            if "org.freedesktop.systemd1.NoSuchUnit" not in str(exc):
                raise

    def reset_failed(self, *, project_root, unit_name: str) -> None:
        self._validate_unit(project_root, unit_name)
        self._manager_call("ResetFailedUnit", "s", unit_name, allow_missing_unit=True)
