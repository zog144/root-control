"""Privileged build resource registration and finite systemd execution.

The socket has the same trusted-local access boundary as root-control. Build
commands use a separate non-root identity and never access controller storage.
"""
import hashlib
import json
import math
import os
import re
from pathlib import Path, PurePosixPath
import shutil
import stat
import time
from .events import emit

from zog.box_control.durability import replace_json, ensure_directory, synchronize_directory
from .systemd import SystemdBackendError
from dbus_next import Variant


# The one approved host-deploy fresh compiler parent. This is selected by
# root-control's protected build-only role, never an RPC payload or a
# controller-generated per-job name.
FRESH_COMPILER_PROJECT = "fresh-cross-bootstrap-oct25"
FRESH_COMPILER_PARENT_SLICE = "zogfreshcrossbootstrapoct25.slice"
FRESH_COMPILER_LOG_NAMESPACE = "zogfreshcrossbootstrapoct25"
FRESH_COMPILER_BUILD_MOUNT = Path("/home/zog-cross-owner/fresh-cross-bootstrap-oct25/work")
FRESH_COMPILER_EXTERNAL_MOUNT = Path("/var/lib/zog/host-deploy/fresh-cross-bootstrap-oct25/external")
FRESH_COMPILER_RESOURCES = FRESH_COMPILER_EXTERNAL_MOUNT / "artifacts/build-resources"


def identity(value):
    if not isinstance(value, str) or len(value) != 32 or any(c not in '0123456789abcdef' for c in value):
        raise SystemdBackendError('invalid build identity')
    return value


def positive(value, label):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 < value <= 604800:
        raise SystemdBackendError(f'invalid {label}')
    return value


def canonical_request(raw):
    value = json.loads(json.dumps(raw, allow_nan=False))
    required = {'build_root_id', 'source_workspace_id', 'output_workspace_id', 'command', 'environment',
                'working_directory', 'execution_user_id', 'execution_group_id', 'startup_timeout_seconds',
                'execution_timeout_seconds', 'termination_grace_seconds', 'resource_limits', 'read_only_root', 'network_access'}
    if set(value) - {'device_profile'} != required:
        raise SystemdBackendError('build request has missing or unsupported fields')
    if 'device_profile' in value and value['device_profile'] != 'private-null-permission-test':
        raise SystemdBackendError('unsupported build device profile')
    root = identity(value['build_root_id'])
    if value['source_workspace_id'] != root + '-source' or value['output_workspace_id'] != root + '-output':
        raise SystemdBackendError('workspace does not belong to registered build root')
    if value['read_only_root'] is not True or value['network_access'] is not False:
        raise SystemdBackendError('build requires read-only root and disabled network')
    for key in ('execution_user_id', 'execution_group_id'):
        if type(value[key]) is not int or not 0 < value[key] < 2**31:
            raise SystemdBackendError('explicit nonzero build UID/GID required')
    for key in ('startup_timeout_seconds', 'execution_timeout_seconds', 'termination_grace_seconds'):
        positive(value[key], key)
    if not isinstance(value['command'], list) or not value['command'] or any(not isinstance(s, str) or '\0' in s for s in value['command']) or not value['command'][0]:
        raise SystemdBackendError('build command must be nonempty string argv')
    env = value['environment']
    if not isinstance(env, dict) or any(not isinstance(k, str) or not k or '=' in k or '\0' in k or not isinstance(v, str) or '\0' in v for k, v in env.items()):
        raise SystemdBackendError('invalid explicit build environment')
    directory = value['working_directory']
    if not isinstance(directory, str) or not directory.startswith('/') or '..' in PurePosixPath(directory).parts or '\0' in directory:
        raise SystemdBackendError('invalid in-root working directory')
    limits = value['resource_limits']
    if not isinstance(limits, dict) or set(limits) - {'stack-maximum-bytes', 'cpu-weight'} != {'thread-count-maximum', 'memory-maximum-bytes'}:
        raise SystemdBackendError('explicit thread-count-maximum and memory-maximum-bytes required')
    if any(type(v) is not int or not 0 < v < 2**63 for v in limits.values()):
        raise SystemdBackendError('invalid build resource limit')
    if 'cpu-weight' in limits and not 1 <= limits['cpu-weight'] <= 10000:
        raise SystemdBackendError('cpu-weight must be 1..10000')
    return value


def root_path(root, source, output, virtual):
    """Resolve symlinks using guest-root semantics, never host absolute links."""
    pending = list(PurePosixPath(virtual).parts[1:])
    parts, links = [], 0
    def host(items):
        if items[:2] == ['image-build', 'source']:
            return source.joinpath(*items[2:])
        if items[:2] == ['image-build', 'output']:
            return output.joinpath(*items[2:])
        return root.joinpath(*items)
    while pending:
        part = pending.pop(0)
        if part == '..':
            if parts: parts.pop()
            continue
        if part in ('', '.'): continue
        candidate = host(parts + [part])
        if candidate.is_symlink():
            links += 1
            if links > 40: raise SystemdBackendError('excessive build-root symlinks')
            target = PurePosixPath(os.readlink(candidate))
            if target.is_absolute():
                parts = []
                pending = list(target.parts[1:]) + pending
            else:
                pending = list(target.parts) + pending
        else:
            parts.append(part)
    return host(parts), '/' + '/'.join(parts)


class BuildBackend:
    def __init__(self, systemd, directory=Path('/var/lib/zog/build-resources'), *, journal_barrier=None,
                 parent_slice=None, authorized_project_root=None):
        # Only the protected fresh compiler role may select this exact parent.
        # Existing shared-controller deployments keep their original naming.
        if parent_slice is not None:
            if (parent_slice != FRESH_COMPILER_PARENT_SLICE
                    or type(authorized_project_root) is not str
                    or Path(authorized_project_root).name != FRESH_COMPILER_PROJECT
                    or str(Path(authorized_project_root)) != authorized_project_root):
                raise SystemdBackendError("invalid bound compiler parent slice and Project")
        elif authorized_project_root is not None:
            raise SystemdBackendError("unbound compiler parent Project")
        self.systemd = systemd
        self.journal_barrier = journal_barrier
        self.directory = (FRESH_COMPILER_RESOURCES if parent_slice is not None else Path(directory))
        self.parent_slice = parent_slice
        self.authorized_project_root = authorized_project_root
        self.log_namespace = (FRESH_COMPILER_LOG_NAMESPACE if parent_slice is not None else None)
        # The legacy journal-barrier broker synchronizes only the default
        # journal namespace. For this new isolated namespace we must not
        # claim that a default-journal sync proves the build's logs durable.
        if self.log_namespace and journal_barrier is not None:
            raise SystemdBackendError("fresh build journal barrier lacks namespaced synchronization")

    def _check_parent_binding(self, project_root, stored, logging=None):
        if self.parent_slice is None:
            if stored is not None or logging is not None:
                raise SystemdBackendError("historical build parent/logging binding cannot change")
            return
        if (type(project_root) is not str
                or project_root != self.authorized_project_root
                or stored != self.parent_slice
                or logging != self.log_namespace):
            raise SystemdBackendError("build parent/logging binding differs from protected role")

    def _verify_active_parent(self):
        if self.parent_slice is None:
            return
        # No generic privileged parent-slice RPC is granted to the controller.
        # Read exact manager properties directly from this pinned identifier.
        obj = self.systemd._get_unit_path(self.parent_slice)
        if obj is None:
            raise SystemdBackendError("protected compiler parent slice missing")
        from .systemd import _UNIT_IFACE, _SLICE_IFACE
        load_state = self.systemd._get_property(obj, _UNIT_IFACE, "LoadState")
        state = self.systemd._get_property(obj, _UNIT_IFACE, "ActiveState")
        group = self.systemd._get_property(obj, _SLICE_IFACE, "ControlGroup")
        if load_state != "loaded" or state != "active" or group != "/" + self.parent_slice:
            raise SystemdBackendError("protected compiler parent slice not active or relocated")

    @staticmethod
    def _check_worker_cgroup(info, observed):
        parent = info.get("parent_slice")
        if parent is None or not observed.get("exists"):
            return
        if parent != FRESH_COMPILER_PARENT_SLICE:
            raise SystemdBackendError("invalid saved compiler parent slice")
        child = info["slice_name"]
        expected = "/" + parent + "/" + child + "/" + info["unit_name"]
        group = observed.get("control_group")
        if group:
            if group != expected:
                raise SystemdBackendError("compiler worker escaped protected parent cgroup")
        elif observed.get("active_state") not in ("inactive", "failed"):
            raise SystemdBackendError("active compiler worker lacks protected cgroup")


    def _verify_fresh_storage(self, project_root, paths=()):
        """Require real bounded mount backing before modifying fresh compiler state."""
        if self.parent_slice is None:
            return
        project = Path(project_root)
        attempts = project / "state/image-build/attempts"
        if project != Path(self.authorized_project_root):
            raise SystemdBackendError("fresh Project identity changed")
        for mount in (FRESH_COMPILER_BUILD_MOUNT, FRESH_COMPILER_EXTERNAL_MOUNT):
            if mount.is_symlink() or not os.path.ismount(mount):
                raise SystemdBackendError("fresh compiler quota mount is missing")
        # os.path.ismount() cannot reliably identify bind mounts on the SAME
        # filesystem: demand an exact kernel mountinfo target for attempts.
        mountpoints = set()
        for line in Path("/proc/self/mountinfo").read_text().splitlines():
            fields = line.split()
            if len(fields) < 10:
                raise SystemdBackendError("invalid kernel mount inventory")
            mountpoints.add(Path(re.sub(
                r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), fields[4])))
        if attempts not in mountpoints:
            raise SystemdBackendError("fresh attempts bind mount is missing")
        # The worker must not own a quota mount root: otherwise it could
        # rename the root-owned scratch bind source within the mount.
        for fixed in (FRESH_COMPILER_BUILD_MOUNT, FRESH_COMPILER_EXTERNAL_MOUNT):
            meta = fixed.stat()
            if (meta.st_uid != 0 or meta.st_gid != 0 or meta.st_mode & 0o022):
                raise SystemdBackendError("untrusted quota mount root ownership")
        if (attempts.stat().st_dev != FRESH_COMPILER_BUILD_MOUNT.stat().st_dev
                or self.directory.stat().st_dev != FRESH_COMPILER_EXTERNAL_MOUNT.stat().st_dev
                or self.directory.is_symlink()):
            raise SystemdBackendError("fresh build or privileged registration storage escapes quota")
        for source in paths:
            item = Path(source)
            if (item.is_symlink()
                    or not item.resolve().is_relative_to(attempts.resolve())
                    or item.stat().st_dev != attempts.stat().st_dev):
                raise SystemdBackendError("fresh worker input escapes quota")
        if paths:
            checked = [Path(p).resolve() for p in paths]
            for mount in mountpoints:
                if any(mount == p or mount.is_relative_to(p) for p in checked):
                    raise SystemdBackendError("unreviewed nested worker mount")

    def area(self, project_root):
        # Every API path, including status, cancellation, release and forget,
        # must fail closed if either fixed backing mount disappeared.
        self._verify_fresh_storage(project_root)
        root, _, _ = self.systemd._project(project_root)
        return self.directory / hashlib.sha256(str(root).encode()).hexdigest()

    def resource_path(self, project_root, resource_id):
        return self.area(project_root) / identity(resource_id)

    def load(self, project_root, resource_id):
        path = self.resource_path(project_root, resource_id)
        raw = json.loads((path / 'registration.json').read_text())
        if raw['state'] != 'ready': raise SystemdBackendError('build registration is not ready')
        self._check_parent_binding(str(Path(project_root)), raw["intent"].get("parent_slice"), raw["intent"].get("log_namespace"))
        self._verify_fresh_storage(project_root, (
            raw['intent']['prepared_root'], raw['intent']['source_directory'],
            raw['intent']['output_directory']))
        return path, raw

    @staticmethod
    def _tree(path, uid, gid, *, immutable=False):
        # Reject devices/sockets/FIFOs; copy symlinks as links, never follow them.
        for current, dirs, files in os.walk(path, followlinks=False):
            for name in ['.'] + dirs + files:
                item = Path(current) if name == '.' else Path(current) / name
                mode = item.lstat().st_mode
                if stat.S_ISLNK(mode): continue
                if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
                    raise SystemdBackendError(f'unsupported build input type: {item}')
                os.chown(item, uid, gid, follow_symlinks=False)
                permissions = stat.S_IMODE(mode) & 0o777
                if immutable:
                    permissions = (permissions & ~0o222) | (0o555 if stat.S_ISDIR(mode) else 0o444)
                else:
                    permissions |= 0o770 if stat.S_ISDIR(mode) else 0o660
                os.chmod(item, permissions, follow_symlinks=False)
                if stat.S_ISREG(mode):
                    with item.open('rb') as stream: os.fsync(stream.fileno())
            synchronize_directory(Path(current))

    def registration_status(self, *, project_root, resource_id):
        """Atomic durable snapshot; safe on the independent inspection lane."""
        path = self.resource_path(project_root, resource_id) / 'registration.json'
        try:
            record = json.loads(path.read_text())
        except FileNotFoundError:
            return {'resource_id': resource_id, 'state': 'absent'}
        self._check_parent_binding(str(Path(project_root)), record["intent"].get("parent_slice"), record["intent"].get("log_namespace"))
        return record

    def register(self, *, project_root, resource_id, prepared_root, source_directory, output_directory,
                 input_manifest_id, execution_user_id, execution_group_id):
        identity(resource_id)
        root = Path(project_root).resolve()
        paths = [Path(p).resolve(strict=True) for p in (prepared_root, source_directory, output_directory)]
        allowed = root / 'state' / 'image-build' / 'attempts'
        if any(not p.is_dir() or not p.is_relative_to(allowed) for p in paths):
            raise SystemdBackendError('build inputs must be directories beneath state/image-build/attempts')
        if any(a == b or a.is_relative_to(b) or b.is_relative_to(a) for i, a in enumerate(paths) for b in paths[i+1:]):
            raise SystemdBackendError('build root/source/output paths must not overlap')
        if (type(execution_user_id) is not int or type(execution_group_id) is not int
                or not 0 < execution_user_id < 2**31
                or not 0 < execution_group_id < 2**31):
            raise SystemdBackendError('separate nonzero numeric build UID/GID required')
        project_owner = root.stat()
        if (execution_user_id == project_owner.st_uid
                or execution_group_id == project_owner.st_gid):
            raise SystemdBackendError('build UID/GID must differ from controller project owner')
        if not isinstance(input_manifest_id, str) or not input_manifest_id:
            raise SystemdBackendError('verified input manifest identity is required')
        self._check_parent_binding(str(root), self.parent_slice, self.log_namespace)
        self._verify_fresh_storage(str(root), paths)
        intent = dict(prepared_root=str(paths[0]), source_directory=str(paths[1]), output_directory=str(paths[2]),
                      input_manifest_id=input_manifest_id, execution_user_id=execution_user_id, execution_group_id=execution_group_id)
        if self.parent_slice is not None:
            intent["parent_slice"] = self.parent_slice
            intent["log_namespace"] = self.log_namespace
        path = self.resource_path(root, resource_id)
        manifest = path / 'registration.json'
        if self.parent_slice is not None and not self.directory.is_dir():
            raise SystemdBackendError('fresh privileged resource root not installed')
        ensure_directory(self.directory)
        os.chmod(self.directory, 0o755)
        ensure_directory(path)
        if manifest.exists():
            previous = json.loads(manifest.read_text())
            if previous['intent'] != intent: raise SystemdBackendError('registration identity already bound')
            if previous['state'] == 'ready': return previous
            if previous['state'] == 'released': raise SystemdBackendError('registration was released')
        # Reserve overlapping workspaces even while import is interrupted.
        for other in path.parent.glob('*/registration.json'):
            if other == manifest: continue
            prior = json.loads(other.read_text())
            if prior['state'] == 'released': continue
            for a in paths[1:]:
                for key in ('source_directory', 'output_directory'):
                    b = Path(prior['intent'][key])
                    if a == b or a.is_relative_to(b) or b.is_relative_to(a):
                        raise SystemdBackendError('workspace already registered')
        record = {'schema': 1, 'resource_id': resource_id, 'intent': intent, 'state': 'importing'}
        started = time.monotonic()
        record['started_at'] = time.time()
        def progress(phase):
            record.update(phase=phase, updated_at=time.time(), elapsed_seconds=time.monotonic()-started)
            replace_json(manifest, record)
            emit('build-registration-progress', resource_id=resource_id, state=record['state'],
                 phase=phase, elapsed_seconds=record['elapsed_seconds'])
        progress('validate')
        imported = path / 'root' 
        if imported.exists():
            shutil.rmtree(imported)
        # Source is a trusted finalized tree; special files are rejected before copy.
        for current, dirs, files in os.walk(paths[0], followlinks=False):
            if Path(current) == paths[0]:
                dirs[:] = [d for d in dirs if d not in {'dev','proc','sys','run','tmp'}]
            for name in dirs + files:
                mode = (Path(current)/name).lstat().st_mode
                if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode) or stat.S_ISLNK(mode)):
                    raise SystemdBackendError('special file in prepared root')
        progress('copy-root')
        shutil.copytree(paths[0], imported, symlinks=True,
            ignore=lambda directory,names: set(names)&{'dev','proc','sys','run','tmp'} if Path(directory)==paths[0] else set())
        if (imported / 'image-build').is_symlink(): raise SystemdBackendError('reserved mount parent is a symlink')
        for name in ('image-build/source', 'image-build/output', 'tmp', 'run', 'run/zog-journal', 'proc', 'sys', 'dev', *(['var/tmp'] if self.parent_slice else [])):
            dest = imported / name
            if dest.is_symlink(): raise SystemdBackendError('reserved build mount target is a symlink')
            dest.mkdir(parents=True, exist_ok=True)
        progress('sync-root')
        self._tree(imported, 0, 0, immutable=True)
        for phase, workspace in zip(('sync-source', 'sync-output'), paths[1:]):
            progress(phase)
            self._tree(workspace, execution_user_id, execution_group_id)
        record['state'] = 'ready'
        progress('ready')
        return record

    def prepare(self, *, project_root, job_id, request):
        request = canonical_request(request)
        identity(job_id)
        path, registration = self.load(project_root, request['build_root_id'])
        binding = registration['intent']
        self._check_parent_binding(str(Path(project_root)), binding.get("parent_slice"), binding.get("log_namespace"))
        if any(request[k] != binding[k] for k in ('execution_user_id', 'execution_group_id')):
            raise SystemdBackendError('execution identity differs from registration')
        # The registration remains immutable, but host-install ownership can
        # change between register and prepare. Never promote a previously
        # separate build principal into the controller project's owner/group.
        controller_root, _, _ = self.systemd._project(project_root)
        owner = controller_root.stat()
        if (binding['execution_user_id'] == owner.st_uid
                or binding['execution_group_id'] == owner.st_gid):
            raise SystemdBackendError('build principal now overlaps controller project ownership')
        source, output = Path(binding['source_directory']), Path(binding['output_directory'])
        self._verify_fresh_storage(project_root, (binding['prepared_root'], source, output))
        executable = request['command'][0]
        directory = request['working_directory']
        cwd, _ = root_path(path/'root', source, output, directory)
        if not cwd.is_dir(): raise SystemdBackendError('in-root working directory missing')
        candidates = [executable if executable.startswith('/') else directory + '/' + executable] if '/' in executable else [p+'/'+executable for p in request['environment'].get('PATH', '').split(':') if p.startswith('/')]
        resolved = None
        for candidate in candidates:
            host, virtual = root_path(path/'root', source, output, candidate)
            if host.is_file() and host.stat().st_mode & 0o111:
                resolved = virtual
                break
        if resolved is None: raise SystemdBackendError('executable not found inside build root and explicit PATH')
        unit = f'zog-{Path(project_root).name}-build{job_id}.service'
        slice_name = (f'{self.parent_slice[:-6]}-build{job_id}.slice' if self.parent_slice
                      else f'zog-{Path(project_root).name}-build{job_id}.slice')
        result = dict(request=request, job_id=job_id, unit_name=unit, slice_name=slice_name,
                      resolved_executable=resolved, process_cleanup_complete=False)
        if self.parent_slice is not None:
            result["parent_slice"] = self.parent_slice
            result["log_namespace"] = self.log_namespace
        jobs = path / 'jobs'
        ensure_directory(jobs)
        job_path = jobs / (job_id+'.json')
        if job_path.exists():
            prior = json.loads(job_path.read_text())
            if prior['request'] != request: raise SystemdBackendError('job identity already bound')
            if (prior.get("parent_slice") != self.parent_slice
                    or prior.get("slice_name") != slice_name):
                raise SystemdBackendError("prepared job slice differs from protected parent")
            if prior.get("log_namespace") != self.log_namespace:
                raise SystemdBackendError("prepared job logging binding differs from protected role")
            return prior
        for other in jobs.glob('*.json'):
            if not json.loads(other.read_text())['process_cleanup_complete']:
                raise SystemdBackendError('registered workspace has an unfinished writer')
        replace_json(job_path, result)
        return result

    @staticmethod
    def private_null(path):
        """Dedicated inode; never bind the host device or follow caller paths."""
        node = path / 'permission-test-null'
        try:
            os.mknod(node, stat.S_IFCHR | 0o600, os.makedev(1, 3))
        except FileExistsError:
            pass
        else:
            # A privileged daemon may retain the controller's effective group.
            # Normalize only the inode we just created; never repair substitutes.
            os.chown(node, 0, 0, follow_symlinks=False)
        info = node.lstat()
        if not stat.S_ISCHR(info.st_mode) or info.st_rdev != os.makedev(1, 3) or info.st_uid != 0 or info.st_gid != 0:
            raise SystemdBackendError('invalid private null device')
        os.chmod(node, 0o666, follow_symlinks=False)
        synchronize_directory(path)
        return node

    def _prepare_fresh_scratch(self, path, info, registration):
        """Bind all mutable guest temporary paths to the 30-GiB worker mount.

        No host /tmp or /var/tmp PrivateTmp directories are permitted on the
        fresh compiler role. These are created before the no-replay marker.
        """
        # Source directories MUST be rooted in a privileged, non-worker-
        # writable parent. Putting these beneath output (owned by the build
        # UID) allows that UID to rename a parent after validation and before
        # PID1 consumes the BindPaths transaction.
        scratch_root = FRESH_COMPILER_BUILD_MOUNT / ".zog-runtime"
        self._verify_fresh_storage(self.authorized_project_root, (
            registration['intent']['output_directory'],))
        scratch_root.mkdir(mode=0o755, exist_ok=True)
        # Check the parent *before* creating anything beneath it. No path
        # creation is allowed through an existing symlink or untrusted owner.
        metadata = scratch_root.lstat()
        if (not stat.S_ISDIR(metadata.st_mode) or scratch_root.is_symlink()
                or metadata.st_uid != 0 or metadata.st_gid != 0
                or metadata.st_mode & 0o022
                or metadata.st_dev != FRESH_COMPILER_BUILD_MOUNT.stat().st_dev):
            raise SystemdBackendError("untrusted fresh scratch parent")
        job = scratch_root / identity(info['job_id'])
        job.mkdir(mode=0o755, exist_ok=True)
        metadata = job.lstat()
        if (not stat.S_ISDIR(metadata.st_mode) or job.is_symlink()
                or metadata.st_uid != 0 or metadata.st_gid != 0
                or metadata.st_mode & 0o022
                or metadata.st_dev != FRESH_COMPILER_BUILD_MOUNT.stat().st_dev):
            raise SystemdBackendError("untrusted fresh scratch job")
        directories = []
        for name in ('tmp', 'vartmp', 'run'):
            candidate = job / name
            candidate.mkdir(mode=0o700, exist_ok=True)
            if (candidate.is_symlink()
                    or candidate.stat().st_dev != FRESH_COMPILER_BUILD_MOUNT.stat().st_dev
                    or candidate.resolve() != candidate):
                raise SystemdBackendError('fresh scratch was redirected')
            os.chown(candidate, info['request']['execution_user_id'],
                     info['request']['execution_group_id'], follow_symlinks=False)
            directories.append(candidate)
        return directories

    @staticmethod
    def _reload_safe_argv(command):
        """Encode literal argv for portable systemd ExecStart D-Bus execution.

        The observed systemd 252 expands dollars during launch, so an
        argument's '$' must be passed as '$$'. In contrast, percent characters
        supplied over D-Bus reach the process unchanged: doubling them
        corrupts the original argv. No durable request bytes are rewritten.
        """
        if (not command or any(type(arg) is not str or "\x00" in arg for arg in command)
                or "$" in command[0] or "%" in command[0]):
            raise SystemdBackendError("unsupported literal build executable")
        return [command[0], *(arg.replace("$", "$$") for arg in command[1:])]

    @staticmethod
    def _matches_exec_start(observed, expected):
        """Match only the two exact systemd 252 D-Bus ExecStart representations.

        The observed reload parser inserts literal backslashes before dollars
        and semicolons. Compute the alternate array solely from the frozen
        request-derived expected argv; never broadly unescape arbitrary
        systemd properties or bypass an unrelated policy mismatch.
        """
        if (type(expected) is not list or not expected
                or any(type(arg) is not str for arg in expected)
                or type(observed) is not list
                or any(type(arg) is not str for arg in observed)):
            return False
        reloaded = [expected[0], *(
            arg.replace("$", "\\$").replace(";", "\\;")
            for arg in expected[1:]
        )]
        return observed == expected or observed == reloaded

    def start(self, *, project_root, job_id, request):
        info = self.prepare(project_root=project_root, job_id=job_id, request=request)
        path, registration = self.load(project_root, request['build_root_id'])
        job_path = path/'jobs'/(job_id+'.json')
        if info.get('start_attempted'):
            raise SystemdBackendError('build start already attempted; inspect existing job')
        self._check_parent_binding(str(Path(project_root)), info.get("parent_slice"), info.get("log_namespace"))
        if self.parent_slice is not None:
            self._verify_fresh_storage(project_root, (registration['intent']['prepared_root'], registration['intent']['source_directory'], registration['intent']['output_directory']))
            expected_slice = f'{self.parent_slice[:-6]}-build{identity(job_id)}.slice'
            if info["slice_name"] != expected_slice:
                raise SystemdBackendError("build job slice changed from protected parent")
            # Do not persist start_attempted unless the host-owned parent is
            # already active and has exactly the expected PID1 cgroup.
            self._verify_active_parent()
        if self.systemd.version() < 250: raise SystemdBackendError('systemd 250 or later required')
        # Verify the exact reload-safe representation BEFORE persisting the
        # one-way start_attempted marker or touching systemd.
        r = info['request']
        command = [info['resolved_executable'], *r['command'][1:]]
        literal_argv = self._reload_safe_argv(command)
        null_device = self.private_null(path) if info['request'].get('device_profile') == 'private-null-permission-test' else None
        if self.journal_barrier:
            if request['termination_grace_seconds'] < 3:
                raise SystemdBackendError('journal barrier requires at least 3 seconds termination grace')
            # Registration is durable before systemd can run the exit hook.
            # Retry before start reuses its identity; attempted jobs never restart.
            if not info.get('journal_barrier_token'):
                info['journal_barrier_token'] = self.journal_barrier.register(
                    info['unit_name'], request['execution_user_id'], job_id)
                replace_json(job_path, info)
        elif info.get('journal_barrier_token'):
            raise SystemdBackendError('prepared journal barrier requires enabled broker')
        scratch = self._prepare_fresh_scratch(path, info, registration) if self.parent_slice else None
        info['start_attempted'] = True
        replace_json(job_path, info)
        self.systemd.start_slice(project_root=project_root, slice_name=info['slice_name'], description='Zog build job')
        bind = registration['intent']
        # Fixed security policy; callers cannot weaken these properties.
        values = {
            'Description': ('s', 'Zog finite build job'), 'Slice': ('s', info['slice_name']),
            'Type': ('s', 'exec'), 'ExitType': ('s', 'cgroup'), 'Restart': ('s', 'no'),
            'KillMode': ('s', 'control-group'), 'RemainAfterExit': ('b', False), 'AddRef': ('b', True),
            'RootDirectory': ('s', str(path/'root')), 'WorkingDirectory': ('s', r['working_directory']),
            'User': ('s', str(r['execution_user_id'])), 'Group': ('s', str(r['execution_group_id'])),
            'ProtectSystem': ('s', 'strict'), 'PrivateNetwork': ('b', True), 'PrivateDevices': ('b', True),
            'PrivateTmp': ('b', self.parent_slice is None), 'MountAPIVFS': ('b', True), 'NoNewPrivileges': ('b', True),
            'CapabilityBoundingSet': ('t', 0), 'AmbientCapabilities': ('t', 0),
            'StandardOutput': ('s', 'journal'), 'StandardError': ('s', 'journal'),
            'TimeoutStartUSec': ('t', int(r['startup_timeout_seconds']*1000000)),
            'RuntimeMaxUSec': ('t', int(r['execution_timeout_seconds']*1000000)),
            'TimeoutStopUSec': ('t', int(r['termination_grace_seconds']*1000000)),
            'SendSIGKILL': ('b', True), 'TasksMax': ('t', r['resource_limits']['thread-count-maximum']),
            'MemoryMax': ('t', r['resource_limits']['memory-maximum-bytes'])}
        if self.parent_slice is not None:
            values['PrivateMounts'] = ('b', True)
            values['ProtectControlGroups'] = ('b', True)
            values['Delegate'] = ('b', False)
            values['ProtectKernelTunables'] = ('b', True)
            values['RestrictNamespaces'] = ('t', 0)
            values['LimitCORE'] = ('t', 0)
        if self.log_namespace is not None:
            # Fixed trusted worker log routing; caller may not supply any
            # journal namespace or output-path override in canonical_request.
            values["LogNamespace"] = ("s", self.log_namespace)
        if 'cpu-weight' in r['resource_limits']:
            values['CPUWeight'] = ('t', r['resource_limits']['cpu-weight'])
        if 'stack-maximum-bytes' in r['resource_limits']:
            stack = r['resource_limits']['stack-maximum-bytes']
            values['LimitSTACK'] = ('t', stack)
            values['LimitSTACKSoft'] = ('t', stack)
        props = [self.systemd._property(k, sig, value) for k,(sig,value) in values.items()]
        environment = [f'{k}={v}' for k,v in sorted(r['environment'].items())]
        binds = [bind['source_directory'],'/image-build/source','false',0,bind['output_directory'],'/image-build/output','false',0]
        if scratch is not None:
            for source, dest in zip(scratch, ('/tmp', '/var/tmp', '/run')):
                binds += [str(source), dest, 'false', 0]
        if null_device is not None: binds += [str(null_device),'/dev/null','false',0]
        # Use the stable ExecStart property, not ExecStartEx. Older systemd
        # releases accept ExecStartEx over D-Bus but serialize it as an
        # unknown key on daemon-reload, destroying observation properties.
        # Explicit encoding retains the frozen literal argv semantics.
        props += [self.systemd._property('Environment', 'as', len(environment), *environment),
                  self.systemd._property('ExecStart', 'a(sasb)', 1,
                      command[0], len(literal_argv), *literal_argv, 'false'),
                  self.systemd._property('BindPaths','a(ssbt)',len(binds)//4,*binds)]
        if self.journal_barrier:
            # All injected paths are under the controller-created /run directory.
            target = path/'root/run/zog-journal'
            if target.is_symlink(): raise SystemdBackendError('unsafe barrier mount target')
            target.mkdir(exist_ok=True)
            props += [
                self.systemd._property('BindReadOnlyPaths','a(ssbt)',2,
                    str(self.journal_barrier.socket_path.parent),'/run/zog-journal','false',0,
                    str(self.journal_barrier.helper),'/run/zog-journal/wait','false',0),
                # ExecStopPostEx has the same reload-serialization defect.
                # The last boolean preserves its ignore-failure policy.
                self.systemd._property('ExecStopPost', 'a(sasb)', 1,
                    '/run/zog-journal/wait', 2, '/run/zog-journal/wait',
                    info['journal_barrier_token'], 'true')]
        self.systemd._job('StartTransientUnit','ssa(sv)a(sa(sv))',[info['unit_name'],'fail',props,[]])
        return info

    @staticmethod
    def expected_properties(path, info):
        r = info['request']
        expected = {'RootDirectory':str(path/'root'), 'User':str(r['execution_user_id']),
                'Group':str(r['execution_group_id']), 'ExitType':'cgroup','Type':'exec',
                'Restart':'no','ProtectSystem':'strict','KillMode':'control-group',
                'WorkingDirectory':r['working_directory'],
                'ExecStart':BuildBackend._reload_safe_argv(
                    [info['resolved_executable'], *r['command'][1:]]),
                'PrivateNetwork':True,'NoNewPrivileges':True,'CapabilityBoundingSet':0,
                'RuntimeMaxUSec':int(r['execution_timeout_seconds']*1000000)}
        if info.get("parent_slice") is not None:
            if info["parent_slice"] != FRESH_COMPILER_PARENT_SLICE:
                raise SystemdBackendError("invalid prepared compiler parent")
            if info.get("log_namespace") != FRESH_COMPILER_LOG_NAMESPACE:
                raise SystemdBackendError("saved compiler log namespace differs from bound role")
            expected["Slice"] = info["slice_name"]
            expected["LogNamespace"] = info["log_namespace"]
            expected["StandardOutput"] = "journal"
            expected["StandardError"] = "journal"
            expected['PrivateTmp'] = False
            expected['PrivateMounts'] = True
            expected['ProtectControlGroups'] = True
            expected['Delegate'] = False
            expected['ProtectKernelTunables'] = True
            expected['RestrictNamespaces'] = 0
            expected['LimitCORE'] = 0
        return expected

    def observe(self, *, project_root, job_id, build_root_id):
        path, _ = self.load(project_root, build_root_id)
        job_path = path/'jobs'/(identity(job_id)+'.json')
        if not job_path.exists(): return {'exists':False}
        info = json.loads(job_path.read_text())
        self._check_parent_binding(str(Path(project_root)), info.get("parent_slice"), info.get("log_namespace"))
        expected = self.expected_properties(path,info)
        try:
            raw = self.systemd.observe(project_root=project_root, unit_name=info['unit_name'])
            self._check_worker_cgroup(info, raw)
            if raw['exists']:
                obj = self.systemd._get_unit_path(info['unit_name'])
                properties = dict(raw['properties'])
                for name in ('PrivateNetwork','NoNewPrivileges','CapabilityBoundingSet','RuntimeMaxUSec',
                             *(['LogNamespace', 'PrivateTmp', 'PrivateMounts', 'ProtectControlGroups',
                                'Delegate', 'ProtectKernelTunables', 'RestrictNamespaces',
                                'LimitCORE'] if self.log_namespace is not None else [])):
                    properties[name]=self.systemd._get_property(obj,'org.freedesktop.systemd1.Service',name)
                for name,value in expected.items():
                    observed = properties.get(name)
                    matching = (self._matches_exec_start(observed, value)
                                if name == 'ExecStart' else observed == value)
                    if not matching:
                        raise SystemdBackendError(f'build property mismatch: {name}')
                for key in ('ExecMainCode', 'ExecMainStatus', 'ExecMainExitTimestampMonotonic'):
                    raw[key] = self.systemd._get_property(obj, 'org.freedesktop.systemd1.Service', key)
                raw['cgroup_empty'] = (self.cgroup_empty(raw.get('control_group')) if raw.get('control_group') else raw.get('active_state') in ('inactive','failed'))
        except SystemdBackendError:
            # The last AddRef can vanish during this multi-property observation.
            # Only independently verified absence allows the durable fallback.
            if self.systemd._get_unit_path(info['unit_name']) is not None: raise
            raw = {'exists':False}
        token = info.get('journal_barrier_token')
        if token:
            from .journal_barrier import JournalBarrier
            barrier = self.journal_barrier or JournalBarrier()
            raw['journal_barrier'] = barrier.status(token)
            if not raw.get('exists'):
                evidence = barrier.evidence(token,unit=info['unit_name'],job_id=job_id,
                                            uid=info['request']['execution_user_id'])
                if evidence is not None:
                    properties=dict(evidence['properties'])
                    properties['ExecStart']=self.systemd._normalize_exec_start(properties.get('ExecStart'))
                    for name,value in expected.items():
                        observed = properties.get(name)
                        matching = (self._matches_exec_start(observed, value)
                                    if name == 'ExecStart' else observed == value)
                        if not matching:
                            raise SystemdBackendError(f'exit evidence property mismatch: {name}')
                    raw['terminal_evidence']={k:v for k,v in evidence.items() if k!='properties'}
            if raw['journal_barrier']['status'] in ('pending','attempted') and (not raw.get('exists') or raw.get('active_state') in ('inactive','failed')):
                raw['journal_barrier']['status'] = 'unconfirmed'
        else:
            raw['journal_barrier'] = {'status':'not-enabled'}
        return raw

    @staticmethod
    def cgroup_empty(group):
        if not group: return False
        path = Path('/sys/fs/cgroup') / group.lstrip('/')
        if not path.resolve().is_relative_to('/sys/fs/cgroup'): raise SystemdBackendError('invalid cgroup path')
        try:
            values = dict(line.split() for line in (path/'cgroup.events').read_text().splitlines())
            return values.get('populated') == '0'
        except FileNotFoundError: return True

    def cleanup(self, *, project_root, job_id, build_root_id):
        path, _ = self.load(project_root, build_root_id)
        job_path = path/'jobs'/(identity(job_id)+'.json')
        if not job_path.exists(): return True  # No start is possible without its durable privileged record.
        info = json.loads(job_path.read_text())
        self._check_parent_binding(str(Path(project_root)), info.get("parent_slice"), info.get("log_namespace"))
        for unit in (info['unit_name'], info['slice_name']):
            raw = self.systemd.observe(project_root=project_root, unit_name=unit)
            if info.get("parent_slice") is not None:
                parent = info["parent_slice"]
                expected_group = ("/" + parent + "/" + info["slice_name"]
                                  + ("/" + info["unit_name"] if unit.endswith(".service") else ""))
                if raw["exists"] and raw.get("control_group") != expected_group:
                    if (raw.get("control_group")
                            or raw.get("active_state") not in ("inactive", "failed")):
                        raise SystemdBackendError("cannot cleanup worker outside bound parent")
            if raw['exists']:
                if raw.get('control_group'):
                    if not self.cgroup_empty(raw['control_group']): return False
                elif unit.endswith('.service') and raw.get('active_state') not in ('inactive','failed'):
                    return False
                self.systemd.stop(project_root=project_root, unit_name=unit)
                self.systemd.reset_failed(project_root=project_root, unit_name=unit)
                self.systemd.release(project_root=project_root, unit_name=unit)
                if self.systemd.observe(project_root=project_root, unit_name=unit)['exists']: return False
        info['process_cleanup_complete'] = True
        replace_json(job_path, info)
        return True

    def cancel(self, *, project_root, job_id, build_root_id, expected_invocation_id=None):
        path, _ = self.load(project_root, build_root_id)
        job_path = path/'jobs'/(identity(job_id)+'.json')
        if not job_path.exists(): return
        info = json.loads(job_path.read_text())
        observed = self.observe(project_root=project_root,job_id=job_id,build_root_id=build_root_id)
        if not observed.get('exists'): return
        if expected_invocation_id and observed.get('invocation_id') != expected_invocation_id:
            raise SystemdBackendError('refusing to cancel a different build invocation')
        self.systemd.stop(project_root=project_root, unit_name=info['unit_name'])

    def reclaim_workspace_directories(self, *, project_root, build_root_id):
        """Return directory ownership after all jobs stop; preserve file modes/data.

        Only recorded source/output workspaces are accepted. This also supports
        an administrator migrating already-released registrations. A workspace
        re-registered for another build remains protected.
        """
        project, _, _ = self.systemd._project(project_root)
        owner = Path(project).stat()
        uid, gid = owner.st_uid, owner.st_gid
        path = self.resource_path(project_root, build_root_id)
        record = json.loads((path/'registration.json').read_text())
        if record['state'] not in ('releasing', 'released'):
            raise SystemdBackendError('workspace ownership requires resource release')
        for job in (path/'jobs').glob('*.json'):
            if not json.loads(job.read_text())['process_cleanup_complete']:
                raise SystemdBackendError('workspace still pinned by unfinished job')
        allowed = Path(project)/'state/image-build/attempts'
        workspaces = [Path(record['intent'][key]) for key in ('source_directory','output_directory')]
        for workspace in workspaces:
            if workspace.is_symlink() or workspace.resolve() != workspace or not workspace.is_relative_to(allowed):
                raise SystemdBackendError('recorded workspace path changed')
            for other in path.parent.glob('*/registration.json'):
                if other == path/'registration.json': continue
                prior = json.loads(other.read_text())
                if prior['state'] == 'released': continue
                for key in ('source_directory','output_directory'):
                    other_workspace = Path(prior['intent'][key])
                    if workspace == other_workspace or workspace.is_relative_to(other_workspace) or other_workspace.is_relative_to(workspace):
                        raise SystemdBackendError('workspace protected by another registration')
            if not workspace.exists(): continue
            for line in Path('/proc/self/mountinfo').read_text().splitlines():
                mount = Path(re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), line.split()[4]))
                if mount == workspace or workspace in mount.parents:
                    raise SystemdBackendError('workspace contains a mount')
            # Descriptor-relative traversal avoids following directory symlinks.
            # Files (including hard links) are never chowned or chmodded.
            for current, dirs, files, descriptor in os.fwalk(workspace, topdown=False, follow_symlinks=False):
                os.fchown(descriptor, uid, gid)
                os.fsync(descriptor)

    def release(self, *, project_root, build_root_id):
        path = self.resource_path(project_root, build_root_id)
        manifest = path/'registration.json'
        if not manifest.exists():
            if (path/'root').exists(): raise SystemdBackendError('unrecorded imported root requires investigation')
            return {'state': 'released'}
        record = json.loads(manifest.read_text())
        self._check_parent_binding(str(Path(project_root)), record["intent"].get("parent_slice"), record["intent"].get("log_namespace"))
        if record['state'] == 'released': return record
        for job in (path/'jobs').glob('*.json'):
            if not json.loads(job.read_text())['process_cleanup_complete']:
                raise SystemdBackendError('build root still pinned by unfinished job')
        # Mark intent before deletion; retry repeats removal and its barriers.
        record['state'] = 'releasing'
        replace_json(manifest, record)
        if (path/'root').exists(): shutil.rmtree(path/'root')
        self.reclaim_workspace_directories(project_root=project_root, build_root_id=build_root_id)
        (path/'permission-test-null').unlink(missing_ok=True)
        synchronize_directory(path)
        record['state'] = 'released'
        replace_json(manifest, record)
        return record

    def forget(self, *, project_root, build_root_id):
        path = self.resource_path(project_root, build_root_id)
        if not path.exists():
            synchronize_directory(path.parent)
            return
        raw = json.loads((path/'registration.json').read_text())
        if raw['state'] != 'released': raise SystemdBackendError('cannot forget retained build root')
        from .journal_barrier import JournalBarrier
        for job in (path/'jobs').glob('*.json'):
            token=json.loads(job.read_text()).get('journal_barrier_token')
            if token: (self.journal_barrier or JournalBarrier()).forget(token)
        shutil.rmtree(path)
        synchronize_directory(path.parent)
