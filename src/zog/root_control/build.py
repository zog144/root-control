"""Finite builds bound to the authenticated non-root Unix socket peer.

Only kernel SO_PEERCRED determines the execution UID/GID. The caller's JSON
cannot select or switch identities. The root-control daemon keeps its own
privileged management role; PID1 receives numeric User=/Group= derived from
the already authenticated box-control peer, not from the root daemon.
Historical registrations remain readable but cannot start again.
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
                'working_directory', 'startup_timeout_seconds',
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


LEGACY_SYSTEMD_ARGV_ENCODING = 'systemd-252-dollar-doubled-v1'
# Linux MAX_ARG_STRLEN is PAGE_SIZE * 32 on the supported compiler hosts.
# Validate the eventual execve argv, not the larger D-Bus wire form.
LEGACY_ARGV_MAX_BYTES = 128 * 1024 - 1


def legacy_systemd_argv(command):
    """Encode literal argv for systemd 250-253's expanding ExecStart D-Bus API.

    systemd stores the doubled dollar signs in ExecStart. Its executor then
    reduces each '$$' to one literal '$', without consulting environment
    variables, splitting words or invoking a shell. The original build request
    must never be rewritten to this wire representation.
    """
    if not isinstance(command, list) or not command:
        raise SystemdBackendError('invalid legacy build argv')
    encoded = []
    for arg in command:
        if not isinstance(arg, str) or '\0' in arg:
            raise SystemdBackendError('invalid legacy build argument')
        wire = arg.replace('$', '$$')
        try:
            size = len(arg.encode('utf-8'))
        except UnicodeEncodeError as exc:
            raise SystemdBackendError('build argument is not valid UTF-8') from exc
        if size > LEGACY_ARGV_MAX_BYTES:
            raise SystemdBackendError('build argument exceeds legacy exec limit')
        encoded.append(wire)
    return encoded



INHERITED_BUILD_SCHEMA = 2


def authenticated_build_peer(peer):
    """Validate a kernel-derived (effective uid, primary gid) pair."""
    if (type(peer) is not tuple or len(peer) != 2
            or any(type(x) is not int or not 0 < x < 2**31 for x in peer)):
        raise SystemdBackendError('build requires authenticated non-root socket peer UID/GID')
    return peer


def assert_bound_registration(record, peer):
    uid, gid = authenticated_build_peer(peer)
    if (type(record) is not dict or record.get('schema') != INHERITED_BUILD_SCHEMA
            or record.get('execution_identity') != {'uid':uid, 'gid':gid}):
        raise SystemdBackendError('historical or differently bound build registration cannot replay')
    return uid, gid


def assert_bound_job(record, peer):
    uid, gid = authenticated_build_peer(peer)
    if (type(record) is not dict or record.get('schema') != INHERITED_BUILD_SCHEMA
            or record.get('execution_identity') != {'uid':uid, 'gid':gid}):
        raise SystemdBackendError('historical or differently bound build job cannot replay')
    return uid, gid


def check_peer_access(path, peer, required, *, label):
    """Conservative POSIX DAC preflight; actual child access is kernel enforced.

    Do not repair permissions, create directories or chown to make a missing
    Project accessible. Supplementary groups/ACLs are deliberately not
    inferred from an unauthenticated request; their absence may fail closed.
    """
    uid, gid = authenticated_build_peer(peer)
    path = Path(path)
    for item in (*reversed(path.parents), path):
        try:
            st = item.stat()
        except FileNotFoundError as exc:
            raise SystemdBackendError(f'{label} missing (ENOENT): {item}') from exc
        except PermissionError as exc:
            raise SystemdBackendError(f'{label} inaccessible (EACCES): {item}') from exc
        bits = (st.st_mode >> (6 if st.st_uid == uid else 3 if st.st_gid == gid else 0)) & 7
        need = required if item == path else 1
        if bits & need != need:
            raise SystemdBackendError(f'{label} inaccessible to build peer (EACCES): {item}')
    return path

def check_peer_tree_access(root, peer, *, writable, label):
    """Check entire input tree before privileged import touches any storage."""
    for current, directories, files in os.walk(root, followlinks=False):
        for path in (Path(current), *(Path(current)/name for name in directories+files)):
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode):
                continue
            if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
                raise SystemdBackendError(f'{label} has unsupported entry: {path}')
            permissions = (7 if writable else 5) if stat.S_ISDIR(mode) else (6 if writable else 4)
            check_peer_access(path, peer, permissions, label=label)


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
    def __init__(self, systemd, directory=Path('/var/lib/zog/build-resources'), *, journal_barrier=None):
        self.systemd = systemd
        self.journal_barrier = journal_barrier
        self.directory = Path(directory)

    def area(self, project_root):
        root, _, _ = self.systemd._project(project_root)
        return self.directory / hashlib.sha256(str(root).encode()).hexdigest()

    def resource_path(self, project_root, resource_id):
        return self.area(project_root) / identity(resource_id)

    def load(self, project_root, resource_id):
        path = self.resource_path(project_root, resource_id)
        raw = json.loads((path / 'registration.json').read_text())
        if raw['state'] != 'ready': raise SystemdBackendError('build registration is not ready')
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
        return record

    def register(self, *, project_root, resource_id, prepared_root, source_directory, output_directory,
                 input_manifest_id, _peer):
        uid, gid = authenticated_build_peer(_peer)
        identity(resource_id)
        root = Path(project_root).resolve()
        check_peer_access(root, _peer, 5, label='build Project')
        paths = [Path(p).resolve(strict=True) for p in (prepared_root, source_directory, output_directory)]
        allowed = root / 'state' / 'image-build' / 'attempts'
        if any(not p.is_dir() or not p.is_relative_to(allowed) for p in paths):
            raise SystemdBackendError('build inputs must be directories beneath state/image-build/attempts')
        # The input Project must already be accessible to the executing peer;
        # root-control cannot manufacture that access with privileged chown.
        for item, label in zip(paths, ('prepared root', 'source workspace', 'output workspace')):
            check_peer_tree_access(item, _peer, writable=label == 'output workspace',
                                   label=label)
        if any(a == b or a.is_relative_to(b) or b.is_relative_to(a) for i, a in enumerate(paths) for b in paths[i+1:]):
            raise SystemdBackendError('build root/source/output paths must not overlap')
        if not isinstance(input_manifest_id, str) or not input_manifest_id:
            raise SystemdBackendError('verified input manifest identity is required')
        intent = dict(prepared_root=str(paths[0]), source_directory=str(paths[1]), output_directory=str(paths[2]),
                      input_manifest_id=input_manifest_id)
        path = self.resource_path(root, resource_id)
        manifest = path / 'registration.json'
        ensure_directory(self.directory)
        os.chmod(self.directory, 0o755)
        ensure_directory(path)
        if manifest.exists():
            previous = json.loads(manifest.read_text())
            assert_bound_registration(previous, _peer)
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
        record = {'schema': INHERITED_BUILD_SCHEMA, 'resource_id': resource_id,
                  'execution_identity': {'uid': uid, 'gid': gid},
                  'intent': intent, 'state': 'importing'}
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
        for name in ('image-build/source', 'image-build/output', 'tmp', 'run', 'run/zog-journal', 'proc', 'sys', 'dev'):
            dest = imported / name
            if dest.is_symlink(): raise SystemdBackendError('reserved build mount target is a symlink')
            dest.mkdir(parents=True, exist_ok=True)
        progress('sync-root')
        self._tree(imported, 0, 0, immutable=True)
        for phase, workspace in zip(('sync-source', 'sync-output'), paths[1:]):
            progress(phase)
            # Source/output are application-owned and were checked under the
            # exact authenticated peer. Do not chown/chmod another application
            # tree just to make a privileged controller accept it.
            for current, _dirs, files in os.walk(workspace, followlinks=False):
                for name in files:
                    item = Path(current) / name
                    if item.is_file() and not item.is_symlink():
                        with item.open('rb') as stream:
                            os.fsync(stream.fileno())
                synchronize_directory(Path(current))
        record['state'] = 'ready'
        progress('ready')
        return record

    def prepare(self, *, project_root, job_id, request, _peer):
        request = canonical_request(request)
        authenticated_build_peer(_peer)
        identity(job_id)
        path, registration = self.load(project_root, request['build_root_id'])
        uid, gid = assert_bound_registration(registration, _peer)
        binding = registration['intent']
        source, output = Path(binding['source_directory']), Path(binding['output_directory'])
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
        slice_name = f'zog-{Path(project_root).name}-build{job_id}.slice'
        result = dict(schema=INHERITED_BUILD_SCHEMA, request=request,
                      execution_identity={'uid':uid, 'gid':gid},
                      job_id=job_id, unit_name=unit, slice_name=slice_name,
                      resolved_executable=resolved, process_cleanup_complete=False)
        jobs = path / 'jobs'
        ensure_directory(jobs)
        job_path = jobs / (job_id+'.json')
        if job_path.exists():
            prior = json.loads(job_path.read_text())
            assert_bound_job(prior, _peer)
            if prior['request'] != request: raise SystemdBackendError('job identity already bound')
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

    def start(self, *, project_root, job_id, request, _peer):
        uid, gid = authenticated_build_peer(_peer)
        info = self.prepare(project_root=project_root, job_id=job_id,
                            request=request, _peer=_peer)
        assert_bound_job(info, _peer)
        path, registration = self.load(project_root, request['build_root_id'])
        assert_bound_registration(registration, _peer)
        job_path = path/'jobs'/(job_id+'.json')
        if info.get('start_attempted'):
            raise SystemdBackendError('build start already attempted; inspect existing job')
        systemd_version = self.systemd.version()
        if systemd_version < 250: raise SystemdBackendError('systemd 250 or later required')
        command = [info['resolved_executable'], *info['request']['command'][1:]]
        if systemd_version < 254:
            # Validate the wire form before the journal barrier registration
            # or an attempted-start record. Never mutate the canonical argv.
            # The stored encoding mode makes the later ExecStart readback
            # comparable to this exact attempt, even across upgrades.
            legacy_command = legacy_systemd_argv(command)
            info['exec_argv_encoding'] = LEGACY_SYSTEMD_ARGV_ENCODING
        else:
            legacy_command = None
        null_device = self.private_null(path) if info['request'].get('device_profile') == 'private-null-permission-test' else None
        if self.journal_barrier:
            if request['termination_grace_seconds'] < 3:
                raise SystemdBackendError('journal barrier requires at least 3 seconds termination grace')
            # Registration is durable before systemd can run the exit hook.
            # Retry before start reuses its identity; attempted jobs never restart.
            if not info.get('journal_barrier_token'):
                info['journal_barrier_token'] = self.journal_barrier.register(
                    info['unit_name'], uid, job_id)
                replace_json(job_path, info)
        elif info.get('journal_barrier_token'):
            raise SystemdBackendError('prepared journal barrier requires enabled broker')
        info['start_attempted'] = True
        replace_json(job_path, info)
        self.systemd.start_slice(project_root=project_root, slice_name=info['slice_name'], description='Zog build job')
        r = info['request']; bind = registration['intent']
        # Fixed security policy; callers cannot weaken these properties.
        values = {
            'Description': ('s', 'Zog finite build job'), 'Slice': ('s', info['slice_name']),
            'Type': ('s', 'exec'), 'ExitType': ('s', 'cgroup'), 'Restart': ('s', 'no'),
            'KillMode': ('s', 'control-group'), 'RemainAfterExit': ('b', False), 'AddRef': ('b', True),
            'RootDirectory': ('s', str(path/'root')), 'WorkingDirectory': ('s', r['working_directory']),
            'User': ('s', str(uid)), 'Group': ('s', str(gid)),
            'ProtectSystem': ('s', 'strict'), 'PrivateNetwork': ('b', True), 'PrivateDevices': ('b', True),
            'PrivateTmp': ('b', True), 'MountAPIVFS': ('b', True), 'NoNewPrivileges': ('b', True),
            'CapabilityBoundingSet': ('t', 0), 'AmbientCapabilities': ('t', 0),
            'StandardOutput': ('s', 'journal'), 'StandardError': ('s', 'journal'),
            'TimeoutStartUSec': ('t', int(r['startup_timeout_seconds']*1000000)),
            'RuntimeMaxUSec': ('t', int(r['execution_timeout_seconds']*1000000)),
            'TimeoutStopUSec': ('t', int(r['termination_grace_seconds']*1000000)),
            'SendSIGKILL': ('b', True), 'TasksMax': ('t', r['resource_limits']['thread-count-maximum']),
            'MemoryMax': ('t', r['resource_limits']['memory-maximum-bytes'])}
        if 'cpu-weight' in r['resource_limits']:
            values['CPUWeight'] = ('t', r['resource_limits']['cpu-weight'])
        if 'stack-maximum-bytes' in r['resource_limits']:
            stack = r['resource_limits']['stack-maximum-bytes']
            values['LimitSTACK'] = ('t', stack)
            values['LimitSTACKSoft'] = ('t', stack)
        props = [self.systemd._property(k, sig, value) for k,(sig,value) in values.items()]
        environment = [f'{k}={v}' for k,v in sorted(r['environment'].items())]
        binds = [bind['source_directory'],'/image-build/source','false',0,bind['output_directory'],'/image-build/output','false',0]
        if null_device is not None: binds += [str(null_device),'/dev/null','false',0]
        props.append(self.systemd._property('Environment', 'as', len(environment), *environment))
        if systemd_version < 254:
            # systemd 252 does not recognize ExecStartEx; legacy a(sasb)
            # passes executable, argv and one ignore-failure boolean.
            props.append(self.systemd._property('ExecStart', 'a(sasb)',
                1, command[0], len(legacy_command), *legacy_command, 'false'))
        else:
            props.append(['ExecStartEx', Variant('a(sasas)', [[
                command[0], command, ['no-env-expand']]])])
        props.append(self.systemd._property('BindPaths','a(ssbt)',len(binds)//4,*binds))
        if self.journal_barrier:
            # All injected paths are under the controller-created /run directory.
            target = path/'root/run/zog-journal'
            if target.is_symlink(): raise SystemdBackendError('unsafe barrier mount target')
            target.mkdir(exist_ok=True)
            props.append(self.systemd._property('BindReadOnlyPaths','a(ssbt)',2,
                str(self.journal_barrier.socket_path.parent),'/run/zog-journal','false',0,
                str(self.journal_barrier.helper),'/run/zog-journal/wait','false',0))
            hook = ['/run/zog-journal/wait', info['journal_barrier_token']]
            if systemd_version < 254:
                # Legacy boolean keeps ignore-failure; fixed path and
                # hex token cannot trigger legacy environment expansion.
                props.append(self.systemd._property('ExecStopPost', 'a(sasb)',
                    1, hook[0], len(hook), *hook, 'true'))
            else:
                props.append(['ExecStopPostEx', Variant('a(sasas)', [[
                    hook[0], hook, ['no-env-expand', 'ignore-failure']]])])
        self.systemd._job('StartTransientUnit','ssa(sv)a(sa(sv))',[info['unit_name'],'fail',props,[]])
        return info

    @staticmethod
    def expected_properties(path, info):
        r = info['request']
        command = [info['resolved_executable'], *r['command'][1:]]
        mode = info.get('exec_argv_encoding')
        if mode == LEGACY_SYSTEMD_ARGV_ENCODING:
            command = legacy_systemd_argv(command)
        elif mode is not None:
            raise SystemdBackendError('unsupported saved build argv encoding')
        identity_record = info.get('execution_identity')
        if info.get('schema') == INHERITED_BUILD_SCHEMA:
            if (type(identity_record) is not dict
                    or set(identity_record) != {'uid', 'gid'}
                    or any(type(identity_record[k]) is not int or identity_record[k] <= 0
                           for k in ('uid', 'gid'))):
                raise SystemdBackendError('saved build execution identity invalid')
        elif identity_record is not None:
            raise SystemdBackendError('historical job contains untrusted identity selection')
        result = {'RootDirectory':str(path/'root'), 'ExitType':'cgroup','Type':'exec',
                'Restart':'no','ProtectSystem':'strict','KillMode':'control-group',
                'WorkingDirectory':r['working_directory'],
                'ExecStart':command,
                'PrivateNetwork':True,'NoNewPrivileges':True,'CapabilityBoundingSet':0,
                'RuntimeMaxUSec':int(r['execution_timeout_seconds']*1000000)}
        if identity_record is not None:
            result.update(User=str(identity_record['uid']), Group=str(identity_record['gid']))
        return result

    def observe(self, *, project_root, job_id, build_root_id):
        path, _ = self.load(project_root, build_root_id)
        job_path = path/'jobs'/(identity(job_id)+'.json')
        if not job_path.exists(): return {'exists':False}
        info = json.loads(job_path.read_text())
        expected = self.expected_properties(path,info)
        try:
            raw = self.systemd.observe(project_root=project_root, unit_name=info['unit_name'])
            if raw['exists']:
                obj = self.systemd._get_unit_path(info['unit_name'])
                properties = dict(raw['properties'])
                for name in ('PrivateNetwork','NoNewPrivileges','CapabilityBoundingSet','RuntimeMaxUSec'):
                    properties[name]=self.systemd._get_property(obj,'org.freedesktop.systemd1.Service',name)
                for name,value in expected.items():
                    if properties.get(name) != value: raise SystemdBackendError(f'build property mismatch: {name}')
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
                                            uid=(info.get('execution_identity') or {}).get('uid', 0))
                if evidence is not None:
                    properties=dict(evidence['properties'])
                    properties['ExecStart']=self.systemd._normalize_exec_start(properties.get('ExecStart'))
                    for name,value in expected.items():
                        if properties.get(name) != value: raise SystemdBackendError(f'exit evidence property mismatch: {name}')
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
        for unit in (info['unit_name'], info['slice_name']):
            raw = self.systemd.observe(project_root=project_root, unit_name=unit)
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
