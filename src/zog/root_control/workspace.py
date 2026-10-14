"""Privileged workspace resources. Contract v1 deliberately shares host networking."""
import json
import hashlib
import os
from pathlib import Path
import pwd
import grp
import secrets
import socket
import stat
import struct

from zog.box_control.boot import current_boot_id
from zog.box_control.durability import ensure_directory, replace_json, synchronize_directory
from zog.box_control.errors import PersistenceError
from zog.box_control.project import Project
from zog.box_control.workspaces import Workspaces, WorkspaceError
from zog.box_control.runtime.reference import RuntimeReferenceStore


RUNTIME_DIRECTORY = Path('/run/zog/workspace')


def host_namespace_stat():
    return Path('/proc/1/ns/net').stat()


def peer_cgroups(pid):
    return Path(f'/proc/{pid}/cgroup').read_text().splitlines()


def peer_namespace_stat(pid):
    return Path(f'/proc/{pid}/ns/net').stat()


class WorkspaceBackend:
    def __init__(self, systemd):
        self.systemd = systemd

    def location(self, project_root, binding):
        project = Project(Path(project_root))
        record = Workspaces(project).load(binding['workspace_id'])
        if record['state'] != 'registered' or any(record[key] != binding[key] for key in ('number', 'revision', 'incarnation', 'network')):
            raise WorkspaceError('workspace-binding-stale', 'workspace binding is stale')
        if binding['network'] != 'host-shared':
            raise WorkspaceError('unsupported-network', 'only host-shared is implemented')
        epoch = binding['incarnation']
        if not isinstance(epoch, str) or len(epoch) != 32 or any(c not in '0123456789abcdef' for c in epoch):
            raise WorkspaceError('invalid-incarnation', 'invalid desktop resource incarnation')
        base = project.state_dir / 'workspace-resources' / record['workspace_id'] / epoch
        if base.resolve() != base.absolute():
            raise WorkspaceError('workspace-path-redirected', 'workspace resources must not be redirected')
        return project, base

    def prepare(self, *, project_root, binding, user, group=None):
        project, base = self.location(project_root, binding)
        if binding['role'] != 'desktop' or binding['boot_id'] != current_boot_id():
            raise WorkspaceError('workspace-binding-stale', 'desktop preparation must belong to this boot')
        account = pwd.getpwuid(int(user)) if str(user).isdecimal() else pwd.getpwnam(user)
        gid = account.pw_gid if group is None else (int(group) if str(group).isdecimal() else grp.getgrnam(group).gr_gid)
        if account.pw_uid == 0 or gid == 0:
            raise WorkspaceError('privileged-desktop', 'workspace desktop must run unprivileged')
        # Epoch is never reused for a subsequent desktop. Existing files are not repaired.
        ensure_directory(base, exist_ok=False)
        runtime_base = RUNTIME_DIRECTORY / hashlib.sha256(str(project.path).encode()).hexdigest()[:12] / binding['incarnation'][:16]
        if runtime_base.resolve() != runtime_base.absolute():
            raise WorkspaceError('workspace-path-redirected', 'runtime resources must not be redirected')
        ensure_directory(runtime_base, exist_ok=False)
        for child in ('run', 'x11'):
            path = runtime_base / child
            path.mkdir(mode=0o700)
            os.chown(path, account.pw_uid, gid)
            synchronize_directory(path)
        cookie = secrets.token_bytes(16)
        def field(value):
            return struct.pack('>H', len(value)) + value
        auth = struct.pack('>H', 65535) + field(b'') + field(str(binding['number']).encode()) + field(b'MIT-MAGIC-COOKIE-1') + field(cookie)
        path = runtime_base / 'run' / 'Xauthority'
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, 'wb') as stream:
                stream.write(auth)
                stream.flush()
                os.fchown(stream.fileno(), account.pw_uid, gid)
                os.fsync(stream.fileno())
            synchronize_directory(path.parent)
        except OSError as exc:
            raise PersistenceError(f'cannot persist workspace authorization: {exc}') from exc
        namespace = host_namespace_stat()
        result = dict(display=':' + str(binding['number']), namespace_path='/proc/1/ns/net',
                      namespace_device=namespace.st_dev, namespace_inode=namespace.st_ino,
                      x11_directory=str(runtime_base / 'x11'), access_directory=str(runtime_base / 'run'),
                      vnc_endpoint=dict(kind='unix', path=str(runtime_base / 'run' / 'vnc.sock'), browser_direct=False))
        replace_json(base / 'mechanism.json', dict(binding=binding, resolved=result,
                     uid=account.pw_uid, gid=gid, authority_hex=auth.hex(), cookie_hex=cookie.hex()))
        return result

    def verify(self, *, project_root, binding):
        project, base = self.location(project_root, binding)
        raw = json.loads((base / 'mechanism.json').read_text())
        namespace = host_namespace_stat()
        if binding['boot_id'] != current_boot_id() or any(binding.get(key) != value for key, value in raw['resolved'].items()):
            raise WorkspaceError('workspace-binding-stale', 'recorded workspace incarnation is unavailable; no substitution')
        if (namespace.st_dev, namespace.st_ino) != (binding['namespace_device'], binding['namespace_inode']):
            raise WorkspaceError('namespace-changed', 'host network namespace identity changed')
        runtime_base = Path(raw['resolved']['access_directory']).parent
        for directory in (runtime_base, runtime_base / 'run', runtime_base / 'x11'):
            if directory.resolve() != directory.absolute() or not directory.is_dir():
                raise WorkspaceError('workspace-path-redirected', 'workspace resources are missing or redirected')
        authority = runtime_base / 'run' / 'Xauthority'
        if authority.is_symlink() or authority.read_bytes().hex() != raw['authority_hex']:
            raise WorkspaceError('authorization-changed', 'workspace authorization material changed')
        if binding['role'] == 'desktop':
            return dict(ready=True, namespace_inode=namespace.st_ino)
        reference = RuntimeReferenceStore(project.runtime_reference_file).load().get(binding['desktop_runtime_id'])
        if reference is None or (reference.workspace_binding or {}).get('incarnation') != binding['incarnation']:
            raise WorkspaceError('desktop-not-ready', 'desktop runtime evidence is missing')
        groups = []
        for program in reference.programs:
            observed = self.systemd.observe(project_root=project.path, unit_name=program.unit_name)
            if not observed.get('exists') or observed.get('active_state') not in ('active', 'activating') or observed.get('invocation_id') != program.invocation_id:
                raise WorkspaceError('desktop-not-ready', 'desktop invocation changed or stopped')
            groups.append(observed.get('control_group'))
        def connect(path):
            if path.is_symlink() or not stat.S_ISSOCK(path.stat().st_mode):
                raise WorkspaceError('desktop-not-ready', 'desktop endpoint is missing or redirected')
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.settimeout(2)
            try:
                client.connect(str(path))
                pid, uid, gid = struct.unpack('3i', client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                cgroup = peer_cgroups(pid)
                if uid != raw['uid'] or not any(line.startswith('0::') and any(g and (line[3:] == g or line[3:].startswith(g + '/')) for g in groups) for line in cgroup):
                    raise WorkspaceError('desktop-endpoint-owner', 'endpoint is not owned by the recorded desktop cgroup')
                net = peer_namespace_stat(pid)
                if (net.st_dev, net.st_ino) != (namespace.st_dev, namespace.st_ino):
                    raise WorkspaceError('desktop-network-changed', 'desktop endpoint uses a different namespace')
                return client
            except BaseException:
                client.close()
                raise
        try:
            with connect(runtime_base / 'x11' / ('X' + str(binding['number']))) as client:
                name = b'MIT-MAGIC-COOKIE-1'
                cookie = bytes.fromhex(raw['cookie_hex'])
                client.sendall(struct.pack('<BBHHHHH', ord('l'), 0, 11, 0, len(name), len(cookie), 0) + name + b'\0' * (-len(name) % 4) + cookie)
                if client.recv(8)[:1] != b'\x01':
                    raise WorkspaceError('x11-authorization-failed', 'desktop rejected controller X11 authorization')
            with connect(runtime_base / 'run' / 'vnc.sock') as client:
                banner = b''
                while len(banner) < 12:
                    part = client.recv(12 - len(banner))
                    if not part:
                        break
                    banner += part
                if not banner.startswith(b'RFB ') or len(banner) != 12:
                    raise WorkspaceError('vnc-not-ready', 'desktop has no valid RFB endpoint')
        except (OSError, ValueError) as exc:
            raise WorkspaceError('desktop-not-ready', str(exc)) from exc
        return dict(ready=True, vnc_endpoint=binding['vnc_endpoint'], namespace_inode=namespace.st_ino)
