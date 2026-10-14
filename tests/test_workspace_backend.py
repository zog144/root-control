"""Linux socket fixtures. systemd observations are simulated, not host acceptance."""
import json
import os
from pathlib import Path
import socket
from threading import Thread
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from uuid import uuid4
import pytest

from zog.box_control.boot import current_boot_id
from zog.box_control.project import Project
from zog.box_control.workspaces import Workspaces, WorkspaceError, VERSION
from zog.box_control.runtime.reference import RuntimeReferenceStore, ApplicationRuntimeReference, ProgramRuntimeReference
from zog.box_control.model import ApplicationRuntimeState
from zog.root_control.workspace import WorkspaceBackend


def test_owned_unix_endpoints_x11_cookie_and_namespace_identity(tmp_path, monkeypatch):
    try:
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        probe.close()
    except PermissionError:
        pytest.skip('execution environment prohibits Unix sockets; requires Linux socket acceptance host')
    import zog.root_control.workspace as module
    import pwd
    project = Project(tmp_path / 'project')
    workspace = str(uuid4())
    raw = Workspaces(project).register(workspace, 1)
    binding = dict(schema=VERSION, workspace_id=workspace, number=1, network='host-shared',
                   revision=1, incarnation=raw['incarnation'], role='desktop', desktop_runtime_id='ABC123', boot_id=current_boot_id())
    group = next(line[3:] for line in Path('/proc/self/cgroup').read_text().splitlines() if line.startswith('0::'))
    systemd = SimpleNamespace(observe=lambda **kw: dict(exists=True, active_state='active', invocation_id='known-invocation', control_group=group))
    backend = WorkspaceBackend(systemd)
    monkeypatch.setattr(module, "host_namespace_stat", lambda: Path("/proc/self/ns/net").stat())
    monkeypatch.setattr(pwd, 'getpwnam', lambda _: SimpleNamespace(pw_uid=65534, pw_gid=65534))
    monkeypatch.setattr(os, 'chown', lambda *args: None)
    monkeypatch.setattr(os, 'fchown', lambda *args: None)
    with TemporaryDirectory(prefix='zog-ws-') as directory:
        monkeypatch.setattr(module, 'RUNTIME_DIRECTORY', Path(directory))
        binding.update(backend.prepare(project_root=project.path, binding=binding, user='regular'))
        _, base = backend.location(project.path, binding)
        mechanism = json.loads((base / 'mechanism.json').read_text())
        # Fixture sockets run as the test runner, with fake systemd ownership.
        mechanism['uid'] = os.getuid()
        (base / 'mechanism.json').write_text(json.dumps(mechanism))
        ref = ApplicationRuntimeReference('ABC123', 'desktop', 'desktop-1', 'generation', ApplicationRuntimeState.RUNNING,
              programs=(ProgramRuntimeReference('main', 'zog-project-ABC123-main.service', invocation_id='known-invocation'),),
              workspace_binding=binding)
        RuntimeReferenceStore(project.runtime_reference_file).save({ref.runtime_id:ref})
        client_binding = dict(binding, role='client')
        errors = []
        def serve(path, x11):
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server.bind(str(path)); server.listen(); server.settimeout(3)
            def run():
                try:
                    connection, _ = server.accept()
                    with connection:
                        connection.settimeout(3)
                        if x11:
                            payload = b''
                            while len(payload) < 48:
                                payload += connection.recv(48 - len(payload))
                            assert payload.endswith(bytes.fromhex(mechanism['cookie_hex']))
                            connection.sendall(b'\x01\x00\x0b\x00\x00\x00\x00\x00')
                        else:
                            connection.sendall(b'RFB 003.008\n')
                except BaseException as exc:
                    errors.append(exc)
                finally:
                    server.close()
            thread = Thread(target=run); thread.start()
            return thread
        threads = [serve(Path(binding['x11_directory']) / 'X1', True), serve(Path(binding['access_directory']) / 'vnc.sock', False)]
        assert backend.verify(project_root=project.path, binding=client_binding)['ready']
        for thread in threads: thread.join(4)
        assert not errors
        with pytest.raises(WorkspaceError, match='incarnation'):
            backend.verify(project_root=project.path, binding=dict(client_binding, namespace_inode=0))
        (Path(binding['access_directory']) / 'Xauthority').write_text('tampered')
        with pytest.raises(WorkspaceError, match='authorization'):
            backend.verify(project_root=project.path, binding=client_binding)


@pytest.mark.parametrize('accepted', [True, False])
def test_x11_protocol_fixture_requires_cookie_acceptance(tmp_path, monkeypatch, accepted):
    import zog.root_control.workspace as module
    project = Project(tmp_path / 'project'); workspace = str(uuid4())
    record = Workspaces(project).register(workspace, 1)
    base = project.state_dir / 'workspace-resources' / workspace / record['incarnation']
    (base / 'run').mkdir(parents=True); (base / 'x11').mkdir()
    (base / 'run' / 'Xauthority').write_bytes(b'authority')
    (base / 'run' / 'vnc.sock').touch(); (base / 'x11' / 'X1').touch()
    current_group = next(line[3:] for line in Path('/proc/self/cgroup').read_text().splitlines() if line.startswith('0::'))
    namespace = Path('/proc/self/ns/net').stat()
    monkeypatch.setattr(module, 'host_namespace_stat', lambda: namespace)
    monkeypatch.setattr(module, 'peer_cgroups', lambda pid: ['0::' + current_group])
    monkeypatch.setattr(module, 'peer_namespace_stat', lambda pid: namespace)
    resolved = dict(display=':1', namespace_path='/proc/1/ns/net', namespace_device=namespace.st_dev, namespace_inode=namespace.st_ino,
                    access_directory=str(base / 'run'), x11_directory=str(base / 'x11'), vnc_endpoint={'kind':'unix','path':str(base / 'run' / 'vnc.sock')})
    binding = dict(schema=VERSION, workspace_id=workspace, number=1, network='host-shared', revision=1,
                   incarnation=record['incarnation'], boot_id=current_boot_id(), role='client', desktop_runtime_id='ABC123', **resolved)
    (base / 'mechanism.json').write_text(json.dumps(dict(resolved=resolved, uid=os.getuid(), authority_hex=b'authority'.hex(), cookie_hex=('ab'*16))))
    ref = ApplicationRuntimeReference('ABC123','desktop','desktop','gen',ApplicationRuntimeState.RUNNING,
          programs=(ProgramRuntimeReference('main','zog-project-ABC123-main.service',invocation_id='known'),),workspace_binding=binding)
    RuntimeReferenceStore(project.runtime_reference_file).save({ref.runtime_id:ref})
    systemd = SimpleNamespace(observe=lambda **kw: dict(exists=True,active_state='active',invocation_id='known',control_group=current_group))
    sent = []
    class ProtocolSocket:
        def settimeout(self, value): pass
        def connect(self, path): self.path = path
        def getsockopt(self, *args):
            import struct
            return struct.pack('3i',os.getpid(),os.getuid(),os.getgid())
        def sendall(self, payload): sent.append(payload)
        def recv(self, length): return (b'\x01' if accepted else b'\x00') + b'\0'*7 if self.path.endswith('X1') else b'RFB 003.008\n'
        def close(self): pass
        def __enter__(self): return self
        def __exit__(self,*args): self.close()
    monkeypatch.setattr(socket,'socket',lambda *args:ProtocolSocket())
    monkeypatch.setattr(module.stat,'S_ISSOCK',lambda mode:True)
    backend = WorkspaceBackend(systemd)
    if accepted:
        assert backend.verify(project_root=project.path,binding=binding)['ready']
    else:
        with pytest.raises(WorkspaceError,match='rejected'):
            backend.verify(project_root=project.path,binding=binding)
    assert sent[0].endswith(bytes.fromhex('ab'*16))
    assert b'MIT-MAGIC-COOKIE-1' in sent[0]
