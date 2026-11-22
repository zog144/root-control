"""Kernel-peer authentication, exact identity including root, and child evidence."""
import json
import os
import socket
from pathlib import Path

import pytest

from zog.root_control.build import (
    INHERITED_BUILD_SCHEMA, assert_bound_job, authenticated_build_peer,
    check_peer_access, kernel_build_child_identity,
)
from zog.root_control.daemon import RootControlDaemon
from zog.root_control.systemd import SystemdBackendError
from .test_build_backend import registered


class BuildStub:
    def __init__(self):
        self.calls = []

    def register(self, **kwargs):
        self.calls.append(('register', kwargs))
        return kwargs


def test_unix_socket_peer_credentials_are_kernel_observed(tmp_path):
    client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    with client, server:
        selected = RootControlDaemon._kernel_peer(server)
    assert selected == (os.geteuid(), os.getegid())


def test_missing_and_malformed_peer_never_invokes_build_backend(tmp_path):
    daemon = RootControlDaemon(tmp_path/'unused.sock')
    stub = BuildStub()
    daemon.build = stub
    for peer in (None, (0, 1001), (1001, 0), (-1, 0), (0, -1),
                 (True, 0), (0, False), ('0', '0')):
        with pytest.raises(SystemdBackendError, match='authenticated socket peer'):
            daemon.handle({'operation': 'build_register'}, peer=peer)
    assert stub.calls == []


def test_authenticated_root_peer_is_forwarded_unchanged_and_cannot_override_it(tmp_path):
    daemon = RootControlDaemon(tmp_path/'unused.sock')
    stub = BuildStub()
    daemon.build = stub
    request = {'operation': 'build_register', 'project_root': '/project', 'resource_id':'a'*32}
    assert authenticated_build_peer((0, 0)) == (0, 0)
    assert daemon.handle(request, peer=(0, 0))['result']['_peer'] == (0, 0)
    for field in ('_peer', 'peer', 'peer_identity', 'execution_user_id',
                  'execution_group_id', 'User', 'Group'):
        with pytest.raises(ValueError, match='caller-selected'):
            daemon.handle(dict(request, **{field: (1001,1001)}), peer=(0, 0))
    assert len(stub.calls) == 1


def test_build_identity_is_injected_server_side_not_selected_by_json(tmp_path):
    daemon = RootControlDaemon(tmp_path/'unused.sock')
    stub = BuildStub()
    daemon.build = stub
    args = {'operation':'build_register', 'project_root':'/project',
            'resource_id':'a'*32}
    peer = (1002, 1003)
    result = daemon.handle(args, peer=peer)['result']
    assert result['_peer'] == peer
    assert stub.calls[0][1]['_peer'] == peer
    for key in ('_peer', 'peer', 'peer_identity', 'execution_user_id',
                'execution_group_id', 'User', 'Group'):
        with pytest.raises(ValueError, match='caller-selected'):
            daemon.handle(dict(args, **{key: (123, 456)}), peer=peer)
    assert len(stub.calls) == 1


def test_historical_registration_remains_readable_but_not_replayable(registered):
    from zog.box_control.durability import replace_json
    backend, args, request = registered
    project = args['project_root']
    resource = args['resource_id']
    path = backend.resource_path(project, resource)
    manifest = path/'registration.json'
    old = json.loads(manifest.read_text())
    old['schema'] = 1
    old.pop('execution_identity', None)
    old['execution_user_id'] = 24202
    replace_json(manifest, old)
    assert backend.registration_status(project_root=project, resource_id=resource) == old
    with pytest.raises(SystemdBackendError, match='historical or differently bound'):
        backend.prepare(project_root=project, job_id='c'*32, request=request)
    with pytest.raises(SystemdBackendError, match='historical or differently bound'):
        backend.start(project_root=project, job_id='c'*32, request=request)
    assert not (path/'jobs'/('c'*32+'.json')).exists()


def test_existing_job_cannot_be_replayed_by_different_peer_or_old_schema(registered):
    backend, args, request = registered
    project = args['project_root']
    rid = args['resource_id']
    info = backend.prepare(project_root=project, job_id='c'*32, request=request)
    assert info['schema'] == INHERITED_BUILD_SCHEMA
    with pytest.raises(SystemdBackendError, match='historical or differently bound'):
        assert_bound_job(info, (backend.test_peer[0] + 1, backend.test_peer[1]))
    job = backend.resource_path(project, rid)/'jobs'/('c'*32+'.json')
    previous = json.loads(job.read_text())
    previous['schema'] = 1
    previous['execution_user_id'] = 24202
    from zog.box_control.durability import replace_json
    replace_json(job, previous)
    with pytest.raises(SystemdBackendError, match='historical or differently bound'):
        backend.start(project_root=project, job_id='c'*32, request=request)
    assert backend.systemd.properties is None
    assert 'start_attempted' not in json.loads(job.read_text())


def test_project_missing_and_inaccessible_are_distinct(tmp_path):
    peer = (os.geteuid() or 1001, os.getegid() or 1001)
    not_found = tmp_path/'missing'
    with pytest.raises(SystemdBackendError, match='ENOENT'):
        check_peer_access(not_found, peer, 5, label='Project')
    inaccessible = tmp_path/'blocked'
    inaccessible.mkdir()
    inaccessible.chmod(0o000)
    try:
        with pytest.raises(SystemdBackendError, match='EACCES'):
            check_peer_access(inaccessible, peer, 5, label='Project')
    finally:
        inaccessible.chmod(0o700)


def test_running_kernel_child_identity_matches_authenticated_peer():
    uid, gid = os.geteuid(), os.getegid()
    if (uid == 0) != (gid == 0):
        pytest.skip('mixed zero identity is not an authorized compiler peer')
    group_entries = [v for v in Path('/proc/self/cgroup').read_text().splitlines()
                     if v.startswith('0::')]
    if len(group_entries) != 1:
        pytest.skip('test requires cgroup v2; native Host acceptance verifies v2')
    group = group_entries[0][3:]
    identity = kernel_build_child_identity(
        os.getpid(), group, {'uid':uid, 'gid':gid})
    assert identity['euid'] == uid and identity['egid'] == gid
    with pytest.raises(SystemdBackendError, match='EUID/EGID'):
        kernel_build_child_identity(os.getpid(), group, {'uid':uid + 1, 'gid':gid})
    with pytest.raises(SystemdBackendError, match='outside selected'):
        kernel_build_child_identity(os.getpid(), '/not-this-cgroup', {'uid':uid, 'gid':gid})


def test_active_controller_observation_reads_actual_kernel_nonroot_child(registered, monkeypatch):
    backend, args, request = registered
    uid,gid = os.geteuid(),os.getegid()
    if uid == 0 or gid == 0:
        pytest.skip('needs a real nonroot process; native Work verifies systemd child')
    group = [line[3:] for line in Path('/proc/self/cgroup').read_text().splitlines()
             if line.startswith('0::')]
    if len(group) != 1:
        pytest.skip('native cgroup v2 Host acceptance is separate')
    info = backend.start(project_root=args['project_root'], job_id='c'*32, request=request)
    path = backend.resource_path(args['project_root'], args['resource_id'])
    props = backend.expected_properties(path, info)
    assert props['User'] == str(uid) and props['Group'] == str(gid)
    monkeypatch.setattr(backend.systemd, 'observe', lambda **kw: {
        'exists':True, 'transient':True, 'unit_name':info['unit_name'],
        'active_state':'active', 'control_group':group[0],
        'properties':dict(props), 'result':'success', 'invocation_id':'a'*32})
    monkeypatch.setattr(backend.systemd, '_get_unit_path', lambda name:'/fake/systemd/unit')
    readings = dict(PrivateNetwork=True, NoNewPrivileges=True, CapabilityBoundingSet=0,
                    RuntimeMaxUSec=8_000_000, ExecMainCode=0, ExecMainStatus=0,
                    ExecMainExitTimestampMonotonic=0, MainPID=os.getpid())
    monkeypatch.setattr(backend.systemd, '_get_property',
                        lambda _unit,_iface,property:readings[property])
    # Unlike a mock UID string, /proc/self/status is read from the actual
    # nonroot Linux test process through the production controller method.
    result = backend.observe(project_root=args['project_root'], job_id='c'*32,
                             build_root_id=args['resource_id'])
    assert result['child_identity'] == {
        'pid':os.getpid(), 'euid':uid, 'egid':gid,
        'verified_cgroup':group[0]}
    readings['MainPID'] = 1
    with pytest.raises(SystemdBackendError, match='PID/cgroup unavailable'):
        backend.observe(project_root=args['project_root'], job_id='c'*32,
                        build_root_id=args['resource_id'])


def test_terminal_observation_rejects_wrong_systemd_user_group(registered, monkeypatch):
    backend, args, request = registered
    info = backend.start(project_root=args['project_root'], job_id='c'*32, request=request)
    path = backend.resource_path(args['project_root'], args['resource_id'])
    props = backend.expected_properties(path, info)
    assert props['User'] == str(backend.test_peer[0])
    assert props['Group'] == str(backend.test_peer[1])
    properties = dict(props, User='0')
    monkeypatch.setattr(backend.systemd, 'observe', lambda **kwargs: {
        'exists':True, 'unit_name':info['unit_name'], 'transient':True,
        'active_state':'inactive', 'control_group':None,
        'properties':properties, 'result':'success', 'invocation_id':'a'*32})
    monkeypatch.setattr(backend.systemd, '_get_unit_path', lambda name:'/fake/unit')
    readings = dict(PrivateNetwork=True, NoNewPrivileges=True, CapabilityBoundingSet=0,
                    RuntimeMaxUSec=8_000_000, ExecMainCode=1, ExecMainStatus=0,
                    ExecMainExitTimestampMonotonic=10)
    monkeypatch.setattr(backend.systemd, '_get_property',
                        lambda _unit,_iface,key:readings[key])
    with pytest.raises(SystemdBackendError, match='build property mismatch: User'):
        backend.observe(project_root=args['project_root'], job_id='c'*32,
                        build_root_id=args['resource_id'])
    properties['User'] = props['User']
    properties['Group'] = '0'
    with pytest.raises(SystemdBackendError, match='build property mismatch: Group'):
        backend.observe(project_root=args['project_root'], job_id='c'*32,
                        build_root_id=args['resource_id'])


@pytest.mark.parametrize('method,kwargs', [
    ('observe', {'job_id':'c'*32}),
    ('cleanup', {'job_id':'c'*32}),
    ('cancel', {'job_id':'c'*32}),
    ('release', {}),
    ('forget', {}),
])
def test_second_nonroot_peer_cannot_operate_existing_resource(registered, method, kwargs):
    backend, args, request = registered
    if method in ('observe','cleanup','cancel'):
        backend.prepare(project_root=args['project_root'], job_id='c'*32, request=request)
    unauthorized = (backend.test_peer[0] + 1, backend.test_peer[1] + 1)
    with pytest.raises(SystemdBackendError, match='historical or differently bound'):
        getattr(backend, method)(project_root=args['project_root'],
                                  build_root_id=args['resource_id'],
                                  _peer=unauthorized, **kwargs)


def _root_resource(registered):
    """Separate disposable schema-2 resource bound to authenticated 0:0."""
    backend, args, original = registered
    project = args['project_root']
    attempt = project/'state/image-build/attempts/root-peer'
    prepared = attempt/'root'
    (prepared/'bin').mkdir(parents=True)
    (prepared/'bin/cc').write_text('test compiled executable')
    (prepared/'bin/cc').chmod(0o755)
    source = attempt/'source'
    output = attempt/'output'
    source.mkdir()
    output.mkdir()
    (source/'input').write_text('input')
    resource = 'e'*32
    registration = dict(project_root=project,resource_id=resource,
                        prepared_root=prepared,source_directory=source,
                        output_directory=output,input_manifest_id='root-source',
                        _peer=(0,0))
    manifest = backend.register(**registration)
    request = dict(original)
    request.update(build_root_id=resource,source_workspace_id=resource+'-source',
                   output_workspace_id=resource+'-output',
                   command=['cc','$IMAGE_BUILD_SOURCE',"awk '{print $1}'"])
    return backend, registration, request, manifest


def _check_root_launch_recovery(backend, registration, request, manifest, monkeypatch):
    assert manifest['execution_identity'] == {'uid':0,'gid':0}
    assert manifest['schema'] == INHERITED_BUILD_SCHEMA
    assert backend.register(**registration) == manifest
    kwargs = dict(project_root=registration['project_root'],job_id='f'*32,
                  request=request,_peer=(0,0))
    prepared = backend.prepare(**kwargs)
    assert prepared['execution_identity'] == {'uid':0,'gid':0}
    started = backend.start(**kwargs)
    assert started['request'] == request
    props = backend.systemd.properties
    assert props['User'].value == '0' and props['Group'].value == '0'
    assert props['RootDirectory'].value == str(backend.resource_path(
        registration['project_root'],registration['resource_id'])/'root')
    assert props['ProtectSystem'].value == 'strict'
    for key in ('PrivateNetwork','PrivateDevices','PrivateTmp','NoNewPrivileges'):
        assert props[key].value is True
    assert props['CapabilityBoundingSet'].value == 0
    assert props['AmbientCapabilities'].value == 0
    assert props['MemoryMax'].value == request['resource_limits']['memory-maximum-bytes']
    assert props['TasksMax'].value == request['resource_limits']['thread-count-maximum']
    assert props['ExecStart'].value == [[
        '/bin/cc',['/bin/cc','$$IMAGE_BUILD_SOURCE',"awk '{print $$1}'"],False]]
    assert 'ExecStartEx' not in props
    location = backend.resource_path(registration['project_root'],
                                     registration['resource_id'])
    saved = json.loads((location/'jobs'/('f'*32+'.json')).read_text())
    assert saved['execution_identity'] == {'uid':0,'gid':0}
    assert saved['start_attempted'] is True
    expected = backend.expected_properties(location, saved)
    assert (expected['User'],expected['Group']) == ('0','0')
    monkeypatch.setattr(backend.systemd,'observe',lambda **kw:dict(
        exists=True,unit_name=started['unit_name'],transient=True,
        active_state='inactive',control_group=None,properties=dict(expected),
        result='success',invocation_id='a'*32))
    monkeypatch.setattr(backend.systemd,'_get_unit_path',lambda unit:'/fake/systemd/unit')
    values=dict(PrivateNetwork=True,NoNewPrivileges=True,
                CapabilityBoundingSet=0,RuntimeMaxUSec=8_000_000,
                ExecMainCode=1,ExecMainStatus=0,
                ExecMainExitTimestampMonotonic=1234)
    monkeypatch.setattr(backend.systemd,'_get_property',
                        lambda _unit,_interface,key:values[key])
    observe=dict(project_root=registration['project_root'],
                 job_id='f'*32,build_root_id=registration['resource_id'])
    terminal=backend.observe(**observe,_peer=(0,0))
    assert terminal['ExecMainStatus'] == 0 and terminal['cgroup_empty'] is True
    assert terminal['invocation_id'] == 'a'*32
    with pytest.raises(SystemdBackendError,match='historical or differently bound'):
        backend.observe(**observe,_peer=(1001,1002))
    with pytest.raises(SystemdBackendError,match='already attempted'):
        backend.start(**kwargs)


def test_root_peer_0_0_registration_and_recovery_with_synthetic_access(
        registered, monkeypatch):
    from zog.root_control import build as build_module
    # Source-only test runner may be non-root. Simulate accessible files;
    # native root-run counterpart below verifies actual Project DAC.
    monkeypatch.setattr(build_module,'check_peer_access',
                        lambda path,peer,required,*,label:Path(path))
    monkeypatch.setattr(build_module,'check_peer_tree_access',
                        lambda path,peer,*,writable,label:None)
    _check_root_launch_recovery(*_root_resource(registered), monkeypatch)


def test_root_compiler_registration_with_real_root_process(tmp_path,monkeypatch):
    # Run under the existing root CI lane; no nonroot fixture or new accounts.
    if (os.geteuid(),os.getegid()) != (0,0):
        pytest.skip('requires actual 0:0 root test process')
    from .test_build_backend import Systemd
    from zog.root_control.build import BuildBackend
    project=tmp_path/'project'
    attempt=project/'state/image-build/attempts/root-peer'
    prepared=attempt/'root'
    (prepared/'bin').mkdir(parents=True)
    (prepared/'bin/cc').write_text('test executable')
    (prepared/'bin/cc').chmod(0o755)
    source=attempt/'source'
    output=attempt/'output'
    source.mkdir(); output.mkdir()
    (source/'input').write_text('input')
    backend=BuildBackend(Systemd(),tmp_path/'privileged')
    rid='e'*32
    args=dict(project_root=project,resource_id=rid,prepared_root=prepared,
              source_directory=source,output_directory=output,
              input_manifest_id='root-source',_peer=(0,0))
    record=backend.register(**args)
    request=dict(build_root_id=rid,source_workspace_id=rid+'-source',
                 output_workspace_id=rid+'-output',
                 command=['cc','$IMAGE_BUILD_SOURCE',"awk '{print $1}'"],
                 environment={'PATH':'/bin'},working_directory='/image-build/source',
                 startup_timeout_seconds=5,execution_timeout_seconds=8,
                 termination_grace_seconds=2,
                 resource_limits={'thread-count-maximum':32,'memory-maximum-bytes':10_000_000},
                 read_only_root=True,network_access=False)
    assert (project.stat().st_uid,project.stat().st_gid) == (0,0)
    _check_root_launch_recovery(backend,args,request,record,monkeypatch)
