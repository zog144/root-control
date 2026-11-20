"""Kernel-peer authentication, durable identity, and non-root child evidence."""
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


def test_root_peer_and_missing_peer_never_invoke_build_backend(tmp_path):
    daemon = RootControlDaemon(tmp_path/'unused.sock')
    stub = BuildStub()
    daemon.build = stub
    for peer in (None, (0, 1001), (1001, 0), (0, 0)):
        with pytest.raises(SystemdBackendError, match='authenticated non-root'):
            daemon.handle({'operation': 'build_register'}, peer=peer)
    assert stub.calls == []


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
    assert not (path/'jobs'/'c'*32).exists()


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


def test_running_kernel_child_identity_cannot_be_root_or_mismatched():
    uid, gid = os.geteuid(), os.getegid()
    if uid == 0 or gid == 0:
        pytest.skip('current test runner is root; native nonroot proof is separate')
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
