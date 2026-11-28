"""Crash-boundary tests for the privileged build-forget protocol."""
import json
import shutil

import pytest

from zog.root_control import build
from zog.root_control.build import BuildBackend
from zog.root_control.journal_barrier import JournalBarrier
from zog.root_control.systemd import SystemdBackendError
from .test_build_backend import registered


def released(registered, monkeypatch, tmp_path):
    backend, args, request = registered
    project, rid = args['project_root'], args['resource_id']
    path = backend.resource_path(project, rid)
    # Exercise actual job records and actual journal barrier unlink/fsync.
    barrier = JournalBarrier(tmp_path/'barriers')
    barrier.directory.mkdir()
    tokens = ['1'*64, '2'*64]
    for job_id, token in zip(('c'*32, 'd'*32), tokens):
        info = backend.prepare(project_root=project, job_id=job_id, request=request)
        info.update(process_cleanup_complete=True, journal_barrier_token=token)
        build.replace_json(path/'jobs'/(job_id+'.json'), info)
        build.replace_json(barrier.directory/(token+'.json'), {'fixture': token})
    backend.journal_barrier = barrier
    for directory in (path/'root').rglob('*'):
        if directory.is_dir():
            directory.chmod(0o700)
    (path/'root').chmod(0o700)
    backend.release(project_root=project, build_root_id=rid)
    return backend, args, request, path, barrier, tokens


@pytest.mark.parametrize('boundary', ['intent', 'barrier', 'registration', 'parent-sync', 'receipt'])
def test_privileged_forget_recovers_after_restart(registered, monkeypatch, tmp_path, boundary):
    backend, args, request, path, barrier, tokens = released(registered, monkeypatch, tmp_path)
    project, rid = args['project_root'], args['resource_id']
    call = dict(project_root=project, build_root_id=rid, _peer=backend.test_peer)
    marker = backend._forget_path(path)
    original_replace = build.replace_json
    original_rmtree = shutil.rmtree
    original_sync = build.synchronize_directory
    original_forget = barrier.forget
    with monkeypatch.context() as m:
        def interrupted_replace(target, record):
            original_replace(target, record)
            if target == marker and record['state'] == ('deleting' if boundary == 'intent' else 'forgotten'):
                raise OSError('injected interruption')
        def interrupted_barrier(token):
            original_forget(token)
            raise OSError('injected interruption')
        def interrupted_remove(target, *a, **kw):
            if target == path:
                (path/'registration.json').unlink()
                raise OSError('injected interruption')
            return original_rmtree(target, *a, **kw)
        def interrupted_sync(target):
            if target == path.parent and not path.exists():
                raise OSError('injected interruption')
            return original_sync(target)
        if boundary in ('intent', 'receipt'):
            m.setattr(build, 'replace_json', interrupted_replace)
        elif boundary == 'barrier':
            m.setattr(barrier, 'forget', interrupted_barrier)
        elif boundary == 'registration':
            m.setattr(shutil, 'rmtree', interrupted_remove)
        else:
            m.setattr(build, 'synchronize_directory', interrupted_sync)
        with pytest.raises(OSError, match='injected interruption'):
            backend.forget(**call)

    saved = json.loads(marker.read_text())
    assert saved['state'] == ('forgotten' if boundary == 'receipt' else 'deleting')
    assert saved['barrier_tokens'] == tokens
    assert saved['execution_identity'] == dict(zip(('uid', 'gid'), backend.test_peer))
    assert marker.stat().st_mode & 0o777 == 0o600
    if boundary == 'intent':
        assert (path/'registration.json').exists()
        assert all((barrier.directory/(t+'.json')).exists() for t in tokens)
    elif boundary == 'barrier':
        assert (path/'registration.json').exists()
        assert not (barrier.directory/(tokens[0]+'.json')).exists()
        assert (barrier.directory/(tokens[1]+'.json')).exists()
    elif boundary == 'registration':
        assert path.exists() and not (path/'registration.json').exists()
        assert list((path/'jobs').glob('*.json'))
    else:
        assert not path.exists()

    # A new backend instance has no in-memory state from the interrupted call.
    restarted = BuildBackend(backend.systemd, backend.directory,
                             journal_barrier=JournalBarrier(barrier.directory))
    wrong = (backend.test_peer[0]+1, backend.test_peer[1]+1)
    with pytest.raises(SystemdBackendError, match='different authenticated peer'):
        restarted.forget(**dict(call, _peer=wrong))
    assert json.loads(marker.read_text()) == saved
    with pytest.raises(SystemdBackendError, match='deletion pending or already forgotten'):
        restarted.register(**args, _peer=backend.test_peer)
    with pytest.raises(SystemdBackendError, match='deletion pending or already forgotten'):
        restarted.prepare(project_root=project, job_id='e'*32, request=request,
                          _peer=backend.test_peer)
    assert restarted.registration_status(project_root=project, resource_id=rid)['state'] == (
        'absent' if boundary == 'receipt' else 'forgetting')
    restarted.forget(**call)
    restarted.forget(**call)
    assert not path.exists() and not list(barrier.directory.glob('*.json'))
    assert json.loads(marker.read_text())['state'] == 'forgotten'
    assert restarted.registration_status(project_root=project, resource_id=rid)['state'] == 'absent'
    with pytest.raises(SystemdBackendError, match='different authenticated peer'):
        restarted.forget(**dict(call, _peer=wrong))
    with pytest.raises(SystemdBackendError, match='deletion pending or already forgotten'):
        restarted.register(**args, _peer=backend.test_peer)
    assert backend.systemd.properties is None


def test_missing_registration_without_intent_is_not_authority(registered):
    backend, args, _ = registered
    path = backend.resource_path(args['project_root'], args['resource_id'])
    with pytest.raises(SystemdBackendError, match='retained build root'):
        backend.forget(project_root=args['project_root'], build_root_id=args['resource_id'])
    assert not backend._forget_path(path).exists()
    (path/'registration.json').unlink()
    with pytest.raises(FileNotFoundError):
        backend.forget(project_root=args['project_root'], build_root_id=args['resource_id'])
    assert (path/'root').exists() and not backend._forget_path(path).exists()


def test_untrusted_forget_marker_rejected(registered):
    backend, args, _ = registered
    path = backend.resource_path(args['project_root'], args['resource_id'])
    marker = backend._forget_path(path)
    marker.symlink_to(path/'registration.json')
    with pytest.raises(SystemdBackendError, match='untrusted build forget record'):
        backend.forget(project_root=args['project_root'], build_root_id=args['resource_id'])
    assert (path/'registration.json').exists()
