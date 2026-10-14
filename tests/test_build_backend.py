import json
import os
from pathlib import Path

import pytest

from zog.root_control.build import BuildBackend
from zog.root_control.systemd import BusctlSystemdBackend, SystemdBackendError


class Systemd(BusctlSystemdBackend):
    def __init__(self): self.properties=None
    def version(self): return 250
    def start_slice(self, **kwargs): pass
    def _job(self, method, signature, body): self.properties=dict(body[2])


@pytest.fixture
def registered(tmp_path, monkeypatch):
    ownership=[]
    monkeypatch.setattr(os, 'chown', lambda path, uid, gid, **kwargs: ownership.append((Path(path),uid,gid)))
    project=tmp_path/'project'; attempt=project/'state/image-build/attempts/one'; attempt.mkdir(parents=True)
    root,source,output=[attempt/name for name in ('root','source','output')]
    for p in (root,source,output): p.mkdir()
    (root/'bin').mkdir(); (root/'bin/cc').write_text('fake compiler'); (root/'bin/cc').chmod(0o755)
    (source/'input').write_text('source')
    backend=BuildBackend(Systemd(),tmp_path/'privileged')
    backend.test_ownership=ownership
    rid='b'*32
    args=dict(project_root=project,resource_id=rid,prepared_root=root,source_directory=source,output_directory=output,
              input_manifest_id='verified-manifest',execution_user_id=12345,execution_group_id=12345)
    backend.register(**args)
    request=dict(build_root_id=rid,source_workspace_id=rid+'-source',output_workspace_id=rid+'-output',command=['cc','-v'],
                 environment={'PATH':'/bin'},working_directory='/image-build/source',execution_user_id=12345,execution_group_id=12345,
                 startup_timeout_seconds=5,execution_timeout_seconds=8,termination_grace_seconds=2,
                 resource_limits={'thread-count-maximum':32,'memory-maximum-bytes':10000000},read_only_root=True,network_access=False)
    return backend,args,request


def test_import_is_private_read_only_and_workspaces_stay_at_caller_paths(registered):
    backend,args,request=registered
    imported=backend.resource_path(args['project_root'],args['resource_id'])/'root'
    assert (imported/'bin/cc').read_text()=='fake compiler'
    assert not (imported/'bin/cc').stat().st_mode & 0o222
    assert (args['source_directory']/'input',12345,12345) in backend.test_ownership
    (args['prepared_root']/'bin/cc').write_text('changed original')
    backend.register(**args)
    assert (imported/'bin/cc').read_text()=='fake compiler'


def test_properties_enforce_finite_unprivileged_network_disabled_execution(registered):
    backend,args,request=registered
    backend.start(project_root=args['project_root'],job_id='c'*32,request=request)
    props=backend.systemd.properties
    assert props['PrivateNetwork'].value is True
    assert props['NoNewPrivileges'].value is True
    assert props['CapabilityBoundingSet'].value==0
    assert props['User'].value=='12345'
    assert props['RuntimeMaxUSec'].value==8000000
    assert props['TimeoutStartUSec'].value==5000000
    assert props['TimeoutStopUSec'].value==2000000
    assert props['ExecStartEx'].value[0][0]=='/bin/cc'
    assert props['ExecStartEx'].value[0][2]==['no-env-expand']
    assert props['ProtectSystem'].value=='strict'
    with pytest.raises(SystemdBackendError): backend.start(project_root=args['project_root'],job_id='c'*32,request=request)


def test_exclusive_writer_and_no_host_executable_fallback(registered):
    backend,args,request=registered
    request['command']=['only-on-host']
    with pytest.raises(SystemdBackendError): backend.prepare(project_root=args['project_root'],job_id='c'*32,request=request)
    request['command']=['cc']
    backend.prepare(project_root=args['project_root'],job_id='c'*32,request=request)
    with pytest.raises(SystemdBackendError): backend.prepare(project_root=args['project_root'],job_id='d'*32,request=request)
    with pytest.raises(SystemdBackendError): backend.release(project_root=args['project_root'],build_root_id=args['resource_id'])


def test_paths_outside_build_attempt_namespace_are_rejected(registered,tmp_path):
    backend,args,_=registered
    with pytest.raises(SystemdBackendError): backend.register(**dict(args,resource_id='e'*32,source_directory=tmp_path))


def test_private_null_profile_is_explicit_and_retains_sandbox(registered, monkeypatch):
    backend,args,request=registered
    node=backend.resource_path(args['project_root'],args['resource_id'])/'permission-test-null'
    monkeypatch.setattr(backend,'private_null',lambda path:node)
    request['device_profile']='private-null-permission-test'
    backend.start(project_root=args['project_root'],job_id='c'*32,request=request)
    props=backend.systemd.properties
    assert props['PrivateDevices'].value is True
    assert props['ProtectSystem'].value=='strict'
    assert props['CapabilityBoundingSet'].value==0
    assert props['BindPaths'].value[-1][:2]==[str(node),'/dev/null']


def test_unknown_device_profile_rejected(registered):
    from zog.root_control.build import canonical_request
    _,_,request=registered
    with pytest.raises(SystemdBackendError):canonical_request(dict(request,device_profile='host-devices'))
    assert 'device_profile' not in canonical_request(request)


def test_private_null_rejects_symlink_and_regular_file(tmp_path):
    node=tmp_path/'permission-test-null'
    node.symlink_to('/dev/null')
    with pytest.raises(SystemdBackendError):BuildBackend.private_null(tmp_path)
    node.unlink();node.write_text('not a device')
    with pytest.raises(SystemdBackendError):BuildBackend.private_null(tmp_path)


@pytest.mark.parametrize('already_exists', [False, True])
def test_private_null_normalizes_only_new_device_group(tmp_path, monkeypatch, already_exists):
    import stat
    from types import SimpleNamespace
    node = tmp_path/'permission-test-null'
    info = SimpleNamespace(st_mode=stat.S_IFCHR | 0o600, st_rdev=os.makedev(1, 3), st_uid=0, st_gid=993)
    ownership = []
    modes = []
    original_lstat = Path.lstat
    monkeypatch.setattr(Path, 'lstat', lambda path: info if path == node else original_lstat(path))
    def create(path, mode, device):
        assert path == node and device == os.makedev(1, 3)
        if already_exists:
            raise FileExistsError
    def own(path, uid, gid, *, follow_symlinks):
        assert path == node and follow_symlinks is False
        ownership.append((uid, gid))
        info.st_uid, info.st_gid = uid, gid
    monkeypatch.setattr(os, 'mknod', create)
    monkeypatch.setattr(os, 'chown', own)
    monkeypatch.setattr(os, 'chmod', lambda path, mode, **kw: modes.append(mode))
    if already_exists:
        with pytest.raises(SystemdBackendError):
            BuildBackend.private_null(tmp_path)
        assert ownership == [] and modes == []
    else:
        assert BuildBackend.private_null(tmp_path) == node
        assert ownership == [(0, 0)] and modes == [0o666]


def test_release_removes_private_null_after_cleanup(registered):
    backend,args,request=registered
    path=backend.resource_path(args['project_root'],args['resource_id'])
    node=path/'permission-test-null';node.write_text('release fixture')
    backend.prepare(project_root=args['project_root'],job_id='c'*32,request=request)
    with pytest.raises(SystemdBackendError):
        backend.release(project_root=args['project_root'],build_root_id=args['resource_id'])
    assert node.exists()
    job=path/'jobs'/('c'*32+'.json');record=json.loads(job.read_text())
    record['process_cleanup_complete']=True;job.write_text(json.dumps(record))
    # The real backend is privileged; allow this unprivileged fixture to remove its root.
    for directory in (path/'root').rglob('*'):
        if directory.is_dir(): directory.chmod(0o700)
    (path/'root').chmod(0o700)
    backend.release(project_root=args['project_root'],build_root_id=args['resource_id'])
    assert not node.exists()


def test_explicit_stack_limit_preserved_in_launch(registered):
    backend,args,request=registered
    request['resource_limits']['stack-maximum-bytes']=64*1024*1024
    backend.start(project_root=args['project_root'],job_id='c'*32,request=request)
    assert backend.systemd.properties['LimitSTACK'].value==64*1024*1024
    assert backend.systemd.properties['LimitSTACKSoft'].value==64*1024*1024


@pytest.mark.parametrize('value',[0,-1,True,2**63])
def test_invalid_stack_limit_rejected(registered,value):
    from zog.root_control.build import canonical_request
    _,_,request=registered
    request['resource_limits']['stack-maximum-bytes']=value
    with pytest.raises(SystemdBackendError):canonical_request(request)


def test_released_workspace_directories_return_to_owner_without_file_changes(registered,monkeypatch):
    backend,args,request=registered
    child=args['output_directory']/'nested';child.mkdir()
    file=child/'result';file.write_text('retained');file.chmod(0o640)
    before=file.stat();seen=[]
    monkeypatch.setattr(os,'fchown',lambda fd,uid,gid:seen.append((uid,gid)))
    manifest=backend.resource_path(args['project_root'],args['resource_id'])/'registration.json'
    record=json.loads(manifest.read_text());record['state']='releasing';manifest.write_text(json.dumps(record))
    backend.reclaim_workspace_directories(project_root=args['project_root'],build_root_id=args['resource_id'])
    owner=args['project_root'].stat()
    assert len(seen)==3 and set(seen)=={(owner.st_uid,owner.st_gid)}
    assert file.read_text()=='retained' and file.stat().st_mode==before.st_mode
    assert file.stat().st_ino==before.st_ino


def test_workspace_reclamation_refuses_registered_resource(registered):
    backend,args,_=registered
    with pytest.raises(SystemdBackendError,match='requires resource release'):
        backend.reclaim_workspace_directories(project_root=args['project_root'],build_root_id=args['resource_id'])


def test_explicit_cpu_weight_preserved_in_launch(registered):
    backend,args,request=registered
    request['resource_limits']['cpu-weight']=50
    backend.start(project_root=args['project_root'],job_id='c'*32,request=request)
    assert backend.systemd.properties['CPUWeight'].value==50


@pytest.mark.parametrize('value',[0,-1,True,10001])
def test_invalid_cpu_weight_rejected(registered,value):
    from zog.root_control.build import canonical_request
    _,_,request=registered
    request['resource_limits']['cpu-weight']=value
    with pytest.raises(SystemdBackendError):canonical_request(request)
