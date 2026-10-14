import json
import os
import socket
import struct
from pathlib import Path
import pytest
from zog.root_control import journal_barrier as jb
from .test_build_backend import registered


def snapshot(**kw):
    return dict(Id='zog-test.service',ControlPID=os.getpid(),Transient=True,
                SubState='stop-post',InvocationID=[17]*16,**kw)


def record():
    return dict(unit='zog-test.service',uid=12345,boot_id=jb.boot_id(),invocation_id=None)


@pytest.mark.parametrize('change', [dict(ControlPID=987654321),dict(SubState='running'),
    dict(Id='zog-other.service'),dict(Transient=False),dict(InvocationID=[0]*16)])
def test_authentication_rejects_other_process_phase_or_unit(change):
    state=snapshot();state.update(change)
    with pytest.raises(PermissionError): jb.JournalBarrier.authenticate(record(),os.getpid(),12345,state)


def test_authentication_rejects_uid_boot_and_changed_incarnation():
    for r,uid in [(record(),54321),(dict(record(),boot_id='old'),12345),
                  (dict(record(),invocation_id='2'*32),12345)]:
        with pytest.raises(PermissionError): jb.JournalBarrier.authenticate(r,os.getpid(),uid,snapshot())
    assert jb.JournalBarrier.authenticate(record(),os.getpid(),12345,snapshot())=='11'*16


class Peer:
    def __init__(self,sock): self.sock=sock
    def __enter__(self): return self
    def __exit__(self,*args): self.sock.close()
    def __getattr__(self,key): return getattr(self.sock,key)
    def getsockopt(self,level,key,*args):
        if key==socket.SO_PEERCRED: return struct.pack('3i',os.getpid(),12345,12345)
        return self.sock.getsockopt(level,key,*args)


@pytest.fixture
def broker(tmp_path,monkeypatch):
    barrier=jb.JournalBarrier(tmp_path);barrier.server=object()
    token=barrier.register('zog-test.service',12345,'c'*32)
    monkeypatch.setattr(jb,'properties',lambda unit:snapshot())
    return barrier,token


def exchange(broker,token):
    client,server=socket.socketpair()
    with client:
        client.sendall((token+'\n').encode())
        broker.handle(Peer(server))
        return client.recv(1)


def test_exact_repeat_does_not_repeat_sync_and_status_survives_reload(broker,monkeypatch):
    barrier,token=broker;calls=[]
    monkeypatch.setattr(jb,'synchronize',lambda:calls.append(1))
    assert exchange(barrier,token)==b'1'
    assert exchange(barrier,token)==b'1' and calls==[1]
    assert jb.JournalBarrier(barrier.directory).status(token)['status']=='synchronized'
    assert barrier.register('zog-test.service',12345,'c'*32)==token
    assert barrier.status(token)['status']=='synchronized'


def test_sync_failure_is_separate_durable_unconfirmed_outcome(broker,monkeypatch):
    barrier,token=broker
    def fail(): raise TimeoutError()
    monkeypatch.setattr(jb,'synchronize',fail)
    assert exchange(barrier,token)==b'0'
    assert barrier.status(token)['status']=='unconfirmed'
    assert exchange(barrier,token)==b'0'


def test_forged_request_cannot_consume_registration(broker,monkeypatch):
    barrier,token=broker
    state=snapshot();state['ControlPID']=987654321
    monkeypatch.setattr(jb,'properties',lambda unit:state)
    monkeypatch.setattr(jb,'synchronize',lambda:pytest.fail('unauthorized synchronization'))
    assert exchange(barrier,token)==b''
    assert barrier.status(token)['status']=='pending'
    assert exchange(barrier,'../'+'a'*61)==b''


def test_storage_failure_never_acknowledges_success(broker,monkeypatch):
    barrier,token=broker;original=jb.replace_json
    def fail(path,value):
        if value['status']=='synchronized':raise OSError('disk failure')
        original(path,value)
    monkeypatch.setattr(jb,'replace_json',fail)
    monkeypatch.setattr(jb,'synchronize',lambda:None)
    assert exchange(barrier,token)==b''
    assert barrier.status(token)['status']=='attempted'


def test_host_sync_has_fixed_command_clean_environment_and_timeout(monkeypatch):
    calls=[]
    monkeypatch.setattr(jb.subprocess,'run',lambda *args,**kw:calls.append((args,kw)))
    monkeypatch.setenv('LD_PRELOAD','/build/evil.so')
    jb.synchronize()
    args,kw=calls[0]
    assert args[0]==['/usr/bin/journalctl','--sync']
    assert kw['env']==jb.ENV and 'LD_PRELOAD' not in kw['env']
    assert kw['cwd']=='/' and kw['timeout']==.8 and kw['check'] is True


def test_build_payload_mounts_unprivileged_hook_and_keeps_sandbox(registered,tmp_path):
    backend,args,request=registered
    class Barrier:
        helper=Path('/usr/libexec/zog/journal-wait')
        socket_path=Path('/run/zog-journal-broker/socket')
        def register(self,*args):return '1'*64
    backend.journal_barrier=Barrier();request['termination_grace_seconds']=3
    request['environment']['LD_PRELOAD']='/image-build/source/hostile.so'
    backend.start(project_root=args['project_root'],job_id='c'*32,request=request)
    props=backend.systemd.properties
    executable,argv,flags=props['ExecStopPostEx'].value[0]
    assert executable==argv[0]=='/run/zog-journal/wait' and argv[1]=='1'*64
    assert flags==['no-env-expand','ignore-failure']
    assert props['User'].value=='12345' and props['NoNewPrivileges'].value
    assert props['CapabilityBoundingSet'].value==0 and props['PrivateNetwork'].value
    assert props['BindReadOnlyPaths'].value==[
        ['/run/zog-journal-broker','/run/zog-journal',False,0],
        ['/usr/libexec/zog/journal-wait','/run/zog-journal/wait',False,0]]
    assert not any('root-control.sock' in str(v.value) for v in props.values())


def test_disappearing_hook_cannot_report_synchronized(broker,monkeypatch):
    barrier,token=broker;calls=[]
    def state(unit):
        value=snapshot()
        if calls:value['SubState']='dead'
        return value
    monkeypatch.setattr(jb,'properties',state)
    monkeypatch.setattr(jb,'synchronize',lambda:calls.append(1))
    assert exchange(barrier,token)==b'0'
    assert barrier.status(token)['reason']=='hook-identity-lost'


def test_interrupted_attempt_is_not_reexecuted(broker,monkeypatch):
    barrier,token=broker;path=barrier.directory/(token+'.json')
    state=json.loads(path.read_text());state.update(status='attempted',invocation_id='11'*16)
    jb.replace_json(path,state)
    monkeypatch.setattr(jb,'synchronize',lambda:pytest.fail('ambiguous attempt retried'))
    assert exchange(barrier,token)==b'0'
    assert barrier.status(token)['status']=='attempted'


def test_reclamation_during_sync_cannot_recreate_record(broker,monkeypatch):
    barrier,token=broker
    monkeypatch.setattr(jb,'synchronize',lambda:barrier.forget(token))
    assert exchange(barrier,token)==b''
    assert not (barrier.directory/(token+'.json')).exists()


def test_opt_in_rejects_too_short_stop_budget_before_service_start(registered):
    backend,args,request=registered
    backend.journal_barrier=object()
    with pytest.raises(Exception,match='at least 3 seconds'):
        backend.start(project_root=args['project_root'],job_id='c'*32,request=request)
    assert backend.systemd.properties is None
    path=backend.resource_path(args['project_root'],args['resource_id'])/'jobs'/('c'*32+'.json')
    assert not json.loads(path.read_text()).get('start_attempted')


def test_exit_evidence_saved_before_sync_and_survives_broker_reload(broker,monkeypatch):
    barrier,token=broker
    state=snapshot(ExecMainCode=1,ExecMainStatus=7,ExecMainExitTimestampMonotonic=123,Result='exit-code')
    monkeypatch.setattr(jb,'properties',lambda unit:state)
    def sync():
        saved=jb.JournalBarrier(barrier.directory).evidence(token,unit='zog-test.service',job_id='c'*32,uid=12345)
        assert saved['ExecMainStatus']==7 and saved['result']=='exit-code'
        raise TimeoutError('lost synchronization')
    monkeypatch.setattr(jb,'synchronize',sync)
    assert exchange(barrier,token)==b'0'
    saved=jb.JournalBarrier(barrier.directory).evidence(token,unit='zog-test.service',job_id='c'*32,uid=12345)
    assert saved['invocation_id']=='11'*16
    with pytest.raises(ValueError,match='ownership'):
        barrier.evidence(token,unit='zog-other.service',job_id='c'*32,uid=12345)
    monkeypatch.setattr(jb,'boot_id',lambda:'f'*32)
    assert barrier.evidence(token,unit='zog-test.service',job_id='c'*32,uid=12345) is None


def test_unfinished_or_malformed_exit_has_no_terminal_evidence():
    for change in ({'ExecMainCode':0},{'ExecMainExitTimestampMonotonic':0},{'ExecMainStatus':-1}):
        s=snapshot(ExecMainCode=1,ExecMainStatus=0,ExecMainExitTimestampMonotonic=2)
        s.update(change)
        assert jb.JournalBarrier.exit_evidence(s,'11'*16) is None


@pytest.mark.parametrize('disappear',[False,True])
def test_backend_recovers_only_after_verified_absence(registered,disappear):
    from zog.root_control.systemd import SystemdBackendError
    backend,args,request=registered
    info=backend.prepare(project_root=args['project_root'],job_id='c'*32,request=request)
    path=backend.resource_path(args['project_root'],args['resource_id'])
    job=path/'jobs'/('c'*32+'.json');raw=json.loads(job.read_text())
    raw['journal_barrier_token']='1'*64;jb.replace_json(job,raw)
    props=backend.expected_properties(path,raw)
    props['ExecStart']=[['/bin/cc',['/bin/cc','-v'],False,0,0,0,0,0,0,0]]
    class Barrier:
        def status(self,token):return {'status':'synchronized'}
        def evidence(self,token,**kwargs):
            assert kwargs==dict(unit=info['unit_name'],job_id='c'*32,uid=12345)
            return dict(properties=props,invocation_id='a'*32,boot_id=jb.boot_id(),
                        ExecMainCode=1,ExecMainStatus=0,ExecMainExitTimestampMonotonic=1,result='success')
    backend.journal_barrier=Barrier()
    def observe(**kwargs):
        if disappear: raise SystemdBackendError('unit vanished during observation')
        return {'exists':False}
    backend.systemd.observe=observe
    backend.systemd._get_unit_path=lambda unit:None
    result=backend.observe(project_root=args['project_root'],job_id='c'*32,build_root_id=args['resource_id'])
    assert not result['exists'] and result['terminal_evidence']['ExecMainStatus']==0
    props['RootDirectory']='/wrong'
    with pytest.raises(SystemdBackendError,match='evidence property mismatch'):
        backend.observe(project_root=args['project_root'],job_id='c'*32,build_root_id=args['resource_id'])
    if disappear:
        backend.systemd._get_unit_path=lambda unit:'/still-present'
        with pytest.raises(SystemdBackendError,match='vanished'):
            backend.observe(project_root=args['project_root'],job_id='c'*32,build_root_id=args['resource_id'])
