import json
from pathlib import Path
import time
import pytest
from zog.box_control import Project
from zog.box_control.model import ApplicationRuntimeState
from zog.box_control.runtime.reference import RuntimeReferenceStore, ApplicationRuntimeReference, ProgramRuntimeReference
from zog.root_control import processes as p
from zog.root_control.daemon import RootControlDaemon


def stat(pid, started=123):
    return f'{pid} (a name) with parens) S 1 ' + '0 '*17 + str(started) + ' 0\n'


def process(root, pid, group='/unit'):
    path=root/str(pid);path.mkdir(parents=True)
    (path/'stat').write_text(stat(pid))
    (path/'cgroup').write_text('0::'+group+'\n')
    (path/'cmdline').write_bytes(b'/bin/make\0-j2\0')
    (path/'status').write_text('Uid:\t1001\t1001\t1001\t1001\n')


def test_nested_cgroups_and_foreign_or_exited_pids(tmp_path):
    cg=tmp_path/'cg'; proc=tmp_path/'proc'
    (cg/'unit/child').mkdir(parents=True)
    (cg/'unit/cgroup.procs').write_text('10\n11\n12\n')
    (cg/'unit/child/cgroup.procs').write_text('13\n10\n')
    process(proc,10);process(proc,11,'/other');process(proc,13,'/unit/child')
    kw=dict(cgroup_root=cg,proc_root=proc)
    result=p._scan('/unit',50,time.monotonic()+2,**kw)
    assert {r['pid'] for r in result['processes']}=={10,13}
    assert result['skipped_processes']==2
    assert result['processes'][0]['command']==['/bin/make','-j2']
    assert result['processes'][0]['start_time_ticks']==123
    limited=p._scan('/unit',1,time.monotonic()+2,**kw)
    assert limited['truncated'] and len(limited['processes'])==1
    assert p._scan('/unit',50,0,**kw)['truncated']
    for group in ('/', '/../outside', 'relative'):
        with pytest.raises(ValueError):p._scan(group,50,time.monotonic()+2,**kw)


def test_pid_reuse_and_migration_discarded(tmp_path,monkeypatch):
    process(tmp_path,10)
    original=p._read;calls=0
    def read(fd,name,maximum=16384):
        nonlocal calls
        if name=='stat':
            calls+=1
            if calls==2:return stat(10,999).encode(),False
        return original(fd,name,maximum)
    monkeypatch.setattr(p,'_read',read)
    assert p._process(10,'/unit',tmp_path) is None
    monkeypatch.setattr(p,'_read',original)
    (tmp_path/'10/cgroup').write_text('0::/unit-other\n')
    assert p._process(10,'/unit',tmp_path) is None


def test_bounded_command_and_empty_cmdline(tmp_path):
    process(tmp_path,10)
    (tmp_path/'10/cmdline').write_bytes(b'x'*5000)
    result=p._process(10,'/unit',tmp_path)
    assert result['command_truncated'] and len(result['command'][0])==4096
    (tmp_path/'10/cmdline').write_bytes(b'')
    assert p._process(10,'/unit',tmp_path)['command']==[]


@pytest.fixture
def target(tmp_path,monkeypatch):
    project=Project(tmp_path)
    member=ProgramRuntimeReference('main','zog-test.service',command=('saved-command',),invocation_id='a'*32)
    ref=ApplicationRuntimeReference('ABCDEF','app','app','gen',ApplicationRuntimeState.RUNNING,
                                    boot_id='b'*32,programs=(member,))
    RuntimeReferenceStore(project.runtime_reference_file).save({'ABCDEF':ref})
    monkeypatch.setattr(p,'current_boot_id',lambda:'b'*32)
    monkeypatch.setattr(p,'_unit',lambda *args:('a'*32,'/unit'))
    monkeypatch.setattr(p,'_scan',lambda *args:dict(processes=[{'pid':10}],truncated=False,skipped_processes=0))
    return dict(project_root=str(tmp_path),runtime_id='ABCDEF',program='main')


def test_read_only_identity_bound_rpc(target,monkeypatch):
    root=Path(target['project_root']); marker=root/'state/mutation-incomplete.json';marker.write_text('{}')
    before={str(f):f.read_bytes() for f in root.rglob('*') if f.is_file()}
    daemon=RootControlDaemon(root/'unused',systemd_backend=object())
    result=daemon.handle(dict(operation='application_processes',**target))['result']
    assert result['status']=='observed' and result['expected_command']==['saved-command']
    assert all(Path(f).read_bytes()==data for f,data in before.items())
    monkeypatch.setattr(p,'_unit',lambda *a:('different','/unit'))
    assert p.inspect(**target)['status']=='integrity-fault'
    monkeypatch.setattr(p,'current_boot_id',lambda:'new-boot')
    assert p.inspect(**target)['status']=='previous-boot'
    with pytest.raises(ValueError):daemon.handle(dict(operation='application_processes',**target,unit_name='arbitrary'))
    with pytest.raises(ValueError):p.inspect(**target,limit=101)


def test_unit_changes_discard_all_rows(target,monkeypatch):
    units=iter([('a'*32,'/unit'),None])
    monkeypatch.setattr(p,'_unit',lambda *args:next(units))
    result=p.inspect(**target)
    assert result['status']=='changed-during-read' and result['processes']==[]
    monkeypatch.setattr(p,'_unit',lambda *args:None)
    assert p.inspect(**target)['status']=='absent'


def test_build_job_and_missing_identity(target):
    root=Path(target['project_root']);directory=root/'state/build-job';directory.mkdir()
    job='c'*32
    raw=dict(schema=1,entity='job:'+job,request={'command':['make']},
             boot_id='b'*32,invocation_id='a'*32,unit_name='zog-build.service')
    path=directory/(job+'.json');path.write_text(json.dumps(raw))
    assert p.inspect(project_root=str(root),job_id=job)['expected_command']==['make']
    raw['invocation_id']=None;path.write_text(json.dumps(raw))
    assert p.inspect(project_root=str(root),job_id=job)['status']=='identity-unavailable'



def test_boot_read_failure_is_unavailable(target,monkeypatch):
    from zog.box_control.errors import RuntimeOperationError
    def failed(): raise RuntimeOperationError('boot unavailable')
    monkeypatch.setattr(p,'current_boot_id',failed)
    assert p.inspect(**target)['status']=='unavailable'


def test_serialized_byte_budget(tmp_path,monkeypatch):
    root=tmp_path/'cg';(root/'unit').mkdir(parents=True)
    (root/'unit/cgroup.procs').write_text(''.join(str(i)+'\n' for i in range(100)))
    monkeypatch.setattr(p,'_process',lambda pid,*a:dict(pid=pid,command=['\ufffd'*4096]))
    result=p._scan('/unit',100,time.monotonic()+2,cgroup_root=root)
    assert result['truncated'] and 0<len(result['processes'])<100
    assert len(json.dumps(result).encode())<270000
