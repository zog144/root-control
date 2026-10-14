"""Bounded cgroup-v2 process snapshots, scoped to persisted execution identities."""
import os
import json
from pathlib import Path
import time
from types import SimpleNamespace

from zog.box_control.errors import RuntimeOperationError
from zog.box_control.boot import current_boot_id
from zog.box_control.project import Project
from zog.box_control.runtime.reference import RuntimeReferenceStore
from .systemd import BusctlSystemdBackend, _UNIT_IFACE, _SERVICE_IFACE


class IdentityChanged(ValueError):
    pass


def _unit(backend, project, unit):
    backend._validate_unit(project.path, unit)
    obj = backend._get_unit_path(unit)
    if obj is None:
        return None
    def get(interface, name):
        return backend._get_property(obj, interface, name)
    if not get(_UNIT_IFACE, 'Transient') or get(_UNIT_IFACE, 'DropInPaths'):
        raise IdentityChanged('unit is no longer an unmodified transient service')
    return (backend._invocation_id(get(_UNIT_IFACE, 'InvocationID')),
            get(_SERVICE_IFACE, 'ControlGroup'))


def _read(directory, name, maximum=16384):
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
    with os.fdopen(descriptor, 'rb') as stream:
        data = stream.read(maximum + 1)
    return data[:maximum], len(data) > maximum


def _stat(data):
    # comm may contain spaces and parentheses. Fields after the last ')' start at 3.
    text = data.decode(errors='replace')
    fields = text[text.rindex(')') + 2:].split()
    return fields[0], int(fields[1]), int(fields[19])


def _member(data, group):
    for line in data.decode().splitlines():
        if line.startswith('0::'):
            location = line[3:]
            return location == group or location.startswith(group + '/')
    return False


def _process(pid, group, proc_root):
    # Directory descriptor binds reads to this proc entry, not a later reused PID.
    descriptor = os.open(proc_root / str(pid), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        before, cut = _read(descriptor, 'stat')
        if cut: raise ValueError('oversized process stat')
        state, parent, started = _stat(before)
        membership, cut = _read(descriptor, 'cgroup')
        if cut or not _member(membership, group): return None
        command, truncated = _read(descriptor, 'cmdline', 4096)
        status, cut = _read(descriptor, 'status')
        if cut: raise ValueError('oversized process status')
        uid = next(int(line.split()[1]) for line in status.splitlines() if line.startswith(b'Uid:'))
        after, cut = _read(descriptor, 'stat')
        membership, group_cut = _read(descriptor, 'cgroup')
        if cut or group_cut or _stat(after)[2] != started or not _member(membership, group): return None
        return dict(pid=pid, parent_pid=parent, state=state, user_id=uid,
                    start_time_ticks=started,
                    command=command.rstrip(b'\0').decode(errors='replace').split('\0') if command else [],
                    command_truncated=truncated)
    finally:
        os.close(descriptor)


def _scan(group, limit, deadline, *, cgroup_root=Path('/sys/fs/cgroup'), proc_root=Path('/proc')):
    if not isinstance(group, str) or not group.startswith('/') or group == '/' or any(p in ('.','..') for p in group.split('/')):
        raise ValueError('invalid service cgroup')
    target = cgroup_root / group.lstrip('/')
    if not target.resolve().is_relative_to(cgroup_root.resolve()):
        raise ValueError('cgroup escapes hierarchy')
    stack=[target]; seen=set(); processes=[]; skipped=0; visited=0; truncated=False; byte_count=0
    while stack:
        if time.monotonic() >= deadline or visited >= 256:
            truncated=True; break
        directory=stack.pop(); visited+=1
        try:
            with (directory/'cgroup.procs').open() as stream:
                for line in stream:
                    if time.monotonic() >= deadline or len(seen) >= 4096 or len(processes) >= limit:
                        truncated=True; break
                    pid=int(line)
                    if pid in seen: continue
                    seen.add(pid)
                    try:
                        item=_process(pid, group, proc_root)
                        if item is None: skipped+=1
                        else:
                            size=len(json.dumps(item).encode())
                            if byte_count+size > 256*1024:
                                truncated=True; break
                            processes.append(item); byte_count+=size
                    except (OSError, ValueError, StopIteration, IndexError): skipped+=1
            if truncated: break
            with os.scandir(directory) as entries:
                for entry in entries:
                    if time.monotonic() >= deadline or len(stack)+visited >= 256:
                        truncated=True; break
                    if entry.is_dir(follow_symlinks=False): stack.append(Path(entry.path))
        except FileNotFoundError:
            skipped+=1
    return dict(processes=processes, truncated=truncated, skipped_processes=skipped)


def inspect(*, project_root, runtime_id=None, program=None, job_id=None, limit=50):
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError('process limit must be an integer from 1 through 100')
    project=Project(Path(project_root))
    if job_id is not None:
        if runtime_id is not None or program is not None: raise ValueError('ambiguous process target')
        from zog.box_control.build_jobs import BuildJobs
        record=BuildJobs(SimpleNamespace(project=project,systemd_transport=None)).load('job:'+job_id)
        boot, invocation, unit = record.get('boot_id'),record.get('invocation_id'),record.get('unit_name')
        command=record['request']['command']
        target=dict(job_id=job_id)
    else:
        reference=RuntimeReferenceStore(project.runtime_reference_file).load().get(runtime_id)
        if reference is None: raise ValueError('unknown or pruned runtime identity')
        members=[p for p in reference.programs if p.program==program]
        if len(members)!=1: raise ValueError('unknown or ambiguous program identity')
        member=members[0]
        boot,invocation,unit=reference.boot_id,member.invocation_id,member.unit_name
        command=member.command;target=dict(runtime_id=runtime_id,program=program)
    # The saved launch command is not reconstructed from current specifications.
    expected='\0'.join(command).encode()[:4096].decode(errors='replace').split('\0')
    result=dict(target,observed_at=time.time(),snapshot='non-atomic',expected_command=expected,
                expected_command_truncated=len('\0'.join(command).encode())>4096,
                recorded_boot_id=boot,recorded_invocation_id=invocation,
                processes=[],truncated=False,skipped_processes=0)
    if not boot or not invocation or not unit: return dict(result,status='identity-unavailable')
    try:
        if boot != current_boot_id(): return dict(result,status='previous-boot')
    except RuntimeOperationError as exc:
        return dict(result,status='unavailable',error=str(exc)[:1024])
    deadline=time.monotonic()+5
    # Private read-only backend: never share the lifecycle job connection/deadline.
    backend=BusctlSystemdBackend();backend.deadline=deadline
    try:
        before=_unit(backend,project,unit)
        if before is None: return dict(result,status='absent')
        if before[0]!=invocation: raise IdentityChanged('unit invocation differs from saved identity')
        if not before[1]: return dict(result,status='no-cgroup')
        observed=_scan(before[1],limit,deadline)
        after=_unit(backend,project,unit)
        if after!=before: return dict(result,status='changed-during-read')
        return dict(result,**observed,status='partial' if observed['truncated'] or observed['skipped_processes'] else 'observed')
    except IdentityChanged as exc:
        return dict(result,status='integrity-fault',error=str(exc))
    except (OSError, ValueError, RuntimeError) as exc:
        return dict(result,status='unavailable',error=str(exc)[:1024])
