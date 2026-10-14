"""Bounded, invocation-scoped journal reads. No arbitrary journal query API."""
import base64
import hashlib
import json
import os
import re
import selectors
import subprocess
import time
from pathlib import Path

from zog.box_control.project import Project
from zog.box_control.runtime.reference import RuntimeReferenceStore

MAX_BYTES = 256 * 1024


def run_bounded(command, *, deadline):
    """Drain both pipes with a shared deadline and a hard total byte budget."""
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as child:
        output, errors = bytearray(), bytearray()
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(child.stdout, selectors.EVENT_READ, output)
                selector.register(child.stderr, selectors.EVENT_READ, errors)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError('journal read deadline exceeded')
                    for key, _ in selector.select(remaining):
                        chunk = os.read(key.fileobj.fileno(), 8192)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        key.data.extend(chunk)
                        if len(output) + len(errors) > MAX_BYTES:
                            raise ValueError('journal page exceeds byte budget; reduce limit')
            child.wait(timeout=max(.001, deadline-time.monotonic()))
            if child.returncode:
                raise RuntimeError('journalctl failed: ' + errors.decode(errors='replace')[:1024])
            return [json.loads(line) for line in output.splitlines() if line.strip()]
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()


def _identity(value):
    compact = str(value or '').replace('-', '')
    if not re.fullmatch('[0-9a-fA-F]{32}', compact):
        raise ValueError('recorded journal identity is unavailable or invalid')
    return compact.lower()


def read_logs(*, project_root, runtime_id, program, cursor=None, limit=50):
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError('log limit must be an integer from 1 through 100')
    project = Project(Path(project_root))
    reference = RuntimeReferenceStore(project.runtime_reference_file).load().get(runtime_id)
    if reference is None:
        raise ValueError('unknown or pruned runtime identity')
    members = [p for p in reference.programs if p.program == program]
    if len(members) != 1:
        raise ValueError('unknown or ambiguous program identity')
    member = members[0]
    page = dict(runtime_id=runtime_id, program=program, entries=[], next_cursor=cursor,
                has_more=False, status='ok')
    if not reference.boot_id or not member.invocation_id:
        return dict(page, status='identity-unavailable')
    return _read_page(page, project.path, [runtime_id, program],
                      reference.boot_id, member.invocation_id, cursor, limit)


def read_build_logs(*, project_root, job_id, cursor=None, limit=50):
    from types import SimpleNamespace
    from zog.box_control.build_jobs import BuildJobs
    project = Project(Path(project_root))
    store = BuildJobs(SimpleNamespace(project=project, systemd_transport=None))
    record = store.load('job:' + job_id)
    page = dict(job_id=job_id, entries=[], next_cursor=cursor, has_more=False, status='ok')
    return _read_page(page, project.path, ['build-job', job_id],
                      record.get('boot_id'), record.get('invocation_id'), cursor, limit)


def _read_page(page, project_path, stream, boot_id, invocation_id, cursor, limit):
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError('log limit must be an integer from 1 through 100')
    if not boot_id or not invocation_id:
        return dict(page, status='identity-unavailable')
    boot, invocation = _identity(boot_id), _identity(invocation_id)
    scope = hashlib.sha256(json.dumps([str(project_path), *stream, boot, invocation]).encode()).hexdigest()
    after = None
    if cursor is not None:
        try:
            if not isinstance(cursor,str) or len(cursor)>4096: raise ValueError()
            decoded=json.loads(base64.b64decode(cursor,altchars=b'-_',validate=True))
            if decoded['scope'] != scope: raise ValueError()
            after=decoded['cursor']
            if not isinstance(after,str) or not after or len(after)>2048 or '\x00' in after: raise ValueError()
        except (ValueError, KeyError, TypeError):
            raise ValueError('invalid cursor or cursor belongs to another log stream') from None
    command=['journalctl','--no-pager','--quiet','--output=json',
             '--output-fields=__CURSOR,__REALTIME_TIMESTAMP,PRIORITY,MESSAGE,_BOOT_ID,_SYSTEMD_INVOCATION_ID',
             '_BOOT_ID='+boot,'_SYSTEMD_INVOCATION_ID='+invocation]
    deadline=time.monotonic()+5
    try:
        if after:
            # Read anchor and successors together: no separate validation/read race.
            rows=run_bounded(command+['--cursor='+after,'--lines=+'+str(limit+2)],deadline=deadline)
            if not rows or rows[0].get('__CURSOR') != after:
                return dict(page,status='cursor-unavailable',next_cursor=None)
            rows=rows[1:]
        else:
            rows=run_bounded(command+['--lines='+str(limit)],deadline=deadline)
        selected=rows[:limit]
        for row in selected:
            if row.get('_BOOT_ID') != boot or row.get('_SYSTEMD_INVOCATION_ID') != invocation:
                raise ValueError('journal returned an entry outside the requested invocation')
            position=row['__CURSOR']
            if not isinstance(position,str) or len(position)>2048: raise ValueError('invalid journal cursor')
            message=row.get('MESSAGE')
            truncated=message is None
            if isinstance(message,list) and all(type(v) is int and 0<=v<=255 for v in message):
                message=bytes(message).decode('utf-8',errors='replace')
            elif not isinstance(message,str) and message is not None:
                message=json.dumps(message,ensure_ascii=True)
            page['entries'].append(dict(timestamp_microseconds=row.get('__REALTIME_TIMESTAMP'),
                priority=row.get('PRIORITY'), message=message, message_unavailable=truncated))
        if selected:
            page['next_cursor']=base64.urlsafe_b64encode(json.dumps({'scope':scope,'cursor':selected[-1]['__CURSOR']}).encode()).decode()
        page['has_more']=len(rows)>limit
        if not rows and not after: page['status']='empty-history'  # No claim that retention did or did not expire.
        return page
    except (OSError, ValueError, RuntimeError, TimeoutError, subprocess.TimeoutExpired, KeyError) as exc:
        # Never advance the cursor when an incomplete page or reader failure occurs.
        return dict(page,entries=[],next_cursor=cursor,has_more=False,status='unavailable',error=str(exc)[:1024])
