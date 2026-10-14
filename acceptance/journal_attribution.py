"""Opt-in systemd/journald diagnostic, not a substitute for build API acceptance.

Only diagnostic evidence uses unit/marker matching. Production invocation filters
must never use these matches as a fallback. Run on a disposable host as root.
"""
import argparse
import asyncio
import json
import os
import signal
import sys
from pathlib import Path
import subprocess
import uuid

from dbus_next import BusType, Message, MessageType, Variant
from dbus_next.aio import MessageBus


def properties(identifier, marker, outcome, *, retain=False, barrier=None):
    # These lifecycle properties mirror finite build execution. This minimal
    # probe intentionally excludes RootDirectory and the build filesystem setup.
    script = 'printf "%s\\n" "$1"; printf "%s-err\\n" "$1" >&2; '
    script += ('(printf "%s-child\\n" "$1") & wait' if outcome == 'child'
               else 'exit ' + ('7' if outcome == 'failure' else '0'))
    argv = ['/bin/sh', '-c', script, 'probe', marker]
    result = dict(Type=Variant('s', 'exec'), ExitType=Variant('s', 'cgroup'),
        User=Variant('s', 'nobody'), AddRef=Variant('b', True), Restart=Variant('s', 'no'),
        KillMode=Variant('s', 'control-group'), RuntimeMaxUSec=Variant('t', 10_000_000),
        TimeoutStopUSec=Variant('t', 2_000_000),
        RemainAfterExit=Variant('b', retain), StandardOutput=Variant('s', 'journal'),
        StandardError=Variant('s', 'journal'), SyslogIdentifier=Variant('s', identifier),
        ExecStart=Variant('a(sasb)', [['/bin/sh', argv, False]]))
    # Diagnostic only: fixed host commands, no RootDirectory, caller environment,
    # or production privilege policy. The no-op control detects timing effects.
    if barrier:
        if barrier not in ('sync', 'control'):
            raise ValueError('unknown diagnostic barrier')
        executable = '/usr/bin/journalctl' if barrier == 'sync' else '/usr/bin/true'
        argv = [executable, '--sync'] if barrier == 'sync' else [executable]
        result['ExecStopPostEx'] = Variant('a(sasas)', [[executable, argv, ['privileged']]])
    return [[key, value] for key, value in result.items()]


def classify(job, entries):
    """Controlled-marker diagnosis only; never infer missing invocation identity."""
    expected = [job['unit'], job['unit'] + '-err']
    if job['outcome'] == 'child':
        expected.append(job['unit'] + '-child')
    selected = [entry for entry in entries if entry.get('MESSAGE') in expected]
    matched = [entry for entry in selected
               if entry.get('_BOOT_ID') == job['boot_id']
               and entry.get('_SYSTEMD_INVOCATION_ID') == job['invocation_id']]
    return dict(expected=len(expected), recorded=len(selected), attributed=len(matched),
        complete=(len(selected) == len(expected) and len(matched) == len(expected)
                  and sorted(e['MESSAGE'] for e in matched) == sorted(expected)),
        entries=[{key:entry.get(key) for key in ('MESSAGE', '_BOOT_ID', '_SYSTEMD_UNIT',
                 '_SYSTEMD_INVOCATION_ID', '_PID', '_STREAM_ID', '__CURSOR')}
                 for entry in selected])


async def probe(count, concurrency, retain, barrier=None, pause_journal=False):
    bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
    jobs, units, cleanup_errors = [], [], []
    identifier = 'zog-journal-check-' + uuid.uuid4().hex
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip().replace('-', '')

    async def call(path, interface, member, signature, body):
        reply = await asyncio.wait_for(bus.call(Message(destination='org.freedesktop.systemd1',
            path=path, interface=interface, member=member, signature=signature, body=body)), 10)
        if reply.message_type == MessageType.ERROR:
            raise RuntimeError(f'{member}: {reply.error_name}')
        return reply.body

    async def manager(member, signature, body):
        return await call('/org/freedesktop/systemd1', 'org.freedesktop.systemd1.Manager',
                          member, signature, body)

    journal_pid = None
    resumes = []
    if pause_journal:
        if concurrency != 1:
            raise ValueError('paused-journal experiment requires serial execution')
        journal_pid = int(subprocess.check_output(['systemctl', 'show', 'systemd-journald',
            '--property=MainPID', '--value'], text=True, timeout=5))
        if journal_pid <= 1:
            raise RuntimeError('invalid journald PID')

    async def execute(index):
        if journal_pid is not None:
            # Independent watchdog resumes even if the probe is interrupted.
            resumes.append(subprocess.Popen([sys.executable, '-c',
                'import os,signal,time,sys; time.sleep(0.5); os.kill(int(sys.argv[1]),signal.SIGCONT)',
                str(journal_pid)]))
            os.kill(journal_pid, signal.SIGSTOP)
        unit = identifier + '-' + str(index) + '.service'
        units.append(unit)  # Cleanup also covers a lost StartTransientUnit reply.
        outcome = ('success', 'failure', 'child')[index % 3]
        await manager('StartTransientUnit', 'ssa(sv)a(sa(sv))',
                      [unit, 'fail', properties(identifier, unit, outcome, retain=retain, barrier=barrier), []])
        path = (await manager('GetUnit', 's', [unit]))[0]
        async with asyncio.timeout(15):
            while True:
                service = (await call(path, 'org.freedesktop.DBus.Properties', 'GetAll',
                                      's', ['org.freedesktop.systemd1.Service']))[0]
                state = (await call(path, 'org.freedesktop.DBus.Properties', 'GetAll',
                                    's', ['org.freedesktop.systemd1.Unit']))[0]
                ended = bool(service['ExecMainExitTimestampMonotonic'].value)
                if ended and (state['ActiveState'].value in ('inactive', 'failed')
                              or state['SubState'].value == 'exited'):
                    break
                await asyncio.sleep(.01)  # Observation polling, never a payload delay.
        service = (await call(path, 'org.freedesktop.DBus.Properties', 'GetAll',
                              's', ['org.freedesktop.systemd1.Service']))[0]
        hook = service.get('ExecStopPost')
        if barrier and (not hook or not hook.value or hook.value[0][-2:] != [1, 0]):
            raise RuntimeError('Stop hook failed: ' + str(hook))
        expected_exit = 7 if outcome == 'failure' else 0
        if service['ExecMainCode'].value != 1 or service['ExecMainStatus'].value != expected_exit:
            raise RuntimeError(f"Unexpected payload result: {unit}: code={service['ExecMainCode'].value}, status={service['ExecMainStatus'].value}")
        invocation = bytes(state['InvocationID'].value).hex()
        if len(invocation) != 32 or invocation == '0' * 32:
            raise RuntimeError('Missing authoritative invocation identity: ' + unit)
        hook_result = {'code': hook.value[0][-2], 'status': hook.value[0][-1]} if barrier else None
        jobs.append(dict(hook_result=hook_result, unit=unit, invocation_id=invocation, boot_id=boot, outcome=outcome,
                         active_state=state['ActiveState'].value,
                         metadata_exists=os.path.islink('/run/systemd/units/invocation:' + unit)))

    try:
        for first in range(0, count, concurrency):
            results = await asyncio.gather(*(execute(i) for i in range(first, min(first + concurrency, count))),
                                           return_exceptions=True)
            for result in results:
                if isinstance(result, BaseException):
                    raise result
        # Flush only after jobs ended. This distinguishes delayed delivery from
        # permanent missing attribution; it cannot restore metadata already lost.
        subprocess.run(['journalctl', '--sync'], check=True, timeout=15)
        command = ['journalctl', '--no-pager', '-o', 'json', 'SYSLOG_IDENTIFIER=' + identifier]
        logs = [json.loads(line) for line in subprocess.check_output(command, text=True, timeout=15).splitlines()]
        for job in jobs:
            job.update(classify(job, logs))
    finally:
        if journal_pid is not None:
            os.kill(journal_pid, signal.SIGCONT)
        for resume in resumes:
            resume.wait(timeout=2)
        for unit in units:
            for method, signature, body in [('StopUnit', 'ss', [unit, 'replace']),
                                            ('ResetFailedUnit', 's', [unit]), ('UnrefUnit', 's', [unit])]:
                try:
                    await manager(method, signature, body)
                except Exception as exc:
                    cleanup_errors.append(dict(unit=unit, operation=method, error=str(exc)))
        # StopUnit returns a job; await unloading rather than assume it finished.
        pending = set(units)
        for _ in range(200):
            for unit in tuple(pending):
                try:
                    await manager('GetUnit', 's', [unit])
                except RuntimeError as exc:
                    if 'NoSuchUnit' in str(exc):
                        pending.remove(unit)
                    else:
                        raise
            if not pending:
                break
            await asyncio.sleep(.05)
        bus.disconnect()
    return dict(schema=1, diagnostic_only=True, journal_pause_seconds=0.5 if pause_journal else 0, systemd=subprocess.check_output(['systemctl', '--version'], text=True),
                retain_after_exit=retain, barrier=barrier, concurrency=concurrency, jobs=jobs,
                complete=all(job['complete'] for job in jobs),
                cleanup=dict(unloaded=not pending, remaining=sorted(pending), errors=cleanup_errors))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--disposable-host', action='store_true', required=True)
    parser.add_argument('--barrier', choices=['sync', 'control'],
                        help='Diagnostic root stop hook; fixed journal sync or no-op timing control')
    parser.add_argument('--pause-journal', action='store_true',
                        help='Fault injection: briefly suspend host journald, with independent resume')
    parser.add_argument('--count', type=int, default=60)
    parser.add_argument('--concurrency', type=int, default=1)
    parser.add_argument('--retain-after-exit', action='store_true', help='Diagnostic control, not a proposed fix')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() or not Path('/run/systemd/system').is_dir():
        parser.error('requires root on a systemd disposable host')
    if not 1 <= args.count <= 300 or not 1 <= args.concurrency <= 16:
        parser.error('count must be 1..300 and concurrency 1..16')
    if args.pause_journal and args.concurrency != 1:
        parser.error('--pause-journal requires --concurrency 1')
    result = asyncio.run(probe(args.count, args.concurrency, args.retain_after_exit, args.barrier, args.pause_journal))
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(dict(jobs=len(result['jobs']), fully_attributed=sum(j['complete'] for j in result['jobs']),
                         cleanup=result['cleanup'])))
    return 0 if result['complete'] and result['cleanup']['unloaded'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
