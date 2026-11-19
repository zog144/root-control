"""Read-only verifier for a controller-launched dollar-argv build on systemd 252.

Use ONLY after the native Work owner has installed/attested the reviewed
controller, created a distinct disposable finite-build request *through
box-control/root-control*, and retained its exact resource/job IDs.

This checker does not start, stop, refresh, retry or clean up any job.
Run once while the child is alive and once after it exits but before the
accepted cleanup unloads the transient service. Never use old R5 IDs.
"""
import argparse
import hashlib
import json
from pathlib import Path

from zog.root_control.build import (
    BuildBackend, LEGACY_SYSTEMD_ARGV_ENCODING, legacy_systemd_argv,
    identity,
)
from zog.root_control.systemd import BusctlSystemdBackend

_UNIT_IFACE = 'org.freedesktop.systemd1.Unit'
_SERVICE_IFACE = 'org.freedesktop.systemd1.Service'


def _hash_argv(argv):
    return hashlib.sha256(
        json.dumps(argv, separators=(',', ':'), ensure_ascii=True).encode('ascii')
    ).hexdigest()


def check(*, project_root, build_root_id, job_id, phase, resources):
    controller = BusctlSystemdBackend()
    if controller.version() != 252:
        raise RuntimeError('native acceptance requires exact systemd 252')
    backend = BuildBackend(controller, directory=resources)
    location, _registration = backend.load(project_root, identity(build_root_id))
    record = json.loads((location / 'jobs' / (identity(job_id) + '.json')).read_text())
    if (record['job_id'] != job_id or
            record['request']['build_root_id'] != build_root_id or
            record.get('exec_argv_encoding') != LEGACY_SYSTEMD_ARGV_ENCODING or
            record.get('start_attempted') is not True):
        raise RuntimeError('saved build identity or legacy argv encoding differs')
    requested = [record['resolved_executable'], *record['request']['command'][1:]]
    encoded = legacy_systemd_argv(requested)
    unit_name = record['unit_name']
    obj = controller._get_unit_path(unit_name)
    if obj is None:
        raise RuntimeError('native acceptance requires existing transient unit')
    state = controller._get_property(obj, _UNIT_IFACE, 'LoadState')
    if state != 'loaded':
        raise RuntimeError('transient build unit not loaded: ' + str(state))
    stored = controller._normalize_exec_start(
        controller._get_property(obj, _SERVICE_IFACE, 'ExecStart'))
    if stored != encoded:
        raise RuntimeError('systemd ExecStart differs from encoded saved job command')

    observed = backend.observe(project_root=project_root, job_id=job_id,
                               build_root_id=build_root_id)
    if not observed.get('exists') or observed.get('unit_name') != unit_name:
        raise RuntimeError('root-control rejected the native build observation')
    if observed.get('transient') is not True or not observed.get('invocation_id'):
        raise RuntimeError('transient unit or invocation identity is missing')
    result = dict(schema='root-control-systemd252-dollar-argv-native-v1',
                  phase=phase, systemd_version=252, unit=unit_name,
                  job_id=job_id, invocation_id=observed['invocation_id'],
                  request_argv_sha256=_hash_argv(requested),
                  stored_argv_sha256=_hash_argv(stored),
                  argv_count=len(requested), execstart_matches=True,
                  load_state=state)
    if phase == 'running':
        pid = controller._get_property(obj, _SERVICE_IFACE, 'MainPID')
        if type(pid) is not int or pid <= 1:
            raise RuntimeError('no running main child PID for native argv inspection')
        raw = (Path('/proc') / str(pid) / 'cmdline').read_bytes()
        expected = b'\0'.join(word.encode('utf-8') for word in requested) + b'\0'
        if raw != expected:
            raise RuntimeError('kernel child argv differs from original saved build request')
        result.update(child_pid=pid, kernel_child_argv_matches=True,
                      actual_argv_sha256=hashlib.sha256(raw).hexdigest())
    else:
        if (observed.get('active_state') not in ('inactive', 'failed') or
                observed.get('cgroup_empty') is not True or
                observed.get('ExecMainCode') != 1 or
                observed.get('ExecMainStatus') != 0 or
                not observed.get('ExecMainExitTimestampMonotonic') or
                observed.get('result') != 'success'):
            raise RuntimeError('controller terminal or cgroup evidence is not verified success')
        journal = observed.get('journal_barrier', {})
        if journal.get('status') not in ('not-enabled', 'synchronized'):
            raise RuntimeError('journal barrier is not reconciled')
        result.update(terminal_verified=True, cgroup_empty=True,
                      main_exit_code=0, service_result='success',
                      journal_barrier_status=journal.get('status'))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--disposable-accepted-job', action='store_true', required=True)
    parser.add_argument('--project-root', type=Path, required=True)
    parser.add_argument('--build-root-id', required=True)
    parser.add_argument('--job-id', required=True)
    parser.add_argument('--phase', choices=('running', 'terminal'), required=True)
    parser.add_argument('--resource-directory', type=Path,
                        default=Path('/var/lib/zog/build-resources'))
    args = parser.parse_args()
    result = check(project_root=args.project_root, build_root_id=args.build_root_id,
                   job_id=args.job_id, phase=args.phase,
                   resources=args.resource_directory)
    # Avoid printing raw argv: build operations may contain configuration
    # secrets. The match assertions above inspected all original bytes.
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
