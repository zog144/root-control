"""Read-only native acceptance through the normal authenticated root-control socket.

Run from the *same non-root box-control peer* that submitted a separately
authorized, disposable finite build. Never target archived Boot A operations.
This tool does not start jobs, call systemd directly or change state.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import time

from zog.root_control.protocol import encode, decode
from zog.root_control.build import canonical_request, legacy_systemd_argv


def observed_over_socket(socket_path, project_root, job_id, build_root_id):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(10)
        conn.connect(str(socket_path))
        conn.sendall(encode({
            'operation':'build_observe', 'project_root':str(project_root),
            'job_id':job_id, 'build_root_id':build_root_id}))
        response = decode(conn, deadline=time.monotonic()+10)
    if type(response) is not dict or response.get('ok') is not True:
        raise RuntimeError('authenticated root-control build observation rejected: '
                           +str(response.get('error') if isinstance(response,dict) else 'invalid'))
    return response['result']


def acceptance(*, controller_socket, project_root, build_root_id, job_id,
               request_json, phase, expected_invocation_id=None):
    uid, gid = os.geteuid(), os.getegid()
    if uid <= 0 or gid <= 0:
        raise RuntimeError('native build acceptance must use the non-root box-control peer')
    request = canonical_request(json.loads(Path(request_json).read_text()))
    if request['build_root_id'] != build_root_id:
        raise RuntimeError('test request resource identity differs')
    observation = observed_over_socket(controller_socket, project_root, job_id, build_root_id)
    if (not observation.get('exists') or not observation.get('transient')
            or not observation.get('invocation_id')):
        raise RuntimeError('native transient build observation is missing or incomplete')
    properties = observation.get('properties') or {}
    if properties.get('User') != str(uid) or properties.get('Group') != str(gid):
        raise RuntimeError('systemd Unit User/Group differ from authenticated socket peer')
    observed_wire = properties.get('ExecStart')
    if (type(observed_wire) is not list or not observed_wire
            or type(observed_wire[0]) is not str or not observed_wire[0].startswith('/')):
        raise RuntimeError('systemd ExecStart evidence missing')
    if '$' in observed_wire[0]:
        raise RuntimeError('unsupported literal-dollar executable path')
    expected_wire = legacy_systemd_argv(
        [observed_wire[0], *request['command'][1:]])
    if observed_wire != expected_wire:
        raise RuntimeError('transient ExecStart does not match original request')
    result = {
        'schema':'root-control-peer-bound-child-acceptance-v1',
        'phase':phase, 'job_id':job_id, 'resource_id':build_root_id,
        'uid':uid, 'gid':gid, 'child_nonroot':True,
        'unit_name':observation['unit_name'],
        'invocation_id':observation['invocation_id'],
        'argv_sha256':hashlib.sha256(
            json.dumps(request['command'],sort_keys=True).encode()).hexdigest(),
        'literal_dollar_argv_preserved': True,
    }
    if phase == 'running':
        if observation.get('active_state') != 'active':
            raise RuntimeError('expected live controller-owned build service')
        identity = observation.get('child_identity')
        if (type(identity) is not dict or
                identity.get('euid') != uid or identity.get('egid') != gid):
            raise RuntimeError('root-control did not authenticate live child EUID/EGID')
        pid = identity.get('pid')
        if type(pid) is not int or pid <= 1:
            raise RuntimeError('invalid live child PID')
        try:
            raw = (Path('/proc')/str(pid)/'cmdline').read_bytes()
        except OSError as exc:
            raise RuntimeError('live child vanished before argv evidence read') from exc
        expected_argv = [observed_wire[0], *request['command'][1:]]
        if raw != b'\0'.join(arg.encode('utf-8') for arg in expected_argv)+b'\0':
            raise RuntimeError('kernel /proc child argv differs from original request')
        result.update(child_pid=pid, child_euid=uid, child_egid=gid,
                      kernel_argv_verified=True,
                      child_argv_sha256=hashlib.sha256(raw).hexdigest())
    else:
        if not expected_invocation_id or observation['invocation_id'] != expected_invocation_id:
            raise RuntimeError('terminal invocation identity differs from live observation')
        if (observation.get('active_state') not in ('inactive','failed')
                or observation.get('ExecMainCode') != 1
                or observation.get('ExecMainStatus') != 0
                or not observation.get('ExecMainExitTimestampMonotonic')
                or observation.get('result') != 'success'
                or observation.get('cgroup_empty') is not True):
            raise RuntimeError('terminal job evidence failed strict controller checks')
        journal_status = (observation.get('journal_barrier') or {}).get('status')
        if journal_status not in ('synchronized','not-enabled'):
            raise RuntimeError('journal barrier terminal evidence is uncertain')
        result.update(terminal_verified=True, journal_status=journal_status,
                      cgroup_empty=True, main_exit_code=0)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--accepted-disposable-build', action='store_true', required=True)
    parser.add_argument('--controller-socket', type=Path,
                        default=Path('/run/zog/root-control.sock'))
    parser.add_argument('--project-root', required=True)
    parser.add_argument('--build-root-id', required=True)
    parser.add_argument('--job-id', required=True)
    parser.add_argument('--request-json', type=Path, required=True)
    parser.add_argument('--phase', choices=('running','terminal'), required=True)
    parser.add_argument('--expected-invocation-id')
    args = parser.parse_args()
    result = acceptance(
        controller_socket=args.controller_socket,
        project_root=args.project_root, build_root_id=args.build_root_id,
        job_id=args.job_id, request_json=args.request_json,
        phase=args.phase, expected_invocation_id=args.expected_invocation_id)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
