"""Opt-in build exit barrier. This socket never accepts management operations.

Root-owned registrations authorize one attempt per job. Kernel peer credentials,
pidfd liveness and systemd ControlPID authenticate the *current stop hook*.
Synchronization runs in the broker's host context with a fixed environment.
"""
import json
import os
from pathlib import Path
import re
import select
import socket
import stat
import struct
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
import hashlib

from zog.box_control.durability import replace_json

ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C'}
HELPER = Path('/usr/libexec/zog/journal-wait')
SOCKET = Path('/run/zog-journal-broker/socket')
DIRECTORY = Path('/var/lib/zog/journal-barriers')
TOKEN = re.compile(r'[0-9a-f]{64}\Z')


def boot_id():
    return Path('/proc/sys/kernel/random/boot_id').read_text().strip().replace('-', '')


def trusted_path(path, *, directory=False):
    path = Path(path)
    if not path.is_absolute(): raise ValueError('absolute trusted path required')
    for item in [*reversed(path.parents), path]:
        st = item.lstat()
        if stat.S_ISLNK(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            raise ValueError('untrusted barrier deployment path')
    st = path.stat()
    if directory and not stat.S_ISDIR(st.st_mode): raise ValueError('directory required')
    if not directory and not stat.S_ISREG(st.st_mode): raise ValueError('regular helper required')


def properties(unit):
    # No shell, caller-selected executable or inherited build environment.
    path = '/org/freedesktop/systemd1/unit/' + ''.join(
        c if c.isascii() and c.isalnum() else '_'+format(ord(c),'02x') for c in unit)
    result = {}
    for interface in ('Unit', 'Service'):
        command = ['/usr/bin/busctl', '--system', '--json=short', 'call',
                   'org.freedesktop.systemd1', path, 'org.freedesktop.DBus.Properties',
                   'GetAll', 's', 'org.freedesktop.systemd1.'+interface]
        data = json.loads(subprocess.check_output(command, env=ENV, cwd='/', timeout=.3,
                         stderr=subprocess.DEVNULL))['data'][0]
        result.update({key: value['data'] for key,value in data.items()})
    return result


def synchronize():
    subprocess.run(['/usr/bin/journalctl', '--sync'], env=ENV, cwd='/',
                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, check=True, timeout=.8)


class JournalBarrier:
    def __init__(self, directory=DIRECTORY, socket_path=SOCKET, helper=HELPER):
        self.directory, self.socket_path, self.helper = map(Path, (directory, socket_path, helper))
        self.lock = threading.Lock()
        self.slots = threading.BoundedSemaphore(2)
        self.server = None

    def start(self):
        # Require kernel peer-pidfd support; never fall back to reusable numeric PIDs.
        a,b = socket.socketpair()
        try:
            fd = a.getsockopt(socket.SOL_SOCKET, 77)  # Linux SO_PEERPIDFD
            os.close(fd)
        finally:
            a.close(); b.close()
        trusted_path(self.helper)
        # Reject dynamically linked helpers (ELF program interpreter) at deployment.
        info = subprocess.check_output(['/usr/bin/readelf','-l',str(self.helper)], env=ENV, timeout=5)
        if b'INTERP' in info or not self.helper.stat().st_mode & 0o111:
            raise ValueError('executable static journal-wait required')
        for path in (self.directory, self.socket_path.parent):
            path.mkdir(parents=True, exist_ok=True, mode=0o755)
            trusted_path(path, directory=True)
        # A held deployment lock prevents a second broker unlinking a live socket.
        import fcntl
        self.lease = (self.socket_path.parent/'broker.lock').open('a')
        os.chmod(self.socket_path.parent/'broker.lock', 0o600)
        fcntl.flock(self.lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.socket_path.unlink(missing_ok=True)
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(str(self.socket_path)); os.chmod(self.socket_path, 0o666)
        self.server.listen(8)
        threading.Thread(target=self.serve, daemon=True).start()

    def register(self, unit, uid, job_id):
        if not self.server: raise RuntimeError('journal barrier not started')
        if not re.fullmatch(r'zog-[A-Za-z0-9_.-]+\.service', unit) or type(uid) is not int or uid <= 0:
            raise ValueError('invalid barrier registration')
        token = hashlib.sha256((boot_id()+'\0'+unit+'\0'+job_id).encode()).hexdigest()
        record = dict(schema=1, unit=unit, uid=uid, job_id=job_id, boot_id=boot_id(),
                      status='pending', invocation_id=None)
        path=self.directory/(token+'.json')
        if path.exists():
            previous=json.loads(path.read_text())
            if any(previous[k]!=record[k] for k in ('unit','uid','job_id','boot_id')):
                raise ValueError('barrier identity already bound')
        else:
            replace_json(path, record)
        return token

    def status(self, token):
        if not TOKEN.fullmatch(token): raise ValueError('invalid barrier identity')
        record = json.loads((self.directory/(token+'.json')).read_text())
        return {k:record[k] for k in ('status','boot_id','invocation_id','reason') if k in record}

    def evidence(self, token, *, unit, job_id, uid):
        if not TOKEN.fullmatch(token): raise ValueError('invalid barrier identity')
        record = json.loads((self.directory/(token+'.json')).read_text())
        if any(record.get(k) != v for k,v in dict(unit=unit,job_id=job_id,uid=uid).items()):
            raise ValueError('exit evidence ownership differs')
        snapshot = record.get('exit_evidence')
        if snapshot is None: return None
        if record.get('boot_id') != boot_id(): return None
        if snapshot.get('invocation_id') != record.get('invocation_id'):
            raise ValueError('exit evidence invocation differs')
        return snapshot

    @staticmethod
    def exit_evidence(snapshot, invocation):
        # Read directly from PID1, never from hook arguments or build environment.
        code, status = snapshot.get('ExecMainCode'), snapshot.get('ExecMainStatus')
        ended = snapshot.get('ExecMainExitTimestampMonotonic')
        if type(code) is not int or code not in (1,2,3) or type(status) is not int or status < 0:
            return None
        if type(ended) is not int or ended <= 0: return None
        keys = ('RootDirectory','User','Group','ExitType','Type','Restart',
                'ProtectSystem','KillMode','WorkingDirectory','ExecStart',
                'PrivateNetwork','NoNewPrivileges','CapabilityBoundingSet','RuntimeMaxUSec')
        return dict(invocation_id=invocation, boot_id=boot_id(),
                    ExecMainCode=code, ExecMainStatus=status,
                    ExecMainExitTimestampMonotonic=ended, result=snapshot.get('Result'),
                    properties={k:snapshot.get(k) for k in keys})

    def forget(self, token):
        if not TOKEN.fullmatch(token): raise ValueError('invalid barrier identity')
        from zog.box_control.durability import synchronize_directory
        with self.lock:
            (self.directory/(token+'.json')).unlink(missing_ok=True)
            synchronize_directory(self.directory)

    @staticmethod
    def authenticate(record, pid, uid, snapshot):
        invocation = snapshot.get('InvocationID')
        if isinstance(invocation, list): invocation = bytes(invocation).hex()
        if (uid != record['uid'] or uid == 0 or record['boot_id'] != boot_id()
            or snapshot.get('ControlPID') != pid or snapshot.get('SubState') != 'stop-post'
            or snapshot.get('Id') != record['unit'] or snapshot.get('Transient') is not True
            or not isinstance(invocation,str) or not re.fullmatch('[0-9a-f]{32}', invocation)
            or invocation == '0'*32 or record['invocation_id'] not in (None,invocation)):
            raise PermissionError('not the registered exit hook')
        return invocation

    def handle(self, conn):
        pidfd = None
        try:
            with conn:
                conn.settimeout(.2)
                pid, uid, _ = struct.unpack('3i',conn.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                pidfd = conn.getsockopt(socket.SOL_SOCKET, 77)  # SO_PEERPIDFD, bound to original peer
                poll = select.poll(); poll.register(pidfd, select.POLLIN)
                wire = bytearray()
                while len(wire)<65:
                    chunk=conn.recv(65-len(wire))
                    if not chunk: raise ValueError('incomplete barrier request')
                    wire.extend(chunk)
                token = bytes(wire[:64]).decode('ascii')
                if wire[-1]!=10 or not TOKEN.fullmatch(token): raise ValueError('invalid barrier request')
                path=self.directory/(token+'.json')
                with self.lock:
                    record=json.loads(path.read_text())
                    snapshot=properties(record['unit'])
                    invocation=self.authenticate(record,pid,uid,snapshot)
                    if poll.poll(0): raise PermissionError('exit hook no longer alive')
                    # Repeats cannot trigger another synchronization or bind a new invocation.
                    if record['status'] != 'pending':
                        conn.sendall(b'1' if record['status']=='synchronized' else b'0'); return
                    record.update(status='attempted',invocation_id=invocation)
                    evidence=self.exit_evidence(snapshot,invocation)
                    if evidence is not None: record['exit_evidence']=evidence
                    replace_json(path,record)
                try:
                    synchronize()
                    self.authenticate(record,pid,uid,properties(record['unit']))
                    if poll.poll(0): raise PermissionError('exit hook ended before barrier')
                    record['status']='synchronized'
                except Exception as exc:
                    record['status']='unconfirmed'
                    record['reason'] = ('synchronization-timeout' if isinstance(exc,subprocess.TimeoutExpired) else
                        'hook-identity-lost' if isinstance(exc,PermissionError) else 'synchronization-failed')
                with self.lock:
                    if not path.exists(): raise RuntimeError('barrier was reclaimed')
                    replace_json(path,record)  # Evidence must be saved before acknowledging.
                conn.sendall(b'1' if record['status']=='synchronized' else b'0')
        except Exception:
            # Unknown/hostile peers cannot overwrite another job's evidence.
            pass
        finally:
            if pidfd is not None: os.close(pidfd)

    def serve(self):
        with ThreadPoolExecutor(max_workers=2) as workers:
            while True:
                conn,_=self.server.accept()
                if not self.slots.acquire(blocking=False): conn.close(); continue
                def run(connection):
                    try: self.handle(connection)
                    finally: self.slots.release()
                workers.submit(run,conn)
