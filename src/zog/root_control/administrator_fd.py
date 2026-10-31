"""Source-only Linux SCM_RIGHTS boundary for protected administrator credentials.

This primitive does not install sockets, adopt keys, start Django or grant
receipt-signing authority. Both peers must be independently selected by the
protected installer; never derive ExpectedPeer or operation from wire input.
"""
from __future__ import annotations

from dataclasses import dataclass
import array
import fcntl
import hmac
import json
import os
import socket
import stat
import struct
import uuid

SCHEMA = "zog-station-admin-fd-handoff-v1"
_FIELDS = frozenset({"schema", "request_id", "delivery_id", "authorization_id",
                     "credential_revision", "account_id"})
MAX_FRAME = 1024
MAX_SECRET = 1024
_MAX_ANCILLARY_FDS = 8


class ProtectedFdDenied(ValueError):
    pass


def _deny():
    raise ProtectedFdDenied("protected-admin-fd-unavailable") from None


@dataclass(frozen=True)
class ExpectedPeer:
    """Independently pinned process identity, never supplied by the sender."""
    pid: int
    uid: int
    gid: int
    start_ticks: int
    cgroup: str


def process_identity(pid: int):
    """Read /proc evidence; native installer must attest installed unit and PID."""
    if type(pid) is not int or pid <= 0:
        _deny()
    try:
        stats = open(f"/proc/{pid}/stat", "rb").read(4096)
        tail = stats[stats.rfind(b")") + 2:].split()
        start = int(tail[19])  # field 22 (tail begins at field 3)
        lines = open(f"/proc/{pid}/cgroup", "r", encoding="ascii").read().splitlines()
        unified = [line[3:] for line in lines if line.startswith("0::")]
        if len(unified) != 1 or not unified[0].startswith("/"):
            _deny()
        return start, unified[0]
    except (OSError, ValueError, IndexError, UnicodeError):
        _deny()


def peer_verified(sock: socket.socket, expected: ExpectedPeer):
    """Enforce SO_PEERCRED plus PID starttime and exact cgroup, fail closed."""
    if (not isinstance(expected, ExpectedPeer)
        or any(type(x) is not int or x < 0 for x in
               (expected.pid, expected.uid, expected.gid, expected.start_ticks))
        or expected.pid == 0 or expected.start_ticks == 0
        or type(expected.cgroup) is not str or not expected.cgroup.startswith("/")):
        _deny()
    try:
        if sock.family != socket.AF_UNIX or sock.type & 0xf != socket.SOCK_SEQPACKET:
            _deny()
        pid, uid, gid = struct.unpack("3i", sock.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
        observed = process_identity(pid)
        if (pid, uid, gid) != (expected.pid, expected.uid, expected.gid) or observed != (
                expected.start_ticks, expected.cgroup):
            _deny()
    except (OSError, ValueError, struct.error):
        _deny()


def operation_frame(*, request_id: str, delivery_id: str,
                    authorization_id: str, credential_revision: int, account_id: int):
    for item in (request_id, delivery_id, authorization_id):
        if type(item) is not str:
            _deny()
        try:
            if str(uuid.UUID(item)) != item:
                _deny()
        except ValueError:
            _deny()
    if (type(credential_revision) is not int or credential_revision <= 0
            or type(account_id) is not int or account_id <= 0):
        _deny()
    data = {"schema": SCHEMA, "request_id": request_id, "delivery_id": delivery_id,
            "authorization_id": authorization_id, "credential_revision": credential_revision,
            "account_id": account_id}
    frame = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    if len(frame) > MAX_FRAME:
        _deny()
    return frame


def _secret_fd(fd: int):
    if type(fd) is not int or fd < 3:
        _deny()
    try:
        info = os.fstat(fd)
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        seals = fcntl.fcntl(fd, fcntl.F_GET_SEALS)
        required = (fcntl.F_SEAL_SEAL | fcntl.F_SEAL_WRITE |
                    fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 0
            or flags & os.O_ACCMODE != os.O_RDONLY
            or seals & required != required
            or not 0 < info.st_size <= MAX_SECRET):
            _deny()
    except OSError:
        _deny()


def send_secret_fd(sock: socket.socket, fd: int, *, receiver: ExpectedPeer, frame: bytes):
    """One sealed read-only FD, one datagram; no secret bytes in control frame."""
    if type(frame) is not bytes or not 0 < len(frame) <= MAX_FRAME:
        _deny()
    _secret_fd(fd)
    peer_verified(sock, receiver)
    try:
        count = sock.sendmsg([frame], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                       array.array("i", [fd]).tobytes())])
        if count != len(frame):
            _deny()
        peer_verified(sock, receiver)
    except OSError:
        _deny()


def receive_secret_fd(sock: socket.socket, *, broker: ExpectedPeer, frame: bytes):
    """Receive once, close every unwanted FD, verify peer again and return owned FD.

    Caller MUST close the returned FD. No secret is read or persisted here.
    """
    if type(frame) is not bytes or not 0 < len(frame) <= MAX_FRAME:
        _deny()
    peer_verified(sock, broker)
    descriptors = []
    try:
        # SO_PEERCRED alone reflects socket connection time. Require
        # SCM_CREDENTIALS on the actual datagram too, rejecting inherited
        # post-fork socket endpoints with a substituted sender process.
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        data, ancillary, flags, _ = sock.recvmsg(
            MAX_FRAME + 1,
            socket.CMSG_SPACE(_MAX_ANCILLARY_FDS * array.array("i").itemsize)
            + socket.CMSG_SPACE(struct.calcsize("3i")),
            socket.MSG_CMSG_CLOEXEC)
        unexpected = False
        senders = []
        for level, kind, raw in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS:
                if len(raw) != struct.calcsize("3i"):
                    unexpected = True
                else:
                    senders.append(struct.unpack("3i", raw))
            elif level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                if len(raw) % array.array("i").itemsize:
                    unexpected = True
                    continue
                part = array.array("i")
                part.frombytes(raw)
                descriptors.extend(part)
            else:
                unexpected = True
        if (unexpected or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
            or not hmac.compare_digest(data, frame) or len(descriptors) != 1
            or senders != [(broker.pid, broker.uid, broker.gid)]):
            _deny()
        if process_identity(senders[0][0]) != (broker.start_ticks, broker.cgroup):
            _deny()
        peer_verified(sock, broker)
        _secret_fd(descriptors[0])
        fd = descriptors.pop()
        return fd
    except OSError:
        _deny()
    finally:
        for fd in descriptors:
            try:
                os.close(fd)
            except OSError:
                pass

# Control-only recovery deliberately carries no descriptor or password.
_RECOVER = b"zog-admin-recover-v1\\0"


def send_recovery(sock: socket.socket, *, receiver: ExpectedPeer, frame: bytes):
    if type(frame) is not bytes or not 0 < len(frame) <= MAX_FRAME:
        _deny()
    peer_verified(sock, receiver)
    try:
        payload = _RECOVER + frame
        if sock.sendmsg([payload]) != len(payload):
            _deny()
        peer_verified(sock, receiver)
    except OSError:
        _deny()


def receive_recovery(sock: socket.socket, *, broker: ExpectedPeer, frame: bytes):
    if type(frame) is not bytes or not 0 < len(frame) <= MAX_FRAME:
        _deny()
    peer_verified(sock, broker)
    descriptors = []
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        payload, ancillary, flags, _ = sock.recvmsg(
            len(_RECOVER) + MAX_FRAME + 1,
            socket.CMSG_SPACE(_MAX_ANCILLARY_FDS * array.array("i").itemsize)
            + socket.CMSG_SPACE(struct.calcsize("3i")),
            socket.MSG_CMSG_CLOEXEC)
        senders = []
        unexpected = False
        for level, kind, raw in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                part = array.array("i")
                part.frombytes(raw[:len(raw) // part.itemsize * part.itemsize])
                descriptors.extend(part)
                unexpected = True
            elif level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS:
                if len(raw) != struct.calcsize("3i"):
                    unexpected = True
                else:
                    senders.append(struct.unpack("3i", raw))
            else:
                unexpected = True
        if (flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or unexpected
            or senders != [(broker.pid, broker.uid, broker.gid)]
            or not hmac.compare_digest(payload, _RECOVER + frame)):
            _deny()
        if process_identity(senders[0][0]) != (broker.start_ticks, broker.cgroup):
            _deny()
        peer_verified(sock, broker)
    except OSError:
        _deny()
    finally:
        for fd in descriptors:
            os.close(fd)
