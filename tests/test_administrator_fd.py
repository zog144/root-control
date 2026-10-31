"""Linux source fixtures: no root service, real account or live credential."""
import array
from contextlib import contextmanager
from dataclasses import replace
import fcntl
import os
import socket
import uuid

import pytest
from zog.root_control import administrator_fd as broker


def peer():
    start, cgroup = broker.process_identity(os.getpid())
    return broker.ExpectedPeer(os.getpid(), os.getuid(), os.getgid(), start, cgroup)


def frame():
    return broker.operation_frame(
        request_id=str(uuid.uuid4()), delivery_id=str(uuid.uuid4()),
        authorization_id=str(uuid.uuid4()), credential_revision=4, account_id=73)


@contextmanager
def sealed(*, readonly=True, size=32, do_seal=True):
    original = os.memfd_create("synthetic-admin-source-only", os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC)
    handle = None
    try:
        os.write(original, b"z" * size)
        if do_seal:
            fcntl.fcntl(original, fcntl.F_ADD_SEALS,
                        fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW |
                        fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        if readonly:
            handle = os.open(f"/proc/self/fd/{original}", os.O_RDONLY | os.O_CLOEXEC)
        else:
            handle = os.dup(original)
        yield handle
    finally:
        if handle is not None:
            os.close(handle)
        os.close(original)


@pytest.mark.skipif(not hasattr(os, "memfd_create") or not hasattr(socket, "SCM_RIGHTS"),
                    reason="Linux SCM_RIGHTS and memfd required")
def test_one_verified_sealed_readonly_fd_over_real_unix_seqpacket():
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    with left, right, sealed() as fd:
        operation = frame()
        broker.send_secret_fd(left, fd, receiver=peer(), frame=operation)
        received = broker.receive_secret_fd(right, broker=peer(), frame=operation)
        try:
            assert received != fd
            assert os.pread(received, 32, 0) == b"z" * 32
            assert not os.get_inheritable(received)
        finally:
            os.close(received)


@pytest.mark.parametrize("change", ["uid", "gid", "pid", "start_ticks", "cgroup"])
def test_wrong_peer_identity_fails_before_fd_transfer(change):
    with socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET) as pair:
        left, right = pair
        value = peer()
        invalid = replace(value, **{change: getattr(value, change) + ("/wrong" if change == "cgroup" else 1)})
        with sealed() as fd, pytest.raises(broker.ProtectedFdDenied):
            broker.send_secret_fd(left, fd, receiver=invalid, frame=frame())
        with pytest.raises(broker.ProtectedFdDenied):
            broker.receive_secret_fd(right, broker=invalid, frame=frame())


@pytest.mark.parametrize("readonly,do_seal,size", [
    (False, True, 32), (True, False, 32), (True, True, 0), (True, True, 1025),
])
def test_wrong_descriptor_is_refused(readonly, do_seal, size):
    with socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET) as (left, right):
        with sealed(readonly=readonly, do_seal=do_seal, size=size) as fd:
            with pytest.raises(broker.ProtectedFdDenied):
                broker.send_secret_fd(left, fd, receiver=peer(), frame=frame())


def test_missing_extra_and_mismatched_fd_and_frame_fail_closed():
    operation = frame()
    with socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET) as (left, right):
        left.sendmsg([operation])
        with pytest.raises(broker.ProtectedFdDenied):
            broker.receive_secret_fd(right, broker=peer(), frame=operation)
    with socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET) as (left, right):
        with sealed() as fd:
            left.sendmsg([operation], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [fd, fd]))])
            with pytest.raises(broker.ProtectedFdDenied):
                broker.receive_secret_fd(right, broker=peer(), frame=operation)
    with socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET) as (left, right):
        with sealed() as fd:
            broker.send_secret_fd(left, fd, receiver=peer(), frame=operation)
            with pytest.raises(broker.ProtectedFdDenied):
                broker.receive_secret_fd(right, broker=peer(), frame=frame())


def test_wrong_socket_type_and_operation_identity_refused():
    with socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM) as (left, right):
        with sealed() as fd, pytest.raises(broker.ProtectedFdDenied):
            broker.send_secret_fd(left, fd, receiver=peer(), frame=frame())
    with pytest.raises(broker.ProtectedFdDenied):
        broker.operation_frame(
            request_id="not-a-uuid", delivery_id=str(uuid.uuid4()),
            authorization_id=str(uuid.uuid4()), credential_revision=1, account_id=3)
    with pytest.raises(broker.ProtectedFdDenied):
        broker.operation_frame(
            request_id=str(uuid.uuid4()), delivery_id=str(uuid.uuid4()),
            authorization_id=str(uuid.uuid4()), credential_revision=True, account_id=3)
