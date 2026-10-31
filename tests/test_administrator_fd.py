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


@contextmanager
def sockets(kind=socket.SOCK_SEQPACKET):
    left, right = socket.socketpair(socket.AF_UNIX, kind)
    try:
        if kind == socket.SOCK_SEQPACKET:
            broker.prepare_receiver_socket(right)
        yield left, right
    finally:
        left.close()
        right.close()


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
        broker.prepare_receiver_socket(right)
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
    with sockets() as (left, right):
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
    with sockets() as (left, right):
        with sealed(readonly=readonly, do_seal=do_seal, size=size) as fd:
            with pytest.raises(broker.ProtectedFdDenied):
                broker.send_secret_fd(left, fd, receiver=peer(), frame=frame())


def test_missing_extra_and_mismatched_fd_and_frame_fail_closed():
    operation = frame()
    with sockets() as (left, right):
        left.sendmsg([operation])
        with pytest.raises(broker.ProtectedFdDenied):
            broker.receive_secret_fd(right, broker=peer(), frame=operation)
    with sockets() as (left, right):
        with sealed() as fd:
            left.sendmsg([operation], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [fd, fd]))])
            with pytest.raises(broker.ProtectedFdDenied):
                broker.receive_secret_fd(right, broker=peer(), frame=operation)
    with sockets() as (left, right):
        with sealed() as fd:
            broker.send_secret_fd(left, fd, receiver=peer(), frame=operation)
            with pytest.raises(broker.ProtectedFdDenied):
                broker.receive_secret_fd(right, broker=peer(), frame=frame())


def test_wrong_socket_type_and_operation_identity_refused():
    with sockets(socket.SOCK_STREAM) as (left, right):
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


def test_recovery_control_requires_exact_peer_and_no_fds():
    operation = frame()
    with sockets() as (left, right):
        broker.send_recovery(left, receiver=peer(), frame=operation)
        broker.receive_recovery(right, broker=peer(), frame=operation)
    with sockets() as (left, right):
        broker.send_recovery(left, receiver=peer(), frame=operation)
        with pytest.raises(broker.ProtectedFdDenied):
            broker.receive_recovery(right, broker=peer(), frame=frame())
    with sockets() as (left, right), sealed() as fd:
        left.sendmsg([broker._RECOVER + operation],
                     [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                       array.array("i", [fd]).tobytes())])
        with pytest.raises(broker.ProtectedFdDenied):
            broker.receive_recovery(right, broker=peer(), frame=operation)


def test_socket_must_preinstall_passcred_before_receiving():
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    with left, right, sealed() as fd:
        operation = frame()
        broker.send_secret_fd(left, fd, receiver=peer(), frame=operation)
        with pytest.raises(broker.ProtectedFdDenied):
            broker.receive_secret_fd(right, broker=peer(), frame=operation)


def committed(operation):
    import json
    values = json.loads(operation)
    return {
        "schema": "zog-station-admin-password-protected-commit-v1",
        "state": "committed-awaiting-host-signed-receipt",
        "request_id": values["request_id"],
        "delivery_id": values["delivery_id"],
        "authorization_id": values["authorization_id"],
        "credential_revision": values["credential_revision"],
        "account_id": values["account_id"],
        "installed_at": 1793470000,
    }


def test_peer_verified_nonsecret_commit_reply_after_django_transaction():
    operation = frame()
    with sockets() as (host, station):
        broker.prepare_receiver_socket(host)
        broker.send_commit(station, receiver=peer(), frame=operation,
                           commit=committed(operation))
        assert broker.receive_commit(host, station=peer(), frame=operation) == committed(operation)


def test_commit_reply_rejects_wrong_operation_and_account_and_fd_smuggling():
    operation = frame()
    with sockets() as (host, station):
        broker.prepare_receiver_socket(host)
        wrong = dict(committed(operation), account_id=100)
        with pytest.raises(broker.ProtectedFdDenied):
            broker.send_commit(station, receiver=peer(), frame=operation, commit=wrong)
        broker.send_commit(station, receiver=peer(), frame=operation,
                           commit=committed(operation))
        with pytest.raises(broker.ProtectedFdDenied):
            broker.receive_commit(host, station=peer(), frame=frame())
    with sockets() as (host, station), sealed() as fd:
        broker.prepare_receiver_socket(host)
        payload = broker._commit_payload(operation, committed(operation))
        station.sendmsg([payload], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                     array.array("i", [fd]).tobytes())])
        with pytest.raises(broker.ProtectedFdDenied):
            broker.receive_commit(host, station=peer(), frame=operation)



@pytest.mark.parametrize("field,value", [
    ("request_id", "00000000-0000-0000-0000-000000000001"),
    ("delivery_id", "00000000-0000-0000-0000-000000000001"),
    ("authorization_id", "00000000-0000-0000-0000-000000000001"),
    ("credential_revision", 9), ("account_id", 999),
    ("state", "ready"), ("schema", "other"), ("installed_at", True),
])
def test_django_commit_reply_denies_foreign_request_revision_and_account(field, value):
    original = frame()
    invalid = dict(committed(original), **{field: value})
    with sockets() as (host, station):
        broker.prepare_receiver_socket(host)
        with pytest.raises(broker.ProtectedFdDenied):
            broker.send_commit(station, receiver=peer(), frame=original, commit=invalid)


def test_recovery_reply_requires_original_operation_and_no_second_secret():
    original = frame()
    durable = committed(original)
    # A lost first reply is not a license to send the FD or change password again.
    with sockets() as (host, station):
        broker.prepare_receiver_socket(host)
        broker.send_commit(station, receiver=peer(), frame=original, commit=durable)
        # Deliberately lose the completed response by closing the channel.
    with sockets() as (host, station):
        broker.prepare_receiver_socket(host)
        broker.send_recovery(host, receiver=peer(), frame=original)
        broker.receive_recovery(station, broker=peer(), frame=original)
        broker.send_commit(station, receiver=peer(), frame=original, commit=durable)
        assert broker.receive_commit(host, station=peer(), frame=original) == durable


def test_duplicate_json_commit_keys_denied_on_receive():
    original = frame()
    payload = broker._commit_payload(original, committed(original))
    # Replay the same canonical outer frame with an extra duplicate inner key.
    import json
    wrapper = json.loads(payload[len(broker._COMMIT):])
    content = json.dumps(wrapper, sort_keys=True, separators=(",", ":")).encode()
    assert content == payload[len(broker._COMMIT):]
    corrupted = payload.replace(b'"account_id":73,', b'"account_id":73,"account_id":999,', 1)
    assert corrupted != payload
    with sockets() as (host, station):
        broker.prepare_receiver_socket(host)
        station.sendmsg([corrupted])
        with pytest.raises(broker.ProtectedFdDenied):
            broker.receive_commit(host, station=peer(), frame=original)


def test_commit_reply_rejects_missing_passcred_and_wrong_peer_epoch():
    original = frame()
    durable = committed(original)
    with sockets() as (host, station):
        broker.send_commit(station, receiver=peer(), frame=original, commit=durable)
        with pytest.raises(broker.ProtectedFdDenied):
            broker.receive_commit(host, station=peer(), frame=original)
    with sockets() as (host, station):
        broker.prepare_receiver_socket(host)
        broker.send_commit(station, receiver=peer(), frame=original, commit=durable)
        wrong = replace(peer(), start_ticks=peer().start_ticks + 1)
        with pytest.raises(broker.ProtectedFdDenied):
            broker.receive_commit(host, station=wrong, frame=original)
