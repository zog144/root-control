"""Bounded root-control ingress, peer admission and raw mount denial fixtures.

No real privileged socket, systemd job, mount or host identity is modified.
"""
from concurrent.futures import ThreadPoolExecutor
from threading import BoundedSemaphore
import json
import socket
import struct
import time

import pytest

from zog.root_control import daemon, protocol


def _service():
    return daemon.RootControlDaemon(
        "/run/zog/root-control.sock", systemd_backend=object(),
        controller_uid=12001,
    )


def _message(value):
    data = json.dumps(value).encode()
    return struct.pack("!I", len(data)) + data


def test_privileged_raw_mount_and_unmount_are_not_exposed(monkeypatch):
    calls = []
    monkeypatch.setattr(daemon, "mount", lambda *a: calls.append(("mount", a)), raising=False)
    monkeypatch.setattr(daemon, "unmount", lambda *a: calls.append(("unmount", a)), raising=False)
    service = _service()
    for request in (
        {"operation": "mount", "source": "/", "target": "/tmp/target",
         "filesystem": "bind", "flags": 4096},
        {"operation": "unmount", "target": "/"},
    ):
        with pytest.raises(ValueError, match="raw mount RPC is disabled"):
            service.handle(request)
    assert calls == []


@pytest.mark.parametrize("frame", [
    b"\x00\x00\x00\x00",
    struct.pack("!I", protocol.MAX_MESSAGE + 1),
    _message([]),
    _message(None),
    _message("ping"),
    _message({"operation": "ping", "operation2": "ping"})[:-1],
    b"\x00\x00\x00\x22" + b'{"operation":"ping","operation":"mount"}',
    b"\x00\x00\x00\x13" + b'{"operation":NaN}',
    b"\x00\x00\x00\x03" + b"\xff\xfe!",
])
def test_invalid_frames_fail_closed(frame):
    a, b = socket.socketpair()
    try:
        b.settimeout(0.15)
        a.sendall(frame)
        a.shutdown(socket.SHUT_WR)
        with pytest.raises((ValueError, UnicodeError, ConnectionError, TimeoutError,
                            json.JSONDecodeError)):
            protocol.decode(b, deadline=time.monotonic() + 0.3)
    finally:
        a.close()
        b.close()


@pytest.mark.parametrize("value", [[], None, "ping", {"operation": 3},
                                   {"operation": None}, {"operation": "/etc"},
                                   {"operation": "x" * 65}])
def test_invalid_request_shape_never_reaches_mutation(value):
    with pytest.raises(ValueError):
        _service()._request_operation(value)


def test_wrong_uid_rejected_before_receiving_frame(monkeypatch):
    service = _service()
    a, b = socket.socketpair()
    try:
        monkeypatch.setattr(service, "_authorize_peer",
                            lambda conn: (_ for _ in ()).throw(PermissionError("wrong uid")))
        # No complete frame is transmitted; rejecting the peer cannot wait for one.
        admission = BoundedSemaphore(1)
        assert admission.acquire(blocking=False)
        service._admit(b, (None, None), (None, None), admission, time.monotonic())
        a.settimeout(0.2)
        answer = protocol.decode(a, deadline=time.monotonic() + 0.2)
        assert answer == {"ok": False, "error": "root-control request rejected"}
        assert admission.acquire(blocking=False)
        admission.release()
    finally:
        a.close()


def test_stalled_frame_does_not_delay_valid_ping_or_read_only_inspection(monkeypatch):
    service = _service()
    monkeypatch.setattr(service, "_authorize_peer", lambda _: None)
    monkeypatch.setattr(daemon, "_INGRESS_DEADLINE_SECONDS", 0.65)
    service.handle = lambda req: {"ok": True, "result": req["operation"]}
    first, slow = socket.socketpair()
    second, valid = socket.socketpair()
    third, read = socket.socketpair()
    slots = (BoundedSemaphore(8), BoundedSemaphore(2))
    admission = BoundedSemaphore(daemon._INGRESS_WORKERS)
    try:
        with (ThreadPoolExecutor(max_workers=4) as ingress,
              ThreadPoolExecutor(max_workers=1) as mutation,
              ThreadPoolExecutor(max_workers=2) as logs):
            workers = (mutation, logs)
            assert service._enqueue(slow, ingress, workers, slots, admission)
            first.sendall(b"\x00")  # incomplete length; stalls only one ingress slot
            started = time.monotonic()
            assert service._enqueue(valid, ingress, workers, slots, admission)
            assert service._enqueue(read, ingress, workers, slots, admission)
            second.sendall(_message({"operation": "ping"}))
            third.sendall(_message({"operation": "application_logs"}))
            second.settimeout(0.3)
            third.settimeout(0.3)
            assert protocol.decode(second)["result"] == "ping"
            assert protocol.decode(third)["result"] == "application_logs"
            assert time.monotonic() - started < 0.5
    finally:
        first.close()
        second.close()
        third.close()


def test_ingress_capacity_rejects_fifth_without_unbounded_queue(monkeypatch):
    service = _service()
    monkeypatch.setattr(service, "_authorize_peer", lambda _: None)
    monkeypatch.setattr(daemon, "_INGRESS_DEADLINE_SECONDS", 0.25)
    admission = BoundedSemaphore(daemon._INGRESS_WORKERS)
    clients = []
    try:
        with (ThreadPoolExecutor(max_workers=4) as ingress,
              ThreadPoolExecutor(max_workers=1) as mutations,
              ThreadPoolExecutor(max_workers=2) as reads):
            workers = (mutations, reads)
            slots = (BoundedSemaphore(8), BoundedSemaphore(2))
            for _ in range(4):
                a, b = socket.socketpair()
                clients.append(a)
                assert service._enqueue(b, ingress, workers, slots, admission)
            overflow_client, overflow_server = socket.socketpair()
            clients.append(overflow_client)
            start = time.monotonic()
            assert not service._enqueue(overflow_server, ingress, workers, slots, admission)
            overflow_client.settimeout(0.2)
            assert protocol.decode(overflow_client) == {
                "ok": False, "error": "root-control admission busy"
            }
            assert time.monotonic() - start < 0.2
    finally:
        for client in clients:
            client.close()


def test_completed_mutations_preserve_serial_single_worker_execution(monkeypatch):
    service = _service()
    monkeypatch.setattr(service, "_authorize_peer", lambda _: None)
    events = []
    def work(req):
        events.append(("start", req["operation"]))
        time.sleep(0.015)
        events.append(("finish", req["operation"]))
        return {"ok": True}
    service.handle = work
    clients = []
    try:
        with (ThreadPoolExecutor(max_workers=4) as ingress,
              ThreadPoolExecutor(max_workers=1) as mutations,
              ThreadPoolExecutor(max_workers=2) as reads):
            workers = (mutations, reads)
            slots = (BoundedSemaphore(8), BoundedSemaphore(2))
            admission = BoundedSemaphore(4)
            for i in range(3):
                a, b = socket.socketpair()
                clients.append(a)
                a.sendall(_message({"operation": "systemd_stop", "unit": str(i)}))
                assert service._enqueue(b, ingress, workers, slots, admission)
                # The single executor ensures no overlapping privileged actions.
            for client in clients:
                assert protocol.decode(client)["ok"] is True
            assert events == [("start", "systemd_stop"), ("finish", "systemd_stop")] * 3
    finally:
        for client in clients:
            client.close()
