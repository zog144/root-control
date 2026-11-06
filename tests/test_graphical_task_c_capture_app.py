import io
import json
import os
import threading

import pytest

from zog.root_control import graphical_task_c_capture_app as module


def app(tmp_path):
    tmp_path.chmod(0o700)
    return module.CaptureApplication({'repository_id': 1, 'actor_id': 2, 'actor': 'actor'},
                                     b'x' * 32, tmp_path)


def call(application):
    status = []
    body = b''.join(application({'REQUEST_METHOD': 'GET'}, lambda s, h: status.append(s)))
    return status[0], body


def test_invalid_http_never_creates_receipt(tmp_path):
    assert call(app(tmp_path))[0] == '403 Forbidden'
    assert list(tmp_path.glob('*.json')) == []


def test_quota_holds_without_deleting_old_evidence(tmp_path, monkeypatch):
    a = app(tmp_path)
    receipt = tmp_path / 'old.json'
    receipt.write_text('original evidence')
    monkeypatch.setattr(module, 'MAX_FILES', 1)
    assert call(a)[0] == '503 Service Unavailable'
    assert receipt.read_text() == 'original evidence'


def test_separate_workers_share_nonblocking_lock(tmp_path, monkeypatch):
    a, b = app(tmp_path), app(tmp_path)
    entered, release = threading.Event(), threading.Event()
    def hold(e, start_response, **kwargs):
        entered.set()
        assert release.wait(3)
        start_response('202 Accepted', [])
        return [b'fixture']
    monkeypatch.setattr(module, 'capture_wsgi', hold)
    worker = threading.Thread(target=lambda: call(a))
    worker.start()
    assert entered.wait(3)
    try:
        assert call(b)[0] == '503 Service Unavailable'
    finally:
        release.set()
        worker.join(3)
    assert not worker.is_alive()


def test_symlink_in_spool_holds(tmp_path):
    a = app(tmp_path)
    (tmp_path / 'receipt.json').symlink_to('/etc/passwd')
    assert call(a)[0] == '503 Service Unavailable'


def test_secret_rejects_link_and_writable_input(tmp_path):
    p = tmp_path / 'secret'
    p.write_bytes(b'x' * 32)
    p.chmod(0o600)
    assert module.protected_read(p, owner=os.getuid(), max_size=32) == b'x' * 32
    p.chmod(0o666)
    with pytest.raises(ValueError):
        module.protected_read(p, owner=os.getuid(), max_size=32)
    link = tmp_path / 'link'
    link.symlink_to(p)
    with pytest.raises(OSError):
        module.protected_read(link, owner=os.getuid(), max_size=32)
