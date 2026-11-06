# Copyright (c) 2026 Alex Black.
"""Bounded deployment wrapper for keyless, original-event capture.

Shared-host administration is trusted. This service does not sign, submit,
initialize checkpoints or turn capture receipts into accepted authority.
"""
import fcntl
import json
import os
from pathlib import Path
import stat
import threading
import time

from .graphical_task_c_webhook_capture import capture_wsgi

MAX_FILES = 4096
MAX_BYTES = 64 * 1024 * 1024
RECEIPT_RESERVE = 2 * 65536


def protected_read(path, *, owner, max_size):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner
                or info.st_nlink != 1 or info.st_mode & 0o022
                or not 1 <= info.st_size <= max_size):
            raise ValueError('invalid capture input')
        raw = os.read(fd, max_size + 1)
        if len(raw) != info.st_size:
            raise ValueError('changed capture input')
        return raw
    finally:
        os.close(fd)


class CaptureApplication:
    def __init__(self, policy, secret, directory):
        if (type(policy) is not dict or set(policy) != {'repository_id', 'actor_id', 'actor'}
                or type(policy['repository_id']) is not int or policy['repository_id'] <= 0
                or type(policy['actor_id']) is not int or policy['actor_id'] <= 0
                or type(policy['actor']) is not str or not policy['actor']
                or type(secret) is not bytes or not 32 <= len(secret) <= 512):
            raise ValueError('invalid capture configuration')
        self.policy, self.secret = policy, secret
        self.directory = Path(directory)
        info = os.lstat(self.directory)
        if (not self.directory.is_absolute() or not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.geteuid() or info.st_mode & 0o077):
            raise ValueError('invalid capture directory')
        self.thread_lock = threading.Lock()

    def __call__(self, environ, start_response):
        def busy():
            start_response('503 Service Unavailable', [('Content-Type', 'text/plain')])
            return [b'capture unavailable; no authority issued\n']
        # Serialize quota accounting and create-only publication, including
        # overlapping workers during reload. Never remove an uncertain receipt.
        if not self.thread_lock.acquire(blocking=False):
            return busy()
        fd = None
        try:
            fd = os.open(self.directory / '.capture.lock',
                         os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600):
                return busy()
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            count = total = 0
            for path in self.directory.iterdir():
                if path.name == '.capture.lock':
                    continue
                s = os.lstat(path)
                if not stat.S_ISREG(s.st_mode) or s.st_nlink != 1:
                    return busy()
                count += 1
                total += s.st_size
                if count >= MAX_FILES or total + RECEIPT_RESERVE > MAX_BYTES:
                    return busy()
            return capture_wsgi(environ, start_response, policy=self.policy,
                                secret=self.secret, directory=self.directory,
                                now=int(time.time()))
        except OSError:
            return busy()
        finally:
            if fd is not None:
                os.close(fd)
            self.thread_lock.release()


def create_app():
    credentials = Path(os.environ['CREDENTIALS_DIRECTORY'])
    policy = json.loads(protected_read(credentials / 'policy.json',
                                      owner=os.geteuid(), max_size=4096))
    secret = protected_read(Path(os.environ['CREDENTIALS_DIRECTORY']) / 'webhook.hmac',
                            owner=os.geteuid(), max_size=512)
    return CaptureApplication(policy, secret, '/var/lib/zog-github-capture')
