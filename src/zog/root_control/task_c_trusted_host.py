"""Trusted-Host Task C: one durable local intent before one SSM submission.

No S3, signers, second AWS role, or independent rollback domain. The installed
Host/service administrator and its root-backed filesystem are trusted. A lost
SendCommand acknowledgement is uncertain, not permission to resend.

The caller must validate the admitted request, compiler target, source, fixed
document and generated script BEFORE calling submit_once. This class only owns
the local once-only send boundary, not request authorization.
"""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat

SCHEMA = "zog-task-c-trusted-host-local-intent-v1"
RESULT_SCHEMA = "zog-task-c-trusted-host-command-v1"
CANCEL_SCHEMA = "zog-task-c-trusted-host-cancel-v1"
DEFAULT_DIRECTORY = "/var/lib/zog-task-c/operations"
OPERATION = re.compile(r"[0-9a-f]{32}\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
INSTANCE = re.compile(r"i-[0-9a-f]{8,17}\Z")
REGION = re.compile(r"[a-z]{2}-[a-z]+-[0-9]\Z")
COMMAND = re.compile(r"[A-Za-z0-9-]{1,128}\Z")
DOCUMENT = "AWS-RunShellScript"


class SubmissionBlocked(RuntimeError):
    """Duplicate, cancelled, unsafe or uncertain local submission."""


def _blocked():
    raise SubmissionBlocked("Task C operation already submitted, cancelled, or uncertain")


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _file(directory, name):
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=directory)
    except FileNotFoundError:
        return None
    except OSError:
        _blocked()
    try:
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1
                or st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o600
                or not 0 < st.st_size <= 8192):
            _blocked()
        raw = os.read(fd, 8193)
        if len(raw) != st.st_size:
            _blocked()
    finally:
        os.close(fd)
    try:
        def unique(pairs):
            row = {}
            for key, value in pairs:
                if key in row:
                    _blocked()
                row[key] = value
            return row
        result = json.loads(raw, object_pairs_hook=unique,
                            parse_constant=lambda _: _blocked())
        if type(result) is not dict or _canonical(result) != raw:
            _blocked()
        return result
    except (ValueError, UnicodeError, TypeError):
        _blocked()


def _write_once(directory, name, row):
    raw = _canonical(row)
    if not 0 < len(raw) <= 8192:
        _blocked()
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
    except OSError:
        _blocked()
    try:
        if os.write(fd, raw) != len(raw):
            _blocked()
        os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(directory)
    if _file(directory, name) != row:
        _blocked()


def intent(*, operation_id, request_sha256, script, target, seconds):
    """Validate a frozen original operation and fixed SSM submission shape."""
    if (type(operation_id) is not str or not OPERATION.fullmatch(operation_id)
            or type(request_sha256) is not str
            or not DIGEST.fullmatch(request_sha256)
            or type(script) is not str or not script
            or len(script.encode("utf-8")) > 32768
            or type(seconds) is not int or not 1 <= seconds <= 21600
            or type(target) is not dict
            or set(target) != {"instance_id", "region", "account_id"}
            or type(target["instance_id"]) is not str
            or not INSTANCE.fullmatch(target["instance_id"])
            or type(target["region"]) is not str
            or not REGION.fullmatch(target["region"])
            or type(target["account_id"]) is not str
            or not re.fullmatch(r"[0-9]{12}\Z", target["account_id"])):
        _blocked()
    return {"schema": SCHEMA, "operation_id": operation_id,
            "request_sha256": request_sha256,
            "script_sha256": hashlib.sha256(script.encode("utf-8")).hexdigest(),
            "target": dict(target), "document": DOCUMENT,
            "execution_timeout_seconds": seconds}


class LocalTaskCJournal:
    """One root-owned directory; flock, O_EXCL and fsync precede SendCommand.

    The Host administrator is trusted; no anti-rollback claim is made. The
    process must be installed under root, using a root-owned 0700 directory.
    The parent is prepared by host-install, not created from remote requests.
    """

    def __init__(self, directory=DEFAULT_DIRECTORY):
        if os.geteuid() != 0:
            _blocked()
        directory = Path(directory)
        if directory.is_symlink():
            _blocked()
        self.directory = directory
        try:
            self.fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY |
                              os.O_NOFOLLOW | os.O_CLOEXEC)
            st = os.fstat(self.fd)
            if (not stat.S_ISDIR(st.st_mode) or st.st_uid != 0
                    or stat.S_IMODE(st.st_mode) != 0o700):
                _blocked()
            self.lock_fd = os.open(".lock", os.O_RDWR | os.O_CREAT |
                                   os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
                                   dir_fd=self.fd)
            lock = os.fstat(self.lock_fd)
            if (not stat.S_ISREG(lock.st_mode) or lock.st_uid != 0
                    or lock.st_nlink != 1
                    or stat.S_IMODE(lock.st_mode) != 0o600):
                _blocked()
            os.fsync(self.fd)
        except OSError:
            self.close()
            _blocked()

    def close(self):
        for name in ("lock_fd", "fd"):
            if hasattr(self, name):
                os.close(getattr(self, name))
                delattr(self, name)

    @contextmanager
    def locked(self):
        # Independent open-file description for concurrent threads/processes.
        fd = os.open(".lock", os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=self.fd)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            first = os.fstat(fd)
            retained = os.fstat(self.lock_fd)
            current = os.stat(".lock", dir_fd=self.fd, follow_symlinks=False)
            if any((item.st_dev, item.st_ino) != (first.st_dev, first.st_ino)
                   for item in (retained, current)):
                _blocked()
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _files(self, operation_id):
        if type(operation_id) is not str or not OPERATION.fullmatch(operation_id):
            _blocked()
        return (operation_id + ".intent.json",
                operation_id + ".command.json",
                operation_id + ".cancel.json")

    def inspect(self, operation_id):
        names = self._files(operation_id)
        with self.locked():
            return tuple(_file(self.fd, name) for name in names)

    def cancel(self, operation_id, reason="operator-cancelled"):
        if type(reason) is not str or not 1 <= len(reason) <= 128:
            _blocked()
        names = self._files(operation_id)
        with self.locked():
            if _file(self.fd, names[2]) is not None:
                _blocked()
            _write_once(self.fd, names[2], {
                "schema": CANCEL_SCHEMA, "operation_id": operation_id,
                "reason": reason})
        # Cancellation stops future sends; it cannot undo an existing AWS send.

    def submit_once(self, *, operation_id, request_sha256, script, target,
                    seconds, sender):
        selected = intent(operation_id=operation_id,
                          request_sha256=request_sha256, script=script,
                          target=target, seconds=seconds)
        if not callable(getattr(sender, "submit_command", None)):
            _blocked()
        if getattr(sender, "instance", target["instance_id"]) != target["instance_id"]:
            _blocked()
        names = self._files(operation_id)
        with self.locked():
            if any(_file(self.fd, name) is not None for name in names):
                _blocked()
            # Intent is durable before the one external side effect.
            _write_once(self.fd, names[0], selected)
            # No automatic retries, including on a lost reply or BaseException.
            command_id = sender.submit_command(script, seconds=seconds)
            if type(command_id) is not str or not COMMAND.fullmatch(command_id):
                _blocked()
            _write_once(self.fd, names[1], {
                "schema": RESULT_SCHEMA, "operation_id": operation_id,
                "request_sha256": request_sha256, "command_id": command_id})
            return command_id
