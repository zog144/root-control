"""Separately retained monotonic file checkpoint for graphical owner.

The protected checkpoint directory must be installed on an independent mount
and must not be writable by the gateway principal. This guarantees resistance
to rollback of gateway-local state, but not rollback of BOTH protected media.
A real native admission must verify an external nonrollbackable trust anchor.
"""
from __future__ import annotations

import fcntl
import hashlib
import os
import stat
from contextlib import contextmanager

from . import graphical_operation_owner_source as source
from .graphical_native_owner import _read_one, _write_once, _checked_file, hold, LOCK

CLAIMS = "claims"
REVOCATION = "revoked.json"
CHECKPOINT_SCHEMA = "zog-graphical-independent-send-checkpoint-v1"


class SeparateDurableCheckpoint:
    def __init__(self, path, *, owner_uid=None, gateway_volume_dev=None,
                 owner_ledger_dev=None):
        self.uid = os.geteuid() if owner_uid is None else owner_uid
        self.root = os.open(path, os.O_RDONLY | os.O_DIRECTORY |
                            os.O_NOFOLLOW | os.O_CLOEXEC)
        st = os.fstat(self.root)
        if (not stat.S_ISDIR(st.st_mode) or st.st_uid != self.uid or
                stat.S_IMODE(st.st_mode) != 0o700):
            hold()
        if (gateway_volume_dev is not None and
                st.st_dev == gateway_volume_dev):
            hold()
        if (owner_ledger_dev is not None and
                st.st_dev == owner_ledger_dev):
            hold()
        self.dir = os.open(CLAIMS, os.O_RDONLY | os.O_DIRECTORY |
                           os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.root)
        child = os.fstat(self.dir)
        if (not stat.S_ISDIR(child.st_mode) or
                child.st_uid != self.uid or
                stat.S_IMODE(child.st_mode) != 0o700):
            hold()
        lock = self._open_lock()
        self._identity = (os.fstat(lock).st_dev, os.fstat(lock).st_ino)
        os.close(lock)

    def _open_lock(self):
        fd = os.open(LOCK, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=self.root)
        _checked_file(fd, self.uid)
        return fd

    @contextmanager
    def locked(self):
        fd = self._open_lock()
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            a = os.fstat(fd)
            b = os.stat(LOCK, dir_fd=self.root, follow_symlinks=False)
            if (a.st_dev, a.st_ino) != self._identity or (
                    b.st_dev, b.st_ino) != self._identity:
                hold()
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def claim_once(self, scope_digest, operation_id, request_digest):
        if (not source.match(scope_digest, source.SHA) or
                not source.match(operation_id, source.H32) or
                not source.match(request_digest, source.SHA)):
            hold()
        with self.locked():
            if _read_one(self.root, REVOCATION, self.uid) is not None:
                hold()
            if _read_one(self.dir, operation_id + ".json", self.uid) is not None:
                hold()  # Even same-byte replay is denied; lost ACK is inspect only.
            _write_once(self.dir, operation_id + ".json",
                        {"schema": CHECKPOINT_SCHEMA,
                         "scope_sha256": scope_digest,
                         "operation_id": operation_id,
                         "request_sha256": request_digest}, self.uid)

    def revoke(self, scope_digest):
        if not source.match(scope_digest, source.SHA):
            hold()
        with self.locked():
            if _read_one(self.root, REVOCATION, self.uid) is not None:
                hold()
            _write_once(self.root, REVOCATION, {"schema": CHECKPOINT_SCHEMA,
                                                "scope_sha256": scope_digest,
                                                "revoked": True}, self.uid)

    def inspect_current(self, scope_digest):
        if not source.match(scope_digest, source.SHA):
            hold()
        # To count as a *current* monotonic witness, each inspection must
        # prove the same independently pinned checkpoint source and the
        # separately installed mount identity, not caller data. A missing
        # checkpoint is never equivalent to an empty gateway journal.
        with self.locked():
            rev = _read_one(self.root, REVOCATION, self.uid)
            if rev is not None and rev.get("scope_sha256") != scope_digest:
                hold()
            return {"revoked": rev is not None}

    def inspect_claim(self, scope_digest, operation_id, request_digest):
        with self.locked():
            item = _read_one(self.dir, operation_id + ".json", self.uid)
            if item is None or item != {
                "schema": CHECKPOINT_SCHEMA, "scope_sha256": scope_digest,
                "operation_id": operation_id, "request_sha256": request_digest,
            }:
                hold()
            return dict(item)
