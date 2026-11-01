"""Protected issuer execution-admission epoch *source contract*.

Not a deployed systemd admission path. A trusted root-control adapter must
open and attest the fixed root-owned directory and invoke this coordinator
for *both* selected start and host-install revocation, using the SAME stable
flock identity. Until that exact native wiring is reviewed, issuer activation
remains disabled. No general socket/RPC, arbitrary command or root invocation.
"""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import json
import os
import re
import secrets
import stat

SCHEMA = "zog-root-selected-issuer-execution-fence-v1"
LOCK = "selected-issuer-execution.lock"
STATE = "selected-issuer-execution.json"
_PROGRAMS = frozenset(("renew", "inspect", "stage"))
_REQUEST = re.compile(r"[A-Za-z0-9-]{1,40}\Z")
_RUNTIME = re.compile(r"[A-Za-z0-9-]{1,40}\Z")
_BOOT = re.compile(r"[0-9a-f]{32}\Z")
_HEX = re.compile(r"[0-9a-f]{64}\Z")


class IssuerFenceDenied(RuntimeError):
    pass


def _deny():
    raise IssuerFenceDenied("selected issuer execution admission unavailable") from None


def _encode(row):
    return json.dumps(row, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _deny()
        result[key] = value
    return result


def _valid_id(value, expression):
    return type(value) is str and expression.fullmatch(value) is not None


class IssuerExecutionFence:
    """Durable execution intent plus a cross-process root-owner writer lock.

    The dirfd is supplied exclusively by a future fixed-path, independently
    authenticated root owner, not by the broker/caller or over a generic RPC.
    Tests use temporary ownership-matched dirfds. The lock remains held
    throughout the bounded native launch callback: root revocation cannot
    publish while a selected launch is being admitted. Once revoked, no
    operation may start, and cleanup is independently reconciled.
    """

    def __init__(self, protected_dir_fd, *, owner_uid=0):
        if (type(owner_uid) is not int or owner_uid < 0
                or type(protected_dir_fd) is not int or protected_dir_fd < 0):
            _deny()
        self.dirfd = protected_dir_fd
        self.uid = owner_uid
        st = os.fstat(self.dirfd)
        if (not stat.S_ISDIR(st.st_mode) or st.st_uid != owner_uid
                or stat.S_IMODE(st.st_mode) != 0o700):
            _deny()
        self._ensure_lock()

    def _regular(self, fd, mode):
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != self.uid
                or stat.S_IMODE(st.st_mode) != mode or st.st_nlink != 1):
            _deny()
        return st

    def _ensure_lock(self):
        try:
            fd = os.open(LOCK, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=self.dirfd)
        except FileExistsError:
            fd = os.open(LOCK, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC,
                         dir_fd=self.dirfd)
        try:
            self._regular(fd, 0o600)
            os.fsync(fd)
            os.fsync(self.dirfd)
        finally:
            os.close(fd)

    @contextmanager
    def _locked(self):
        try:
            fd = os.open(LOCK, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC,
                         dir_fd=self.dirfd)
            self._regular(fd, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX)
            # Prevent unlink/recreate from silently replacing the lock identity.
            by_path = os.stat(LOCK, dir_fd=self.dirfd, follow_symlinks=False)
            st = os.fstat(fd)
            if (st.st_dev, st.st_ino) != (by_path.st_dev, by_path.st_ino):
                _deny()
            yield
        except OSError:
            _deny()
        finally:
            if "fd" in locals():
                fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)

    def _read(self):
        try:
            fd = os.open(STATE, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                         dir_fd=self.dirfd)
        except FileNotFoundError:
            return None
        except OSError:
            _deny()
        try:
            st = self._regular(fd, 0o600)
            if not 0 < st.st_size <= 262144:
                _deny()
            raw = os.read(fd, 262145)
            if len(raw) != st.st_size:
                _deny()
        finally:
            os.close(fd)
        try:
            row = json.loads(raw, object_pairs_hook=_unique,
                             parse_constant=lambda _: _deny())
            if _encode(row) != raw:
                _deny()
        except (ValueError, TypeError, UnicodeError, OverflowError):
            _deny()
        if (type(row) is not dict or set(row) != {
                "schema", "authority_commit_sha256", "boot_id", "epoch",
                "revoked", "operations"} or row["schema"] != SCHEMA
                or not _valid_id(row["authority_commit_sha256"], _HEX)
                or not _valid_id(row["boot_id"], _BOOT)
                or type(row["epoch"]) is not int or row["epoch"] < 1
                or type(row["revoked"]) is not bool
                or type(row["operations"]) is not dict):
            _deny()
        for request_id, op in row["operations"].items():
            if (not _valid_id(request_id, _REQUEST) or type(op) is not dict
                    or set(op) != {"program", "epoch", "phase", "boot_id",
                                    "runtime_id", "invocation_id"}
                    or op["program"] not in _PROGRAMS
                    or type(op["epoch"]) is not int
                    or not 1 <= op["epoch"] <= row["epoch"]
                    or not _valid_id(op["boot_id"], _BOOT)
                    or op["phase"] not in {"admission-uncertain", "running",
                                          "cancel-pending", "terminal"}
                    or (op["runtime_id"] is not None
                        and not _valid_id(op["runtime_id"], _RUNTIME))
                    or (op["invocation_id"] is not None
                        and not _valid_id(op["invocation_id"], _BOOT))):
                _deny()
        return row

    def _write(self, row):
        raw = _encode(row)
        if len(raw) > 262144:
            _deny()
        name = ".selected-issuer-fence-" + secrets.token_hex(16)
        fd = None
        try:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=self.dirfd)
            self._regular(fd, 0o600)
            if os.write(fd, raw) != len(raw):
                _deny()
            os.fsync(fd)
            os.close(fd)
            fd = None
            os.replace(name, STATE, src_dir_fd=self.dirfd, dst_dir_fd=self.dirfd)
            os.fsync(self.dirfd)
        except OSError:
            _deny()
        finally:
            if fd is not None:
                os.close(fd)
            try:
                os.unlink(name, dir_fd=self.dirfd)
            except FileNotFoundError:
                pass

    def initialize(self, *, trusted_commit_sha256, boot_id):
        """One-time protected installer creation; never resets an old ledger."""
        if (not _valid_id(trusted_commit_sha256, _HEX)
                or not _valid_id(boot_id, _BOOT)):
            _deny()
        with self._locked():
            row = self._read()
            if row is not None:
                if row["authority_commit_sha256"] != trusted_commit_sha256:
                    _deny()
                return row
            row = {"schema": SCHEMA, "authority_commit_sha256": trusted_commit_sha256,
                   "boot_id": boot_id, "epoch": 1, "revoked": False,
                   "operations": {}}
            self._write(row)
            return row

    def admit(self, *, request_id, program, boot_id, trusted_commit_sha256,
              native_launch):
        """Under protected lock: intent fsync -> bounded launch -> receipt fsync.

        If native_launch raises or acknowledgement is lost, the durable
        admission-uncertain record blocks re-execution of this request.
        """
        if (not _valid_id(request_id, _REQUEST) or program not in _PROGRAMS
                or not _valid_id(boot_id, _BOOT)
                or not _valid_id(trusted_commit_sha256, _HEX)
                or not callable(native_launch)):
            _deny()
        with self._locked():
            row = self._read()
            if (row is None or row["revoked"] or row["boot_id"] != boot_id
                    or row["authority_commit_sha256"] != trusted_commit_sha256
                    or request_id in row["operations"]
                    or any(op["phase"] in ("admission-uncertain", "cancel-pending")
                           for op in row["operations"].values())):
                _deny()
            op = {"program": program, "epoch": row["epoch"],
                  "phase": "admission-uncertain", "boot_id": boot_id,
                  "runtime_id": None, "invocation_id": None}
            row["operations"][request_id] = op
            self._write(row)
            # This callback must be root-control's selected, bounded systemd
            # admission, NEVER arbitrary Python supplied by a broker.
            outcome = native_launch(request_id=request_id, program=program,
                                    epoch=row["epoch"], boot_id=boot_id)
            if (type(outcome) is not dict
                    or set(outcome) != {"request_id", "runtime_id",
                                        "invocation_id", "program"}
                    or outcome["request_id"] != request_id
                    or outcome["program"] != program
                    or not _valid_id(outcome["runtime_id"], _RUNTIME)
                    or not _valid_id(outcome["invocation_id"], _BOOT)):
                _deny()
            op["phase"] = "running"
            op["runtime_id"] = outcome["runtime_id"]
            op["invocation_id"] = outcome["invocation_id"]
            self._write(row)
            return dict(op)

    def revoke(self, *, publish_pending_revocation):
        """Serialize with admit; persist revocation BEFORE any stop/cleanup.

        Native host-install MUST create its irreversible pending marker under
        this same writer lock. No user-supplied approval/paths are accepted by
        the real root adapter. Revoke is idempotent, never clears state.
        """
        if not callable(publish_pending_revocation):
            _deny()
        with self._locked():
            row = self._read()
            if row is None:
                _deny()
            if row["revoked"]:
                return row
            # Commit the irrevocable deny FIRST, while holding the same
            # lock as launch. If the subsequent tombstone publication fails
            # or crashes, this ledger remains terminal, not launchable.
            row["revoked"] = True
            row["epoch"] += 1
            for op in row["operations"].values():
                if op["phase"] != "terminal":
                    op["phase"] = "cancel-pending"
            self._write(row)
            if publish_pending_revocation() is not True:
                _deny()
            return row

    def reboot(self, *, new_boot_id):
        """Mark all nonterminal operations for cleanup; never relaunch them."""
        if not _valid_id(new_boot_id, _BOOT):
            _deny()
        with self._locked():
            row = self._read()
            if row is None:
                _deny()
            if row["boot_id"] != new_boot_id:
                row["boot_id"] = new_boot_id
                row["epoch"] += 1
                for op in row["operations"].values():
                    if op["phase"] != "terminal":
                        op["phase"] = "cancel-pending"
                self._write(row)
            return row

    def reconcile(self, *, request_id, verify_stopped_and_clean):
        """An independent root observation is required before terminal ACK."""
        if not _valid_id(request_id, _REQUEST) or not callable(verify_stopped_and_clean):
            _deny()
        with self._locked():
            row = self._read()
            if (row is None or request_id not in row["operations"]):
                _deny()
            op = row["operations"][request_id]
            if op["phase"] == "terminal":
                return dict(op)
            # An ambiguous launch may have executed before a lost result.
            # Do not guess absence or choose a replacement request identity.
            op["phase"] = "cancel-pending"
            self._write(row)
            observed = verify_stopped_and_clean(
                request_id=request_id, original_boot_id=op["boot_id"],
                runtime_id=op["runtime_id"], invocation_id=op["invocation_id"],
                epoch=op["epoch"])
            if observed is not True:
                _deny()
            op["phase"] = "terminal"
            self._write(row)
            return dict(op)
