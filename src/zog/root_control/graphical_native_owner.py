"""Selected graphical owner durable filesystem and fixed-command boundary.

Source implementation; installing, credential custody, rollback-independent
checkpoint and AWS execution require host-install + native acceptance.
Caller cannot choose paths, sender, keys or original-operation authority.
"""
from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
from contextlib import contextmanager

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import graphical_operation_owner_source as contract

REQUEST_LIMIT = 16384
LOCK = ".selected-graphical-owner.lock"
CLAIMS = "claims"
RESULTS = "results"
REVOKED = "revoked.json"
RPC_SCHEMA = "zog-graphical-owner-native-ipc-v1"
HEX32 = re.compile(r"[a-f0-9]{32}\Z")


def hold():
    raise contract.OperationDenied("protected graphical native owner unavailable or uncertain")


def _checked_file(fd, uid, mode=0o600):
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
            info.st_uid != uid or stat.S_IMODE(info.st_mode) != mode):
        hold()
    return info


def _read_one(directory_fd, name, uid, max_bytes=8192):
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=directory_fd)
    except FileNotFoundError:
        return None
    try:
        size = _checked_file(fd, uid).st_size
        if not 0 < size <= max_bytes:
            hold()
        raw = os.read(fd, max_bytes + 1)
        if len(raw) != size:
            hold()
        return strict(raw)
    finally:
        os.close(fd)


def strict(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= REQUEST_LIMIT:
        hold()

    def unique(pairs):
        item = {}
        for key, value in pairs:
            if key in item:
                hold()
            item[key] = value
        return item

    try:
        data = json.loads(raw, object_pairs_hook=unique,
                          parse_constant=lambda _: hold())
        if type(data) is not dict or contract.canonical(data) != raw:
            hold()
    except (ValueError, TypeError, UnicodeError, OverflowError):
        hold()
    return data


def _write_once(fd, name, value, uid):
    raw = contract.canonical(value)
    if not 0 < len(raw) <= 8192:
        hold()
    try:
        item = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                       os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
    except FileExistsError:
        hold()
    try:
        _checked_file(item, uid)
        if os.write(item, raw) != len(raw):
            hold()
        os.fsync(item)
    finally:
        os.close(item)
    os.fsync(fd)


class ProtectedLedger:
    """Root-owned independently retained storage; not gateway-writable.

    Source persistence does NOT prove rollback resistance of the protected
    volume itself. An independently installed monotonic highwater authority
    must be checked before any native SendCommand.
    """
    def __init__(self, directory, *, owner_uid=None, external_checkpoint=None):
        self.uid = os.geteuid() if owner_uid is None else owner_uid
        self.root = os.open(directory, os.O_RDONLY | os.O_DIRECTORY |
                           os.O_NOFOLLOW | os.O_CLOEXEC)
        st = os.fstat(self.root)
        if (not stat.S_ISDIR(st.st_mode) or st.st_uid != self.uid or
                stat.S_IMODE(st.st_mode) != 0o700):
            hold()
        self.claims = self._subdir(CLAIMS)
        self.results = self._subdir(RESULTS)
        self.lock_inode = None
        self.checkpoint = external_checkpoint
        if self.checkpoint is None:
            # A file-only storage domain cannot make a native send decision.
            hold()
        fd = self._lock_fd()
        try:
            self.lock_inode = (os.fstat(fd).st_dev, os.fstat(fd).st_ino)
        finally:
            os.close(fd)

    def _subdir(self, name):
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                     os.O_CLOEXEC, dir_fd=self.root)
        st = os.fstat(fd)
        if (not stat.S_ISDIR(st.st_mode) or st.st_uid != self.uid or
                stat.S_IMODE(st.st_mode) != 0o700):
            hold()
        return fd

    def _lock_fd(self):
        fd = os.open(LOCK, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=self.root)
        _checked_file(fd, self.uid)
        return fd

    @contextmanager
    def locked(self):
        fd = self._lock_fd()
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            a = os.fstat(fd)
            b = os.stat(LOCK, dir_fd=self.root, follow_symlinks=False)
            if ((a.st_dev, a.st_ino) != (b.st_dev, b.st_ino) or
                    (a.st_dev, a.st_ino) != self.lock_inode):
                hold()
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _state(self, operation_id):
        if not contract.match(operation_id, HEX32):
            hold()
        name = operation_id + ".json"
        return (_read_one(self.claims, name, self.uid),
                _read_one(self.results, name, self.uid))

    def claim(self, req, *, scope, preapproved_sha):
        """Only call under locked(). No auto retry, including partial files."""
        if (req["operation_id"] not in scope["approved"] or
                scope["approved"][req["operation_id"]] != preapproved_sha or
                contract.digest(req) != preapproved_sha):
            hold()
        if _read_one(self.root, REVOKED, self.uid) is not None:
            hold()
        previous, result = self._state(req["operation_id"])
        if previous is not None or result is not None:
            hold()
        row = {"schema": "zog-graphical-owner-durable-claim-v1",
               "operation_id": req["operation_id"],
               "request_sha256": preapproved_sha,
               "outcome": "CLAIMED_UNCERTAIN"}
        # Independent checkpoint MUST irrevocably commit the exact original
        # claim before the local file and before any SSM send. Its validation
        # must remain under this same owner serialization domain.
        self.checkpoint.claim_once(scope["identity"], req["operation_id"],
                                   preapproved_sha)
        _write_once(self.claims, req["operation_id"] + ".json", row, self.uid)
        return row

    def record(self, req, command_id):
        if (type(command_id) is not str or not 1 <= len(command_id) <= 128):
            hold()
        prior, current = self._state(req["operation_id"])
        if (prior is None or current is not None or
                prior["request_sha256"] != contract.digest(req)):
            hold()
        _write_once(self.results, req["operation_id"] + ".json",
                    {"schema": "zog-graphical-owner-durable-result-v1",
                     "operation_id": req["operation_id"],
                     "request_sha256": contract.digest(req),
                     "outcome": "SENT_ORIGINAL", "command_id": command_id}, self.uid)

    def revoke(self, scope):
        if _read_one(self.root, REVOKED, self.uid) is not None:
            hold()
        self.checkpoint.revoke(scope["identity"])
        _write_once(self.root, REVOKED,
                    {"schema": "zog-graphical-owner-revoked-v1",
                     "scope_sha256": scope["identity"],
                     "status": "revoked"}, self.uid)

    def inspect(self, req, *, scope):
        self.checkpoint.inspect_current(scope["identity"])
        prior, result = self._state(req["operation_id"])
        if prior is None or prior.get("request_sha256") != contract.digest(req):
            hold()
        return {"operation_id": req["operation_id"],
                "request_sha256": contract.digest(req),
                "outcome": result["outcome"] if result else "CLAIMED_UNCERTAIN",
                "command_id": result["command_id"] if result else None,
                "revoked": _read_one(self.root, REVOKED, self.uid) is not None}


class SelectedOwner:
    """No network client from caller; fixed command selected by installer."""
    def __init__(self, ledger, *, installed, pinned_operator_key,
                 observation_signer, sender):
        # The native executable MUST construct these from independently
        # installed immutable paths, not RPC fields or environment variables.
        if (type(installed) is not dict or set(installed) !=
            {"scope", "approved", "identity", "commands"} or
            not isinstance(observation_signer, Ed25519PrivateKey) or
            type(pinned_operator_key) is not bytes or len(pinned_operator_key) != 32):
            hold()
        self.ledger = ledger
        self.installed = installed
        self.operator_key = pinned_operator_key
        self.signer = observation_signer
        self.sender = sender

    def submit(self, request, signed_approval, *, now):
        req = contract.validate_request(request)
        grant = contract.verify_original_operator_approval(
            req, signed_approval,
            externally_pinned_operator_key=self.operator_key,
            expected_approval_id=self.installed["commands"][req["operation_id"]]["approval_id"],
            now=now)
        with self.ledger.locked():
            if (contract.scope_from_request(req) != self.installed["scope"] or
                    grant["request_sha256"] != self.installed["approved"].get(req["operation_id"])):
                hold()
            self.ledger.claim(req, scope=self.installed,
                              preapproved_sha=grant["request_sha256"])
            # Command is looked up by installed original operation ID, not
            # selected from the request, a socket path or a gateway script.
            command = self.installed["commands"][req["operation_id"]]
            ident = self.sender.send_fixed(req["operation_id"], command)
            self.ledger.record(req, ident)
            return {"outcome": "SENT_ORIGINAL", "command_id": ident}

    def revoke(self, signed_grant, *, now):
        contract.verify_signed_revocation_approval(
            self.installed["scope"], signed_grant,
            externally_pinned_operator_key=self.operator_key,
            expected_approval_id=self.installed["identity"][:32], now=now)
        with self.ledger.locked():
            self.ledger.revoke(self.installed)
            return {"status": "revoked"}

    def observe(self, request, nonce):
        req = contract.validate_request(request)
        if not contract.match(nonce, contract.NONCE):
            hold()
        with self.ledger.locked():
            if contract.scope_from_request(req) != self.installed["scope"]:
                hold()
            row = self.ledger.inspect(req, scope=self.installed)
            body = {"schema": "zog-graphical-owner-native-observation-v1",
                    "scope_sha256": self.installed["identity"],
                    "nonce": nonce, **row}
            sig = self.signer.sign(b"zog-graphical-owner-native-observation-v1\0" +
                                   contract.canonical(body))
            return {**body, "signature_ed25519":
                    base64.b64encode(sig).decode("ascii")}


def peer_uid_gid(connection, expected_uid, expected_gid):
    if (connection.family != socket.AF_UNIX or
            (connection.type & 0xf) != socket.SOCK_SEQPACKET):
        hold()
    try:
        peer = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        pid, uid, gid = struct.unpack("3i", peer)
    except (OSError, ValueError, struct.error):
        hold()
    if (pid < 1 or uid != expected_uid or gid != expected_gid):
        hold()
    return pid


def serve_one(connection, owner, *, expected_uid, expected_gid, now):
    """One complete seqpacket, strict typed request, bounded response.

    Native service must pin connection socket inode, requester cgroup/boot
    and executable in addition to SO_PEERCRED before calling this.
    """
    peer_uid_gid(connection, expected_uid, expected_gid)
    raw, anc, flags, _ = connection.recvmsg(REQUEST_LIMIT + 1, 0)
    if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or anc:
        hold()
    value = strict(raw)
    if (set(value) != {"schema", "action", "request", "approval", "nonce"} or
            value["schema"] != RPC_SCHEMA or
            value["action"] not in ("submit", "revoke", "observe")):
        hold()
    if value["action"] == "submit":
        if value["nonce"] is not None:
            hold()
        response = owner.submit(value["request"], value["approval"], now=now)
    elif value["action"] == "revoke":
        if value["request"] is not None or value["nonce"] is not None:
            hold()
        response = owner.revoke(value["approval"], now=now)
    else:
        if value["approval"] is not None:
            hold()
        response = owner.observe(value["request"], value["nonce"])
    raw = contract.canonical(response)
    if len(raw) > 8192 or connection.send(raw) != len(raw):
        hold()
    return response
