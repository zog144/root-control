"""Fixed root-owned issuer execution source and lock provenance gate.

The installer must independently verify the *actual* installed root-control
wheel/RECORD; a caller-selected digest or source JSON is never authority. This
module only checks the immutable protected receipt and its binding to the
actual open lock/directory and root-authorized installation commit.
"""
import json
import os
import re
import stat
from .issuer_execution_fence import IssuerFenceDenied, LOCK

NAME = "selected-issuer-execution-provenance.json"
SCHEMA = "zog-host-install-selected-issuer-execution-source-v1"
FIELDS = frozenset((
    "schema", "root_control_revision", "wheel_record_sha256",
    "box_control_revision", "host_id", "installation_id", "state_volume_id",
    "commit_sha256", "directory_dev", "directory_ino",
    "lock_dev", "lock_ino",
))
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


def _deny():
    raise IssuerFenceDenied("selected issuer execution source unavailable") from None


def _pairs(pairs):
    result = {}
    for k, v in pairs:
        if k in result:
            _deny()
        result[k] = v
    return result


def require_installed_provenance(fd, *, root_control_revision,
                                 box_control_revision, commit_sha256,
                                 identities, owner_uid=0):
    """Require exact protected installed source and unchanged lock inode."""
    try:
        directory = os.fstat(fd)
        if (not stat.S_ISDIR(directory.st_mode)
                or directory.st_uid != owner_uid
                or directory.st_gid != owner_uid
                or stat.S_IMODE(directory.st_mode) != 0o700):
            _deny()
        leaf = os.open(NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                       dir_fd=fd)
        try:
            st = os.fstat(leaf)
            if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1
                    or (st.st_uid, st.st_gid) != (owner_uid, owner_uid)
                    or stat.S_IMODE(st.st_mode) != 0o600
                    or not 0 < st.st_size <= 8192):
                _deny()
            raw = os.read(leaf, 8193)
            if len(raw) != st.st_size:
                _deny()
        finally:
            os.close(leaf)
        lock = os.stat(LOCK, dir_fd=fd, follow_symlinks=False)
        if (not stat.S_ISREG(lock.st_mode)
                or (lock.st_uid, lock.st_gid) != (owner_uid, owner_uid)
                or stat.S_IMODE(lock.st_mode) != 0o600
                or lock.st_nlink != 1):
            _deny()
        record = json.loads(raw, object_pairs_hook=_pairs,
                            parse_constant=lambda _: _deny())
        if (type(record) is not dict or set(record) != FIELDS
                or json.dumps(record, sort_keys=True, separators=(",", ":"),
                              ensure_ascii=True).encode("ascii") != raw
                or record.get("schema") != SCHEMA
                or type(record["root_control_revision"]) is not str
                or HEX40.fullmatch(record["root_control_revision"]) is None
                or record["root_control_revision"] != root_control_revision
                or type(record["wheel_record_sha256"]) is not str
                or HEX64.fullmatch(record["wheel_record_sha256"]) is None
                or record["box_control_revision"] != box_control_revision
                or record["commit_sha256"] != commit_sha256
                or any(record[name] != identities[name] for name in
                       ("host_id", "installation_id", "state_volume_id"))
                or any(type(record[name]) is not int or record[name] < 1
                       for name in ("directory_dev", "directory_ino",
                                    "lock_dev", "lock_ino"))
                or (record["directory_dev"], record["directory_ino"]) !=
                    (directory.st_dev, directory.st_ino)
                or (record["lock_dev"], record["lock_ino"]) !=
                    (lock.st_dev, lock.st_ino)):
            _deny()
        return True
    except (OSError, UnicodeError, ValueError, TypeError, KeyError):
        _deny()
