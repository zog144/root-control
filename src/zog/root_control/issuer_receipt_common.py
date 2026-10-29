"""Transport-independent root-owned credential receipt file/JSON admission.

No network, SSH, credential delivery or implicit file creation.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat

from . import issuer_credentials as credentials


class CredentialReceiptDenied(credentials.IssuerCredentialError):
    """A fixed, secret-free denial from the selected credential receiver."""


def deny():
    raise CredentialReceiptDenied("approved HTTPS credential receipt unavailable") from None


def pairs(values):
    out = {}
    for name, value in values:
        if name in out:
            deny()
        out[name] = value
    return out


def root_regular(path, *, mode=0o600, max_bytes=8192):
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        deny()
    try:
        credentials._check_root_directory(path.parent)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW |
                     os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                    or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != mode
                    or info.st_nlink != 1 or info.st_size > max_bytes):
                deny()
            raw = os.read(fd, max_bytes + 1)
            if len(raw) != info.st_size or len(raw) > max_bytes:
                deny()
            return raw
        finally:
            os.close(fd)
    except (OSError, ValueError):
        deny()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")
