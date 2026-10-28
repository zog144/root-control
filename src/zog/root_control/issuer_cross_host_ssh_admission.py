"""Read-only, root-controlled admission of real station SSH key -> bridge UID.

The expected key fingerprint field in cross-host-station.json is NOT proof of
sshd admission. Check sshd's effective Match User configuration and the unique
root-owned authorized_keys file before any socket/service activation.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess

from . import issuer_cross_host as cross

_COMMAND = "issuer-cloudflare-read-v1"
_DENY = "station-ssh-bridge-admission-unavailable"
_KEY = re.compile(r"[A-Za-z0-9+/]+={0,2}\Z")
OPTIONS = "restrict,command=\"issuer-cloudflare-read-v1\""
_DISABLED = ("passwordauthentication", "kbdinteractiveauthentication",
             "challengeresponseauthentication", "hostbasedauthentication",
             "gssapiauthentication", "allowtcpforwarding", "allowagentforwarding",
             "allowstreamlocalforwarding", "x11forwarding", "permittty",
             "permittunnel", "permituserenvironment", "permituserrc")
_NOT_ALLOWED = {"yes", "local", "remote", "all"}


def _deny():
    raise cross.CrossHostDenied(_DENY) from None


def _effective(raw):
    try:
        if type(raw) is not bytes or len(raw) > 32768:
            _deny()
        lines = raw.decode("ascii").splitlines()
        items = {}
        for line in lines:
            key, sep, value = line.partition(" ")
            key = key.strip().lower()
            value = value.strip()
            if not sep or not key or not value or key in items:
                _deny()
            items[key] = value
        return items
    except (UnicodeError, ValueError):
        _deny()


def verify(effective, keys, *, account, uid, gid, fingerprint, authorized_keys_path,
           forced_command):
    """Pure check of *effective* sshd -T and root-owned key bytes.

    Native installer must additionally verify that its invocation of sshd -T
    uses the real selected service executable, configuration and exact Match.
    """
    if (type(account) is not str
            or cross._USER.fullmatch(account) is None
            or type(uid) is not int or uid < 1000
            or type(gid) is not int or gid < 1000
            or type(fingerprint) is not str or cross._SHA.fullmatch(fingerprint) is None
            or type(authorized_keys_path) is not str
            or not authorized_keys_path.startswith("/etc/zog/")
            or type(forced_command) is not str
            or not re.fullmatch(
                r"/[A-Za-z0-9_./-]+ -I -m zog\.root_control\.issuer_cross_host ssh-bridge",
                forced_command)
            or ".." in forced_command.split(" ")[0].split("/")):
        _deny()
    cfg = _effective(effective)
    if (cfg.get("pubkeyauthentication") != "yes"
            or cfg.get("authenticationmethods") != "publickey"
            or cfg.get("authorizedkeysfile") != authorized_keys_path
            or cfg.get("authorizedkeyscommand") != "none"
            or cfg.get("forcecommand") != forced_command):
        _deny()
    for setting in _DISABLED:
        # Absent settings are not safe: caller must supply effective sshd -T,
        # never a handpicked section or a template.
        if cfg.get(setting) not in ("no", "none"):
            _deny()
    if cfg.get("permitopen", "none") != "none" or cfg.get("permitlisten", "none") != "none":
        _deny()
    if type(keys) is not bytes or not 1 <= len(keys) <= 4096:
        _deny()
    try:
        raw = keys.decode("ascii").splitlines()
        if len(raw) != 1:
            _deny()
        parts = raw[0].split()
        if len(parts) != 3 or parts[:2] != [OPTIONS, "ssh-ed25519"]:
            _deny()
        if not _KEY.fullmatch(parts[2]):
            _deny()
        blob = base64.b64decode(parts[2], validate=True)
        if (len(blob) != 51 or blob[:15] != b"\x00\x00\x00\x0bssh-ed25519"
                or blob[15:19] != b"\x00\x00\x00\x20"
                or base64.b64encode(blob).decode("ascii") != parts[2]):
            _deny()
        identity = "SHA256:" + base64.b64encode(
            hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")
        if identity != fingerprint:
            _deny()
    except (UnicodeError, ValueError, binascii.Error):
        _deny()
    return dict(status="verified-static-ssh-admission",
                account=account, peer_uid=uid, peer_gid=gid,
                ssh_key_fingerprint=fingerprint, authorized_keys_count=1,
                installed_module_attested=False, ssh_connection_tested=False)


def inspect(*, sshd_binary, sshd_config, account, authorized_keys_path,
            forced_command):
    """Root-only readback of installed sshd match and dedicated key namespace.

    Does not edit sshd files, create an account or start any network listener.
    """
    if os.geteuid() != 0:
        _deny()
    binding = cross._station_binding()
    try:
        passwd = pwd.getpwnam(account)
        if (passwd.pw_uid != binding["peer_uid"]
                or passwd.pw_gid != binding["peer_gid"] or passwd.pw_uid < 1000
                or passwd.pw_name != account):
            _deny()
        for path in (sshd_binary, sshd_config, authorized_keys_path):
            path = Path(path)
            if not path.is_absolute() or ".." in path.parts:
                _deny()
            cross.credentials._check_root_directory(path.parent)
            info = path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                    or info.st_mode & 0o022 or info.st_nlink != 1):
                _deny()
        # The reviewed effective configuration must come from the actual
        # executable and selected config, not an operator-authored sample.
        proc = subprocess.run(
            [str(sshd_binary), "-T", "-f", str(sshd_config),
             "-C", "user=" + account + ",host=localhost,addr=127.0.0.1"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=5, check=False,
            env={"PATH": "/usr/sbin:/usr/bin:/bin", "LANG": "C"})
        if proc.returncode != 0:
            _deny()
        data = cross._root_regular(authorized_keys_path, mode=0o600, max_bytes=4096)
        result = verify(
            proc.stdout, data, account=account, uid=passwd.pw_uid,
            gid=passwd.pw_gid, fingerprint=binding["ssh_key_fingerprint"],
            authorized_keys_path=authorized_keys_path,
            forced_command=forced_command)
        if cross._station_binding() != binding:
            _deny()
        return result
    except (OSError, ValueError, subprocess.SubprocessError, KeyError):
        _deny()
