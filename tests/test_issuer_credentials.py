"""Issuer-only Cloudflare installation: no station reader or generic RPC required."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import stat
import time
import uuid

import pytest

from zog.box_control.project import Project
from zog.root_control import issuer_credentials as bridge

TOKEN = b"CF_" + b"A" * 36


def approval(project):
    return {
        "schema": bridge.SCHEMA, "state": "approved", "project": str(project.path),
        "certificate_id": "station-web",
        "assignment_id": str(uuid.uuid4()),
        "assignment_revision": 1,
        "credential_id": str(uuid.uuid4()),
        "credential_revision": 1,
        "zone_id": "cloudflare_zone_01", "zone_name": "example.org",
        "grant_id": "b" * 32, "storage_id": "a" * 32,
        "policy_sha256": "c" * 64, "receipt_sha256": "d" * 64,
        "expires_at": int(time.time()) + 3600,
    }


def sandbox(tmp_path, monkeypatch):
    project = Project(tmp_path / "project")
    parent = project.mounts_dir / "persistent" / ("a" * 32) / "certificate-data"
    parent.mkdir(parents=True)
    parent.chmod(0o700)
    root = tmp_path / "owner-authorizations"
    root.mkdir()
    approved = approval(project)
    grant = {"uid": os.getuid(), "gid": os.getgid(), "grant_id": "b" * 32}
    monkeypatch.setattr(bridge, "AUTH_ROOT", root)
    monkeypatch.setattr(bridge, "_require_root", lambda: None)
    monkeypatch.setattr(bridge, "_quiet", lambda _p: None)
    monkeypatch.setattr(bridge, "_authorization", lambda _p, path: (dict(approved), grant))
    # In the CI sandbox the receipt files have the runner UID, not root;
    # verify actual private-file DAC while simulating only that root ownership.
    original_read = bridge._read_protected
    def read(path, *, missing_ok=False):
        if not path.exists():
            if missing_ok:
                return None
            raise bridge.IssuerCredentialError("protected authorization absent")
        return json.loads(path.read_text())
    monkeypatch.setattr(bridge, "_read_protected", read)
    return project, approved, root, parent


def token_fd(token=TOKEN):
    read, write = os.pipe()
    os.write(write, token)
    os.close(write)
    return read


def install(project, token=TOKEN):
    descriptor = token_fd(token)
    try:
        return bridge.install_from_fd(project.path, descriptor)
    finally:
        os.close(descriptor)


def test_installs_atomically_to_only_issuer_private_storage(tmp_path, monkeypatch):
    project, auth, root, parent = sandbox(tmp_path, monkeypatch)
    result = install(project)
    assert result["status"] == "installed"
    assert result["replayed"] is False
    target = parent / "dns" / "cloudflare.ini"
    assert target.read_bytes() == b"dns_cloudflare_api_token = " + TOKEN + b"\n"
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert (target.stat().st_uid, target.stat().st_gid) == (os.getuid(), os.getgid())
    assert stat.S_IMODE(target.parent.stat().st_mode) == 0o700
    assert not list(parent.glob("*.pending"))
    receipts = list(root.glob("*.installed.json"))
    assert len(receipts) == 1
    saved = receipts[0].read_text()
    assert TOKEN.decode() not in saved
    assert auth["receipt_sha256"] in saved
    assert not list(root.glob("*.pending.json"))


def test_idempotent_replay_does_not_replace_original_token(tmp_path, monkeypatch):
    project, auth, root, parent = sandbox(tmp_path, monkeypatch)
    install(project)
    original = (parent / "dns/cloudflare.ini").stat().st_ino
    outcome = install(project, token=b"CF_" + b"B" * 36)
    assert outcome["replayed"]
    assert (parent / "dns/cloudflare.ini").stat().st_ino == original
    assert TOKEN in (parent / "dns/cloudflare.ini").read_bytes()


@pytest.mark.parametrize("contents", [
    b"bad\nnew-line", b" ", b"ABCD", b"A" * 4097,
    b"CF_" + b"A" * 32 + b"\r\n",
])
def test_invalid_token_rejected_and_not_persisted(tmp_path, monkeypatch, contents):
    project, auth, root, parent = sandbox(tmp_path, monkeypatch)
    with pytest.raises(bridge.IssuerCredentialError, match="credential bytes"):
        install(project, contents)
    assert not (parent / "dns/cloudflare.ini").exists()
    assert not list(root.glob("*.pending.json"))


def test_existing_symlink_is_not_overwritten(tmp_path, monkeypatch):
    project, auth, root, parent = sandbox(tmp_path, monkeypatch)
    (parent / "dns").mkdir(mode=0o700)
    victim = tmp_path / "victim"
    victim.write_text("unchanged")
    (parent / "dns/cloudflare.ini").symlink_to(victim)
    with pytest.raises(bridge.IssuerCredentialError, match="incomplete"):
        install(project)
    assert victim.read_text() == "unchanged"
    assert (parent / "dns/cloudflare.ini").is_symlink()
    assert list(root.glob("*.pending.json"))


@pytest.mark.parametrize("mode", [0o755, 0o750, 0o777])
def test_private_mount_dac_drift_blocks_install(tmp_path, monkeypatch, mode):
    project, auth, root, parent = sandbox(tmp_path, monkeypatch)
    parent.chmod(mode)
    with pytest.raises(bridge.IssuerCredentialError, match="incomplete"):
        install(project)
    assert not (parent / "dns/cloudflare.ini").exists()
    assert list(root.glob("*.pending.json"))


def test_ledger_rollback_and_same_revision_conflict(tmp_path, monkeypatch):
    project, auth, root, parent = sandbox(tmp_path, monkeypatch)
    install(project)
    auth["assignment_revision"] = 0
    with pytest.raises(bridge.IssuerCredentialError, match="rollback"):
        install(project)
    auth["assignment_revision"] = 1
    auth["credential_id"] = str(uuid.uuid4())
    with pytest.raises(bridge.IssuerCredentialError, match="revision conflict"):
        install(project)


def test_rotation_requires_higher_revision_and_preserves_storage(tmp_path, monkeypatch):
    project, auth, root, parent = sandbox(tmp_path, monkeypatch)
    install(project)
    auth["assignment_revision"] += 1
    auth["credential_revision"] += 1
    auth["receipt_sha256"] = "e" * 64
    new_token = b"CF_" + b"Z" * 36
    result = install(project, new_token)
    assert not result["replayed"]
    assert (parent / "dns/cloudflare.ini").read_bytes().endswith(new_token + b"\n")
    assert not list(root.glob("*.pending.json"))


def test_interrupted_audit_barrier_retains_pending_fence(tmp_path, monkeypatch):
    project, auth, root, parent = sandbox(tmp_path, monkeypatch)
    original = bridge._fsync
    def fault(path):
        if Path(path) == root and list(root.glob("*.installed.json")):
            raise OSError("injected barrier fault")
        return original(path)
    monkeypatch.setattr(bridge, "_fsync", fault)
    with pytest.raises(bridge.IssuerCredentialError, match="incomplete"):
        install(project)
    assert list(root.glob("*.pending.json"))
    assert bridge.inspect(project.path)["status"] == "blocked"
