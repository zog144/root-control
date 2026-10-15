"""Root-owned station authorization projection and real AF_UNIX request framing."""
import json
import os
from pathlib import Path
import re
import socket
import stat
import threading
import uuid

import pytest

from zog.box_control.project import Project
from zog.root_control import issuer_credentials as credentials
from zog.root_control import issuer_station_transfer as bridge


TOKEN = b"CF_" + b"D" * 40


def approved(project):
    return {
        "schema": credentials.SCHEMA, "state": "approved",
        "project": str(project.path), "certificate_id": "station-web",
        "assignment_id": str(uuid.uuid4()), "assignment_revision": 2,
        "credential_id": str(uuid.uuid4()), "credential_revision": 4,
        "zone_id": "zone1", "zone_name": "example.org",
        "grant_id": "a" * 32, "storage_id": "b" * 32,
        "policy_sha256": "c" * 64, "receipt_sha256": "d" * 64,
        "expires_at": 1800000000,
    }


def harness(tmp_path, monkeypatch):
    project = Project(tmp_path / "project")
    project.state_dir.mkdir(parents=True)
    root = tmp_path / "owner"
    root.mkdir()
    source = approved(project)
    projection = {
        "schema": bridge._PROJECTION_SCHEMA,
        "authorization": dict(source), "origin": "local",
        "installation_id": str(uuid.uuid4()), "host_id": None,
        "account_id": "e" * 32, "owner_user_id": 10,
    }
    monkeypatch.setattr(credentials, "AUTH_ROOT", root)
    monkeypatch.setattr(credentials, "_require_root", lambda: None)
    monkeypatch.setattr(credentials, "_check_root_directory", lambda path: None)
    monkeypatch.setattr(credentials, "_check_lock_info", lambda info: None)
    monkeypatch.setattr(credentials, "_authorization", lambda project, path: (dict(source), {
        "uid": os.getuid(), "gid": os.getgid(), "grant_id": source["grant_id"]
    }))
    monkeypatch.setattr(credentials, "_read_protected",
                        lambda path, missing_ok=False: json.loads(path.read_text()) if path.exists() else None)
    # CI is an unprivileged user. Production chown-to-root and 0440 file
    # validation remain enabled and unmocked in the actual implementation.
    monkeypatch.setattr(bridge.os, "fchown", lambda fd, uid, gid: None)
    def inspect_mock(path, *, gid, mode):
        info = path.lstat()
        assert stat.S_ISREG(info.st_mode)
        assert stat.S_IMODE(info.st_mode) == 0o440
        assert info.st_gid == gid
        assert info.st_nlink == 1
        return json.loads(path.read_text())
    monkeypatch.setattr(bridge, "_private_file", inspect_mock)
    return project, root, source, projection


def projection_fd(value):
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, credentials._canonical(value))
    finally:
        os.close(write_fd)
    return read_fd


def publish(project, value, *, uid=None, gid=None):
    read_fd = projection_fd(value)
    try:
        return bridge.publish_projection(
            project.path, read_fd,
            reader_uid=os.getuid() if uid is None else uid,
            reader_gid=os.getgid() if gid is None else gid,
        )
    finally:
        os.close(read_fd)


def test_exact_nonsecret_projection_and_reader_peer_pins_are_durable(tmp_path, monkeypatch):
    project, root, source, projection = harness(tmp_path, monkeypatch)
    result = publish(project, projection)
    assert result["status"] == "published"
    assert result["authorization_id"] == credentials._authorization_id(source)
    station_path, peer_path = credentials._projection_paths(project)
    assert station_path.read_text().strip() == credentials._canonical(projection).decode()
    assert stat.S_IMODE(station_path.stat().st_mode) == 0o440
    assert stat.S_IMODE(peer_path.stat().st_mode) == 0o600
    assert peer_path.read_text().find(TOKEN.decode()) == -1
    assert bridge._checked_current(project)[0] == result["authorization_id"]


@pytest.mark.parametrize("tamper", [
    lambda v: v.update(account_id="not-hex"),
    lambda v: v.update(origin="managed"),
    lambda v: v.update(host_id=str(uuid.uuid4())),
    lambda v: v.update(another_field="/tmp/arbitrary"),
    lambda v: v["authorization"].update(assignment_revision=3),
    lambda v: v["authorization"].update(state="revoked"),
])
def test_projection_cannot_change_original_root_approval_or_shape(tmp_path, monkeypatch, tamper):
    project, root, source, projection = harness(tmp_path, monkeypatch)
    tamper(projection)
    with pytest.raises(credentials.IssuerCredentialError):
        publish(project, projection)


def test_provision_fences_reader_uid_migration_without_owner_reapproval(tmp_path, monkeypatch):
    project, root, source, projection = harness(tmp_path, monkeypatch)
    publish(project, projection)
    with pytest.raises(credentials.IssuerCredentialError, match="migration"):
        publish(project, projection, uid=os.getuid() + 1)


def test_stale_nonsecret_projection_blocks_socket_token_read(tmp_path, monkeypatch):
    project, root, source, projection = harness(tmp_path, monkeypatch)
    publish(project, projection)
    source["assignment_revision"] += 1
    with pytest.raises(credentials.IssuerCredentialError):
        bridge._checked_current(project)


def test_live_local_socket_request_and_private_fd_transfer(tmp_path, monkeypatch):
    project, root, source, projection = harness(tmp_path, monkeypatch)
    path = tmp_path / "reader.sock"
    monkeypatch.setattr(bridge, "_SOCKET", path)
    publish(project, projection)
    expected = credentials._authorization_id(source)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(path))
    path.chmod(0o600)
    listener.listen(1)
    seen = []
    def station():
        try:
            conn, _ = listener.accept()
            with conn:
                request = bytearray()
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    request.extend(chunk)
                assert request.endswith(b"\n")
                data = json.loads(request)
                seen.append(data)
                conn.sendall(TOKEN[:17])
                conn.sendall(TOKEN[17:])
        finally:
            listener.close()
    worker = threading.Thread(target=station)
    worker.start()
    def check_socket(target, peer):
        info = target.lstat()
        assert stat.S_ISSOCK(info.st_mode)
        assert stat.S_IMODE(info.st_mode) == 0o600
        assert peer["reader_uid"] == os.getuid()
    monkeypatch.setattr(bridge, "_verify_socket", check_socket)
    delivered = []
    def installer(path, token_fd, *, expected_authorization_id):
        delivered.append((credentials._read_token(token_fd), expected_authorization_id))
        return {"schema": credentials.AUDIT_SCHEMA, "status": "installed"}
    monkeypatch.setattr(credentials, "install_from_fd", installer)
    try:
        result = bridge.transfer_and_install(project.path)
    finally:
        worker.join(timeout=5)
    assert not worker.is_alive()
    assert result["status"] == "installed"
    assert delivered == [(TOKEN, expected)]
    assert len(seen) == 1
    assert set(seen[0]) == {"schema", "operation", "authorization_id", "nonce"}
    assert seen[0]["schema"] == bridge._REQUEST_SCHEMA
    assert seen[0]["authorization_id"] == expected
    assert re.fullmatch("[0-9a-f]{32}", seen[0]["nonce"])


def test_unauthorized_socket_response_cannot_install(tmp_path, monkeypatch):
    project, root, source, projection = harness(tmp_path, monkeypatch)
    publish(project, projection)
    monkeypatch.setattr(bridge, "_verify_socket", lambda *_: None)
    def refuse(*args):
        raise credentials.IssuerCredentialError("station vault reader peer identity disagrees")
    monkeypatch.setattr(bridge, "_read_station_socket", refuse)
    monkeypatch.setattr(credentials, "install_from_fd",
                        lambda *args, **kwargs: pytest.fail("secret must not install"))
    with pytest.raises(credentials.IssuerCredentialError, match="peer identity"):
        bridge.transfer_and_install(project.path)
