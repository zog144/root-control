"""Pure and socket-level cross-host credential transport regressions.

No real SSH, vault token or host mutation. Native sshd and UID/key mapping are
independent required acceptance gates, not implied by these tests.
"""
import json
import os
from pathlib import Path
import socket
import threading
import uuid

import pytest

from zog.box_control.project import Project
from zog.root_control import issuer_cross_host as cross
from zog.root_control import issuer_credentials as creds


TOKEN = b"CF_" + b"Q" * 42

def sample_request():
    return {
        "schema": cross.SCHEMA, "operation": cross.OPERATION,
        "authorization_id": "a" * 64, "host_id": str(uuid.uuid4()),
        "installation_id": str(uuid.uuid4()), "assignment_id": str(uuid.uuid4()),
        "assignment_revision": 4, "receipt_sha256": "b" * 64,
        "nonce": "c" * 32,
    }

def wire(data):
    return creds._canonical(data) + b"\n"

@pytest.mark.parametrize("tamper", [
    lambda x: x.update(schema="legacy"),
    lambda x: x.update(operation="arbitrary-command"),
    lambda x: x.update(authorization_id="A" * 64),
    lambda x: x.update(assignment_revision=True),
    lambda x: x.update(assignment_revision=0),
    lambda x: x.update(host_id="foreign"),
    lambda x: x.update(nonce="c" * 33),
    lambda x: x.update(destination="/etc/shadow"),
])
def test_request_rejects_unreviewed_selectors(tamper):
    request = sample_request()
    tamper(request)
    with pytest.raises(cross.CrossHostDenied):
        cross._read_request(wire(request))

@pytest.mark.parametrize("raw", [
    b"", b"{}", b"{}\n", b"{garbage}\n",
    b"{\"nonce\":1,\"nonce\":2}\n",
    b"x" * 1025 + b"\n",
])
def test_request_rejects_incomplete_noncanonical_or_oversized_wire(raw):
    with pytest.raises(cross.CrossHostDenied):
        cross._read_request(raw)

def test_valid_request_roundtrip_exact_canonical():
    source = sample_request()
    assert cross._read_request(wire(source)) == source
    with pytest.raises(cross.CrossHostDenied):
        cross._read_request(wire(source).replace(b',"', b', "'))

def binding(request):
    return {
        **{key: request[key] for key in ("authorization_id", "host_id",
            "installation_id", "assignment_id", "assignment_revision", "receipt_sha256")},
        "schema": cross.STATION_SCHEMA,
        "state_volume_id": str(uuid.uuid4()),
        "host_fingerprint": "d" * 64, "registry_id": "test-registry",
        "ssh_key_fingerprint": "SHA256:" + "A" * 43,
        "peer_uid": os.getuid(), "peer_gid": os.getgid(),
        "reader_uid": os.getuid() + 100, "reader_gid": os.getgid() + 100,
        "projection_path": "/etc/zog/issuer-credentials/projection.json",
        "nonce_directory": "/var/lib/zog-issuer-bridge/nonces",
    }

def test_station_binding_denies_payload_authority_substitution(monkeypatch):
    request = sample_request()
    selected = binding(request)
    auth = {
        "schema": creds.SCHEMA, "state": "approved",
        "assignment_id": request["assignment_id"],
        "assignment_revision": request["assignment_revision"],
        "receipt_sha256": request["receipt_sha256"],
    }
    # Real checker compares *full* protected approval, not merely fields
    # supplied by SSH client; fixture supplies a complete opaque frozen shape.
    approved = {name: "value" for name in creds._FIELDS}
    approved.update(auth)
    aid = creds._authorization_id(approved)
    selected["authorization_id"] = aid
    request["authorization_id"] = aid
    projection = {"origin": "managed", "host_id": selected["host_id"],
                  "installation_id": selected["installation_id"],
                  "authorization": approved}
    monkeypatch.setattr(cross.local, "_private_file",
                        lambda *a, **kw: projection)
    assert cross._station_approved(selected, request)["reader_uid"] == selected["reader_uid"]
    for changed in ("host_id", "installation_id", "assignment_id",
                    "authorization_id", "receipt_sha256", "assignment_revision"):
        wrong = dict(request)
        wrong[changed] = str(uuid.uuid4()) if changed in ("host_id", "installation_id", "assignment_id") else (
            request[changed] + 1 if changed == "assignment_revision" else "f" * 64
        )
        with pytest.raises(cross.CrossHostDenied):
            cross._station_approved(selected, wrong)
    projection["origin"] = "local"
    with pytest.raises(cross.CrossHostDenied):
        cross._station_approved(selected, request)

def test_durable_nonce_is_consumed_once_in_root_directory(tmp_path, monkeypatch):
    request = sample_request()
    bound = binding(request)
    nonce_dir = tmp_path / "nonces"
    nonce_dir.mkdir()
    bound["nonce_directory"] = str(nonce_dir)
    monkeypatch.setattr(creds, "_check_root_directory", lambda path: None)
    cross._consume_nonce(bound, request)
    records = list(nonce_dir.iterdir())
    assert len(records) == 1
    assert records[0].read_bytes() == b"used\n"
    assert request["nonce"].encode() not in records[0].read_bytes()
    with pytest.raises(cross.CrossHostDenied):
        cross._consume_nonce(bound, request)
    # Scope remains stable across process restart; the durable record stays.
    assert len(list(nonce_dir.iterdir())) == 1

def test_station_broker_wrong_peer_never_reads_request_or_vault(monkeypatch):
    source = sample_request()
    bound = binding(source)
    bound["peer_uid"] = os.getuid() + 1
    seen = []
    monkeypatch.setattr(cross.local, "_read_station_socket",
                        lambda *a, **kw: seen.append("vault"))
    left, right = socket.socketpair()
    try:
        assert cross._serve_broker_connection(left, bound) is False
        assert seen == []
    finally:
        left.close()
        right.close()

def test_station_broker_consumes_nonce_before_vault_and_returns_only_token(monkeypatch):
    request = sample_request()
    bound = binding(request)
    seen = []
    monkeypatch.setattr(cross, "_station_approved", lambda b, r: (
        seen.append("approval") or {"reader_uid": 44}))
    monkeypatch.setattr(cross, "_consume_nonce", lambda b, r: seen.append("nonce"))
    monkeypatch.setattr(cross.local, "_read_station_socket", lambda *args: (
        seen.append("vault") or TOKEN))
    monkeypatch.setattr(cross, "_station_binding", lambda: bound)
    left, right = socket.socketpair()
    try:
        right.sendall(wire(request))
        right.shutdown(socket.SHUT_WR)
        assert cross._serve_broker_connection(left, bound)
        assert right.recv(8192) == TOKEN
        assert seen == ["approval", "nonce", "vault", "approval"]
    finally:
        left.close()
        right.close()

def test_station_broker_midstream_authorization_rotation_returns_zero_bytes(monkeypatch):
    request = sample_request()
    bound = binding(request)
    monkeypatch.setattr(cross, "_station_approved",
                        lambda b, r: {"reader_uid": 44})
    monkeypatch.setattr(cross, "_consume_nonce", lambda b, r: None)
    monkeypatch.setattr(cross.local, "_read_station_socket", lambda *a: TOKEN)
    monkeypatch.setattr(cross, "_station_binding", lambda: dict(bound, assignment_revision=99))
    left, right = socket.socketpair()
    try:
        right.sendall(wire(request))
        right.shutdown(socket.SHUT_WR)
        assert not cross._serve_broker_connection(left, bound)
        left.close()  # Forced-command wrapper closes the rejected connection.
        right.settimeout(1)
        assert right.recv(8192) == b""
    finally:
        left.close()
        right.close()

def test_client_only_installs_via_fd_after_second_owner_check(tmp_path, monkeypatch):
    project = Project(tmp_path / "project")
    request = sample_request()
    pinned = {"test": "exact-binding"}
    monkeypatch.setattr(creds, "_require_root", lambda: None)
    monkeypatch.setattr(cross, "_client_binding", lambda p: dict(pinned))
    checks = []
    def approved(p, b):
        checks.append(dict(b))
        return request["authorization_id"]
    monkeypatch.setattr(cross, "_client_approved", approved)
    monkeypatch.setattr(cross, "_request", lambda b: wire(request))
    monkeypatch.setattr(cross, "_ssh_token", lambda b, w: TOKEN)
    installed = []
    def install(p, fd, *, expected_authorization_id):
        installed.append((os.read(fd, 8192), expected_authorization_id))
        return {"status": "installed"}
    monkeypatch.setattr(creds, "install_from_fd", install)
    assert cross.transfer_and_install(project.path) == {"status": "installed"}
    assert installed == [(TOKEN, request["authorization_id"])]
    assert len(checks) == 2

def test_client_rotation_after_remote_token_fails_before_install(tmp_path, monkeypatch):
    project = Project(tmp_path / "project")
    monkeypatch.setattr(creds, "_require_root", lambda: None)
    index = [0]
    def next_binding(p):
        index[0] += 1
        return {"revision": index[0]}
    monkeypatch.setattr(cross, "_client_binding", next_binding)
    monkeypatch.setattr(cross, "_client_approved", lambda p, b: "a" * 64)
    monkeypatch.setattr(cross, "_request", lambda b: b"test")
    monkeypatch.setattr(cross, "_ssh_token", lambda b, r: TOKEN)
    monkeypatch.setattr(creds, "install_from_fd",
                        lambda *a, **kw: pytest.fail("rotated token must not install"))
    with pytest.raises(cross.CrossHostDenied):
        cross.transfer_and_install(project.path)


def test_client_profile_requires_actual_owner_ledger_and_single_pinned_host_key(tmp_path, monkeypatch):
    import base64
    import hashlib
    project = Project(tmp_path / "project")
    request = sample_request()
    owner = b"retained-authority-receipt\n"
    signer = b"independently-installed-station-key\n"
    identity = b"operator-provisioned-test-identity"
    ssh_blob = b"\x00\x00\x00\x0bssh-ed25519" + b"\x00\x00\x00\x20" + b"K" * 32
    known = ("[station.example.org]:2222 ssh-ed25519 " +
             base64.b64encode(ssh_blob).decode() + "\n").encode()
    profile = dict(
        schema=cross.CLIENT_SCHEMA, project=str(project.path),
        authorization_id=request["authorization_id"], host_id=request["host_id"],
        installation_id=request["installation_id"],
        state_volume_id=str(uuid.uuid4()), host_fingerprint="a" * 64,
        registry_id="test-registry",
        assignment_id=request["assignment_id"],
        assignment_revision=request["assignment_revision"],
        receipt_sha256=request["receipt_sha256"],
        ssh_host="station.example.org", ssh_port=2222,
        ssh_user="issuer_bridge", ssh_identity="/etc/zog/ssh-issuer/client",
        ssh_known_hosts="/etc/zog/ssh-issuer/known_hosts",
        ssh_known_hosts_sha256=hashlib.sha256(known).hexdigest(),
        owner_authority_sha256=hashlib.sha256(owner).hexdigest(),
        station_signer_pin_sha256=hashlib.sha256(signer).hexdigest(),
    )
    protected = {
        "/state/host-install/certificate-owner-authority/authority.json": owner,
        "/etc/zog/host-install/certificate-assignment-authority.json": signer,
        profile["ssh_identity"]: identity,
        profile["ssh_known_hosts"]: known,
    }
    monkeypatch.setattr(cross, "_load_json", lambda path: dict(profile))
    monkeypatch.setattr(cross, "_root_regular",
                        lambda path, **kw: protected[str(path)])
    assert cross._client_binding(project) == profile
    protected["/state/host-install/certificate-owner-authority/authority.json"] = b"changed-ledger"
    with pytest.raises(cross.CrossHostDenied):
        cross._client_binding(project)
    protected["/state/host-install/certificate-owner-authority/authority.json"] = owner
    protected[profile["ssh_known_hosts"]] = known + known
    with pytest.raises(cross.CrossHostDenied):
        cross._client_binding(project)
    protected[profile["ssh_known_hosts"]] = known
    profile["ssh_host"] = "-oProxyCommand=malicious"
    with pytest.raises(cross.CrossHostDenied):
        cross._client_binding(project)


@pytest.mark.parametrize("changed", ["schema", "peer_uid", "ssh_key_fingerprint",
                                     "host_id", "assignment_revision", "projection_path"])
def test_station_binding_rejects_stale_or_untrusted_service_principal(monkeypatch, changed):
    request = sample_request()
    config = binding(request)
    config[changed] = (0 if changed == "peer_uid" else
                       "ssh-rsa-not-accepted" if changed == "ssh_key_fingerprint" else
                       "../escaped" if changed == "projection_path" else
                       -1 if changed == "assignment_revision" else "invalid")
    monkeypatch.setattr(cross, "_load_json", lambda path: config)
    with pytest.raises(cross.CrossHostDenied):
        cross._station_binding()
