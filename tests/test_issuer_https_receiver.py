"""Canonical HTTPS credential receiver contract: pinned public cross-owner vector.

Synthetic keys and fake FD installer ONLY; never a real protected credential.
"""
import base64
import hashlib
import json
import os
import time
from pathlib import Path

import pytest
from http_message_signatures.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from zog.host_identify import credential_delivery as cd
from zog.host_identify import signatures
from zog.root_control import issuer_https_receiver as receiver
from zog.root_control.issuer_receipt_common import CredentialReceiptDenied

VECTOR = Path(__file__).parent / "fixtures" / "credential-delivery-v1-vector.json"


def fixture():
    v = json.loads(VECTOR.read_text())
    host = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(v["host_seed_hex"]))
    ca = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(v["authority_seed_hex"]))
    return v, host, ca


def profile(v):
    a = v["authorization"]
    return {
        "schema": receiver.PROFILE_SCHEMA,
        "project": "/approved/project",
        "https_origin": v["origin"],
        "tls_authority_pin_sha256": "a"*64,
        "station_signer_pin_sha256": "b"*64,
        "credential_authority_pin_sha256": "c"*64,
        "owner_authority_sha256": "d"*64,
        **{name:a[name] for name in (
            "host_id", "host_fingerprint", "installation_id",
            "state_volume_id", "registry_id", "credential_revision")},
        "authorization_id": "e"*64,  # distinct local issuer authorization digest
        "assignment_id": "00000000-0000-4000-8000-000000000011",
        "assignment_revision": 3,
        "receipt_sha256": "f"*64,
        "purpose": receiver.PURPOSE,
        "delivery_credential_id": a["credential_id"],
        "credential_authorization_id": a["authorization_id"],
        "credential_authorization_revision": a["revision"],
        "grant_id": "1"*32,
        "storage_id": "2"*32,
        "consumer_uid": 24321,
        "credential_id": "00000000-0000-4000-8000-000000000012",
        "policy_sha256": "3"*64,
    }


def test_exact_station_public_vectors_and_authority_key_separation():
    v, host, ca = fixture()
    a, r, d = v["authorization"], v["request"], v["delivery"]
    assert receiver.PROTOCOL_SOURCE == "4a176373ff4cb47a66a8ab1b5fd3d6ff01ff2a3b"
    assert receiver.PATH == v["request_path"]
    assert receiver.RECEIPT_PATH == v["receipt_path"]
    assert receiver.CANCEL_PATH == v["cancel_path"]
    assert hashlib.sha256(cd.canonical(a)).hexdigest() == v["authorization_sha256"]
    assert hashlib.sha256(cd.canonical(r)).hexdigest() == v["request_sha256"]
    assert hashlib.sha256(cd.canonical(d)).hexdigest() == v["delivery_sha256"]
    assert cd.sign_authorization(a, ca)["signature"] == v["authorization_signature_base64"]
    assert cd.sign_delivery(d, ca)["signature"] == v["delivery_signature_base64"]
    assert cd.verify_authorization(
        cd.sign_authorization(a, ca), ca.public_key(),
        expected_issuer=v["origin"], expected_binding=cd.binding(a),
        now=v["time"]) == a
    with pytest.raises(cd.CredentialProtocolError):
        cd.verify_authorization(cd.sign_authorization(a, host),
            ca.public_key(), expected_issuer=v["origin"],
            expected_binding=cd.binding(a), now=v["time"])


def test_signed_authorization_is_not_local_sha_digest(monkeypatch):
    v, host, ca = fixture()
    p = profile(v)
    raw = cd.canonical(cd.sign_authorization(v["authorization"], ca))
    monkeypatch.setattr(receiver, "_signed_authorization_path", lambda _: "authority")
    monkeypatch.setattr(receiver, "_root_regular", lambda path, **kw: raw)
    assert receiver._authorization(None, p, ca.public_key(), now=v["time"]) == v["authorization"]
    with pytest.raises(CredentialReceiptDenied):
        receiver._authorization(None, dict(p, state_volume_id=
            "00000000-0000-4000-8000-000000000099"),
            ca.public_key(), now=v["time"])
    with pytest.raises(CredentialReceiptDenied):
        receiver._authorization(None, p, host.public_key(), now=v["time"])
    with pytest.raises(CredentialReceiptDenied):
        receiver._authorization(None, dict(p, credential_authorization_revision=3),
                                ca.public_key(), now=v["time"])


def test_delivery_signing_and_decode_requires_canonical_envelope():
    v, host, ca = fixture()
    a, r, d = v["authorization"], v["request"], v["delivery"]
    signed = cd.sign_delivery(d, ca)
    raw = cd.canonical(signed)
    token, public = receiver._delivery(raw, r, a, ca.public_key(), now=v["time"])
    assert token == base64.b64decode(d["secret"])
    assert "secret" not in public and "token" not in repr(public).lower()
    assert public["delivery_id"] == d["delivery_id"]
    for tamper in (
        cd.canonical(cd.sign_delivery(dict(d, request_id="00000000-0000-4000-8000-000000000099"), ca)),
        cd.canonical(cd.sign_delivery(d, host)),
        raw + b" ",
        cd.canonical(dict(signed, signature="invalid")),
        b"not-json",
    ):
        with pytest.raises(CredentialReceiptDenied):
            receiver._delivery(tamper, r, a, ca.public_key(), now=v["time"])


def test_exact_rfc9421_request_and_secret_free_install_receipt():
    v, host, ca = fixture()
    now = int(time.time())
    a = dict(v["authorization"], approved_at=now-10, expires_at=now+3600)
    state = cd.new_ledger(a)
    req = receiver._new_request(a, state, now=now)
    assert set(req) == set(v["request"]) and req["schema"] == cd.REQUEST_SCHEMA
    prepared = cd.prepare_request(v["origin"]+receiver.PATH, req, a, host,
                                  nonce="A"*24)
    assert prepared.url == v["origin"]+v["request_path"]
    decoded, nonce, expiry = cd.verify_request_http(
        prepared.url, "POST", dict(prepared.headers), prepared.body,
        host.public_key(), a, now=now)
    assert decoded == req and nonce == "A"*24
    assert prepared.body == cd.canonical(req)
    with pytest.raises((ValueError, InvalidSignature)):
        cd.verify_request_http(v["origin"]+"/api/hosts/credential-delivery/v1/receive/",
                               "POST", dict(prepared.headers), prepared.body,
                               host.public_key(), a, now=now)
    delivery = dict(v["delivery"], request_id=req["request_id"],
                    issued_at=now, expires_at=now+60)
    receipt = {
        "schema": cd.RECEIPT_SCHEMA,
        **cd.binding(req),
        **{name:req[name] for name in (
            "credential_revision","authorization_id",
            "authorization_revision","request_id")},
        "delivery_id": delivery["delivery_id"],
        "receipt_id": "00000000-0000-4000-8000-000000000007",
        "outcome": "installed", "installed_at": now,
    }
    posted = cd.prepare_receipt(v["origin"]+receiver.RECEIPT_PATH, receipt,
                                req, delivery, host, nonce="B"*24)
    observed, nonce, expiry = cd.verify_receipt_http(
        posted.url, "POST", dict(posted.headers), posted.body,
        host.public_key(), req, delivery, now=now)
    assert observed == receipt and nonce == "B"*24
    assert b"secret" not in posted.body and b"token" not in posted.body


def test_durable_pending_unknown_and_explicit_rotation(tmp_path, monkeypatch):
    v, _, _ = fixture()
    project = type("ProjectStub", (), {"path": Path("/approved/project")})()
    root = tmp_path/"https-receipts"
    root.mkdir()
    monkeypatch.setattr(receiver.credentials, "AUTH_ROOT", tmp_path)
    monkeypatch.setattr(receiver.credentials, "_check_root_directory", lambda *_: None)
    monkeypatch.setattr(receiver, "_root_regular", lambda path, **kwargs: Path(path).read_bytes())
    auth = v["authorization"]
    req = v["request"]
    state = cd.admit_request(cd.new_ledger(auth), req)
    state["rotation_required"] = True  # outbound may have reached issuer
    receiver._save_operation(project, req, None, "pending")
    receiver._persist_state(project, state)
    assert receiver._load_state(project, auth) == state
    assert receiver._operation(project)["phase"] == "pending"
    with pytest.raises(cd.CredentialProtocolError, match="in-progress"):
        cd.admit_request(state, dict(req, request_id=
            "00000000-0000-4000-8000-000000000099"))
    cancel = {
        "schema": cd.CANCEL_SCHEMA, **cd.binding(req),
        **{name:req[name] for name in (
            "credential_revision", "authorization_id",
            "authorization_revision", "request_id")},
        "cancel_id": "00000000-0000-4000-8000-000000000008",
        "reason": "interruption-recovery",
        "created_at": v["time"], "expires_at": v["time"]+60,
    }
    cancelled = cd.record_cancel(state, cancel)
    assert cancelled["requests"][-1]["status"] == "cancelled"
    assert cancelled["rotation_required"] is True
    # Rotation cannot reuse the same authorization revision.
    with pytest.raises(cd.CredentialProtocolError):
        cd.admit_request(cancelled, dict(req, request_id=
            "00000000-0000-4000-8000-000000000099"))
    assert b"secret" not in (root/receiver._state_paths(project)[1]).read_bytes()


def test_purpose_scoped_root_admission_blocks_network(monkeypatch):
    monkeypatch.setattr(receiver.credentials, "_require_root", lambda: None)
    with pytest.raises(CredentialReceiptDenied):
        receiver.receive_and_install("/safe/project", private_identity=None,
            admission={"status": "protected-source-preflight-only",
                       "native_https_accepted": False, "owner": {"status": "retained"}})


@pytest.fixture
def recovery(tmp_path, monkeypatch):
    from contextlib import nullcontext
    v, host, ca = fixture()
    now = int(time.time())
    a = dict(v["authorization"], approved_at=now-10, expires_at=now+3600)
    p = profile(v)
    project = tmp_path/"project"
    project.mkdir()
    p["project"] = str(project)
    root = tmp_path/"https-receipts"
    root.mkdir()
    monkeypatch.setattr(receiver.credentials, "AUTH_ROOT", tmp_path)
    monkeypatch.setattr(receiver.credentials, "_require_root", lambda: None)
    monkeypatch.setattr(receiver.credentials, "_check_root_directory", lambda *_: None)
    monkeypatch.setattr(receiver.credentials, "_check_lock_info", lambda *_: None)
    monkeypatch.setattr(receiver.credentials, "_locked", lambda *_: nullcontext())
    monkeypatch.setattr(receiver, "_root_regular", lambda path, **kw: Path(path).read_bytes())
    monkeypatch.setattr(receiver, "LIVE_NETWORK_ACTIVATION", True)
    monkeypatch.setattr(receiver, "_profile", lambda proj: {
        k:x for k,x in p.items() if k not in ("credential_id","policy_sha256")})
    monkeypatch.setattr(receiver, "_approval", lambda proj, prof: (
        p["authorization_id"], {"credential_id":p["credential_id"],
                                "policy_sha256":p["policy_sha256"]}))
    monkeypatch.setattr(receiver, "_authority_key", lambda prof:ca.public_key())
    monkeypatch.setattr(receiver, "_authorization", lambda *args, **kw:a)
    # Keep real _current() and signature/ledger validators. Only the protected
    # installation/owner readbacks and transport are synthetic here.
    installed = []
    def installer(proj, fd, *, expected_authorization_id):
        assert expected_authorization_id == p["authorization_id"]
        assert os.read(fd,4096) == base64.b64decode(v["delivery"]["secret"])
        installed.append(True)
        return {"status":"installed","replayed":False,
                "credential_revision":p["credential_revision"]}
    monkeypatch.setattr(receiver.credentials, "install_from_fd", installer)
    def assert_bytes(proj, binding):
        assert installed == [True]
    monkeypatch.setattr(receiver, "_assert_installed_bytes", assert_bytes)

    class Station:
        # Pinned v1 verifies actual HTTP signatures and consumes fresh nonces.
        # This in-memory station models the commit boundary, not Django/HTTPS.
        def __init__(self):
            self.state = cd.new_ledger(a)
            self.request = None
            self.metadata = None
            self.nonces = set()
            self.posts = []
            self.loss = None
            self.lost_delivery = False
        def __call__(self, prepared, profile, *, expected_status):
            headers, body = dict(prepared.headers), prepared.body
            if expected_status == 200:
                assert prepared.url == v["origin"] + receiver.PATH
                self.request, nonce, _ = cd.verify_request_http(
                    prepared.url, "POST", headers, body, host.public_key(), a)
                assert nonce not in self.nonces
                self.nonces.add(nonce)
                self.state = cd.admit_request(self.state, self.request)
                moment = int(time.time())
                delivery = dict(v["delivery"], request_id=self.request["request_id"],
                                issued_at=moment, expires_at=moment+60)
                self.state = cd.record_delivery(self.state, delivery)
                self.metadata = {k:x for k,x in delivery.items() if k!="secret"}
                if self.lost_delivery:
                    raise OSError("synthetic lost delivery")
                return cd.canonical(cd.sign_delivery(delivery, ca))
            assert expected_status == 204
            if prepared.url.endswith(receiver.RECEIPT_PATH):
                value, nonce, _ = cd.verify_receipt_http(
                    prepared.url, "POST", headers, body, host.public_key(),
                    self.request, self.metadata)
                next_state = cd.record_installation(self.state, value)
            else:
                assert prepared.url.endswith(receiver.CANCEL_PATH)
                value, nonce, _ = cd.verify_cancel_http(
                    prepared.url, "POST", headers, body, host.public_key(), self.request)
                next_state = cd.record_cancel(self.state, value)
            assert nonce not in self.nonces
            self.nonces.add(nonce)
            assert b"secret" not in body and b"token" not in body
            self.posts.append((body, nonce))
            if self.loss == "before":
                raise OSError("synthetic loss before station commit")
            self.state = next_state
            if self.loss == "after":
                raise OSError("synthetic loss after station commit")
            return b""

    station = Station()
    admission = {"status":"protected-source-preflight-only",
                 "native_https_accepted":True,"owner":{"status":"retained"}}
    kwargs = dict(private_identity=host, admission=admission, transport=station)
    proj = receiver.Project(project)
    return proj, p, a, station, installed, kwargs


@pytest.mark.parametrize("loss", ["before", "after"])
def test_lost_installation_reply_reuses_exact_receipt_with_fresh_nonce(recovery, loss):
    project, p, a, station, installed, kwargs = recovery
    station.loss = loss
    with pytest.raises(CredentialReceiptDenied):
        receiver.receive_and_install(project.path, **kwargs)
    op = receiver._operation(project)
    assert op["phase"] == "installed" and not op["acknowledged"]
    assert installed == [True]
    request_id = op["request"]["request_id"]
    assert station.state["requests"][-1]["status"] == (
        "delivered" if loss == "before" else "installed")
    with pytest.raises(CredentialReceiptDenied):
        receiver.receive_and_install(project.path, **kwargs)
    station.loss = None
    result = receiver.recover_acknowledgement(project.path, request_id=request_id, **kwargs)
    assert result["receipt_id"] == op["ack_payload"]["receipt_id"]
    assert installed == [True]
    assert station.posts[0][0] == station.posts[1][0] == cd.canonical(op["ack_payload"])
    assert station.posts[0][1] != station.posts[1][1]
    assert station.state["requests"][-1]["status"] == "installed"
    assert receiver._operation(project)["acknowledged"]
    receiver.recover_acknowledgement(project.path, request_id=request_id, **kwargs)
    assert len(station.posts) == 2


@pytest.mark.parametrize("loss", ["before", "after"])
def test_lost_cancellation_reply_reuses_same_id_with_fresh_nonce(recovery, loss):
    project, p, a, station, installed, kwargs = recovery
    station.lost_delivery = True
    with pytest.raises(CredentialReceiptDenied):
        receiver.receive_and_install(project.path, **kwargs)
    station.loss = loss
    with pytest.raises(CredentialReceiptDenied):
        receiver.cancel_pending(project.path, **kwargs)
    op = receiver._operation(project)
    assert op["phase"] == "cancelled" and not op["acknowledged"]
    assert op["ledger"]["rotation_required"] is True
    assert station.state["requests"][-1]["status"] == (
        "delivered" if loss == "before" else "cancelled-after-delivery")
    station.loss = None
    result = receiver.recover_acknowledgement(
        project.path, request_id=op["request"]["request_id"], **kwargs)
    assert result["cancel_id"] == op["ack_payload"]["cancel_id"]
    assert station.posts[0][0] == station.posts[1][0]
    assert station.posts[0][1] != station.posts[1][1]
    assert station.state["requests"][-1]["status"] == "cancelled-after-delivery"
    assert receiver._operation(project)["acknowledged"] and installed == []


def test_expired_cancel_refreshes_only_window_retaining_original(recovery, monkeypatch):
    project, p, a, station, installed, kwargs = recovery
    station.lost_delivery = True
    with pytest.raises(CredentialReceiptDenied):
        receiver.receive_and_install(project.path, **kwargs)
    station.loss = "after"
    with pytest.raises(CredentialReceiptDenied):
        receiver.cancel_pending(project.path, **kwargs)
    op = receiver._operation(project)
    # Exercise the exact v1 verifier with current synthetic wall-clock time
    # after cancellation expiry; the original protected authorization stays valid.
    moment = op["ack_payload"]["expires_at"] + 120
    monkeypatch.setattr(time, "time", lambda: moment)
    station.loss = None
    receiver.recover_acknowledgement(
        project.path, request_id=op["request"]["request_id"], **kwargs)
    final = receiver._operation(project)
    assert final["ack_payload"] == op["ack_payload"]
    assert final["send_payload"] == dict(op["ack_payload"], created_at=moment, expires_at=moment+60)
    assert station.posts[-1][0] == cd.canonical(final["send_payload"])
    assert station.posts[0][1] != station.posts[-1][1]
    assert station.state["requests"][-1]["cancel_id"] == op["ack_payload"]["cancel_id"]
    assert final["acknowledged"] and installed == []


@pytest.mark.parametrize("phase", ["pending", "delivered", "installed", "cancelled"])
def test_interruption_between_operation_and_ledger_writes(recovery, monkeypatch, phase):
    project, p, a, station, installed, kwargs = recovery
    persist = receiver._persist_state
    def crash(proj, state):
        if receiver._operation(proj)["phase"] == phase:
            raise OSError("simulated interruption after operation fsync")
        return persist(proj, state)
    if phase == "cancelled":
        station.lost_delivery = True
        with pytest.raises(CredentialReceiptDenied):
            receiver.receive_and_install(project.path, **kwargs)
    monkeypatch.setattr(receiver, "_persist_state", crash)
    with pytest.raises(CredentialReceiptDenied):
        (receiver.cancel_pending if phase == "cancelled" else receiver.receive_and_install)(
            project.path, **kwargs)
    op = receiver._operation(project)
    assert op["phase"] == phase and not op["acknowledged"]
    assert receiver._raw_state(project) != op["ledger"]
    monkeypatch.setattr(receiver, "_persist_state", persist)
    # Restart uses only durable files. Pending/delivered never resends the
    # delivery or installs; explicit cancellation is safe if station knows
    # the request. A pending before-first-send marker remains a hold.
    if phase in ("pending", "delivered"):
        with pytest.raises(CredentialReceiptDenied):
            receiver.receive_and_install(project.path, **kwargs)
        assert receiver._raw_state(project) == op["ledger"]
        assert installed == [] and station.posts == []
    else:
        receiver.recover_acknowledgement(
            project.path, request_id=op["request"]["request_id"], **kwargs)
        assert receiver._raw_state(project) == op["ledger"]
        assert receiver._operation(project)["acknowledged"]
        assert len(station.posts) == 1
        assert installed == ([True] if phase == "installed" else [])


@pytest.mark.parametrize("change", ["revision", "authority", "wrong-id", "ledger"])
def test_recovery_refuses_changed_authority_or_ambiguous_state(recovery, change):
    project, p, a, station, installed, kwargs = recovery
    station.loss = "before"
    with pytest.raises(CredentialReceiptDenied):
        receiver.receive_and_install(project.path, **kwargs)
    op = receiver._operation(project)
    request_id = op["request"]["request_id"]
    if change == "revision":
        a["revision"] += 1
    elif change == "authority":
        p["credential_authority_pin_sha256"] = "9"*64
    elif change == "wrong-id":
        request_id = "00000000-0000-4000-8000-000000000099"
    else:
        state = receiver._raw_state(project)
        state["rotation_required"] = True
        receiver._persist_state(project, state)
    station.loss = None
    with pytest.raises(CredentialReceiptDenied):
        receiver.recover_acknowledgement(project.path, request_id=request_id, **kwargs)
    assert len(station.posts) == 1 and installed == [True]
    assert receiver._operation(project) == op


def test_source_default_blocks_even_pretend_native_acceptance(monkeypatch):
    assert receiver.LIVE_NETWORK_ACTIVATION is False
    monkeypatch.setattr(receiver.credentials, "_require_root", lambda: None)
    with pytest.raises(CredentialReceiptDenied):
        receiver.receive_and_install("/safe/project", private_identity=None,
            admission={"status":"protected-source-preflight-only",
                       "native_https_accepted":True,
                       "owner":{"status":"retained"}})
