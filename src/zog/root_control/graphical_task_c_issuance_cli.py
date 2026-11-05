"""Manually invoked, disabled-by-default Task C original issuance CLI.

Install on *separate* offline/protected signing hosts: operator and GitHub
event issuer. There is no key generation, source-controlled private key,
automatic network listener, background sign, AWS write or SSM authority.
This program requires pre-existing pins, keys, claim directories and a
fresh human operator confirmation before any operator signature.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from . import graphical_task_c_issuance as issue
from . import graphical_task_c_owner as taskc
from . import graphical_operation_owner_source as owner

ROOT = Path("/etc/zog/graphical-task-c-issuance")
OUTPUT = Path("/var/lib/zog/graphical-task-c-issuance")
ROLE_NAMES = {
    "operator": (ROOT / "operator.private", ROOT / "operator.public"),
    "event": (ROOT / "event.private", ROOT / "event.public"),
}
WEBHOOK_SECRET = ROOT / "github-webhook.hmac"
MAX = 131072


def _deny():
    issue.hold()


def _protected_dir(path):
    current = path
    while True:
        info = os.lstat(current)
        if (not stat.S_ISDIR(info.st_mode) or
                info.st_uid != 0 or info.st_mode & 0o022):
            _deny()
        if str(current) == "/":
            return
        current = current.parent


def _read(path, *, size=MAX, mode=0o600):
    p = Path(path)
    if not p.is_absolute() or p.is_symlink():
        _deny()
    _protected_dir(p.parent)
    fd = os.open(str(p), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != mode
                or not 1 <= info.st_size <= size):
            _deny()
        raw = os.read(fd, size + 1)
        if len(raw) != info.st_size:
            _deny()
        return raw
    finally:
        os.close(fd)


def _key(role):
    private, pubpath = ROLE_NAMES[role]
    raw = _read(private, size=32, mode=0o400)
    pin = _read(pubpath, size=32, mode=0o600)
    if len(raw) != 32 or len(pin) != 32:
        _deny()
    key = Ed25519PrivateKey.from_private_bytes(raw)
    derived = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if derived != pin:
        _deny()
    # Only return the scoped caller's key and separately installed pin.
    return key.sign, pin


def _human_confirm(label, value):
    """No approval from argv, env, file, or gateway; physical tty required."""
    digest = issue.sha(owner.canonical(value))
    with open("/dev/tty", "r+", encoding="ascii") as terminal:
        terminal.write(f"Task C {label} SHA-256: {digest}\n")
        terminal.write("Review original Host/install/STATE, S3 genesis, issue/actor,\n"
                       "operation and expiry from the *independent* source.\n")
        terminal.write(f"Type exactly APPROVE {digest} to sign: ")
        terminal.flush()
        reply = terminal.readline(128).strip()
    if reply != "APPROVE " + digest:
        _deny()


def _claim(kind, unique):
    """Never reopen an issuance claim after crash or uncertain write."""
    if (type(unique) is not str or not unique or
            not all(x.isalnum() or x in "-_" for x in unique)
            or len(unique) > 128):
        _deny()
    directory = OUTPUT / "claims" / kind
    _protected_dir(directory)
    name = directory / (unique + ".claimed")
    fd = os.open(str(name), os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(owner.canonical({
                "kind": kind, "id": unique, "status": "irrevocably-reserved"
            }) + b"\n")
            f.flush()
            os.fsync(f.fileno())
        d = os.open(str(directory), os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(d)
        finally:
            os.close(d)
    except BaseException:
        # Do NOT unlink, rename or retry an ambiguous reservation.
        raise


def _publish(kind, unique, result):
    dest = OUTPUT / "receipts" / kind / (unique + ".json")
    _protected_dir(dest.parent)
    content = owner.canonical(result) + b"\n"
    fd = os.open(str(dest), os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        parent = os.open(str(dest.parent), os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    except BaseException:
        # No cleanup on uncertain publication.
        raise
    return {"status": "receipt-written-not-installed",
            "sha256": issue.sha(content.rstrip(b"\n")),
            "kind": kind, "id": unique}


def _input(path):
    return issue.strict(_read(path, mode=0o600))


def run(argv=None):
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="action", required=True)
    op = commands.add_parser("operator-registry")
    op.add_argument("--manifest", required=True)
    ev = commands.add_parser("event-from-webhook")
    ev.add_argument("--manifest", required=True)
    ev.add_argument("--webhook", required=True)
    ev.add_argument("--webhook-signature", required=True)
    ev.add_argument("--delivery-id", required=True)
    captured = commands.add_parser("event-from-capture")
    captured.add_argument("--manifest", required=True)
    captured.add_argument("--capture", required=True)
    purpose = commands.add_parser("operator-purpose")
    purpose.add_argument("--manifest", required=True)
    revoke = commands.add_parser("operator-revoke")
    revoke.add_argument("--manifest", required=True)
    opts = parser.parse_args(argv)
    if os.geteuid() != 0 or os.getuid() != 0:
        _deny()
    os.umask(0o077)
    m = _input(opts.manifest)
    now = int(time.time())
    if opts.action == "operator-registry":
        signer, pub = _key("operator")
        required = {"stage_request", "preflight_request", "stage_original",
                    "original_checkpoint", "approval_ids", "expires_at"}
        if set(m) != required:
            _deny()
        _human_confirm("original preflight and stage", m)
        id_ = m["stage_request"]["operation_id"]
        _claim("operator-registry", id_)
        result = issue.issue_original_registry(
            **m, now=now, sign_operator=signer,
            pinned_operator_public=pub)
        return _publish("operator-registry", id_, result)

    if opts.action in ("event-from-webhook", "event-from-capture"):
        signer, pub = _key("event")
        secret = _read(WEBHOOK_SECRET, size=512, mode=0o400)
        required = {"registry", "operator_public_hex",
                    "authorized_actor", "repository_id", "actor_id",
                    "original_commit_sha", "expires_at"}
        if set(m) != required:
            _deny()
        operator_public = bytes.fromhex(m["operator_public_hex"])
        if operator_public == pub:
            _deny()
        registry = taskc.ProtectedOriginalRegistry(
            m["registry"], pinned_operator_public_key=operator_public)
        if opts.action == "event-from-capture":
            captured = _input(opts.capture)
            fields = {"schema", "event_sha256", "original_request_sha256",
                      "delivery_id", "repository_id", "actor_id",
                      "issue_number", "request_id", "observed_at",
                      "raw_event_base64", "signature_header"}
            if (set(captured) != fields
                    or captured["schema"] !=
                      "zog-task-c-original-github-webhook-capture-v1"
                    or captured["repository_id"] != m["repository_id"]
                    or captured["actor_id"] != m["actor_id"]
                    or type(captured["observed_at"]) is not int
                    or not captured["observed_at"] <= now <=
                        captured["observed_at"] + issue.WEBHOOK_LIFETIME):
                _deny()
            try:
                event = base64.b64decode(
                    captured["raw_event_base64"], validate=True)
            except (ValueError, TypeError):
                _deny()
            if issue.sha(event) != captured["event_sha256"]:
                _deny()
            signature = captured["signature_header"]
            delivery_id = captured["delivery_id"]
        else:
            event = _read(opts.webhook, size=issue.EVENT_LIMIT, mode=0o600)
            signature = _read(opts.webhook_signature, size=80, mode=0o600
                              ).decode("ascii").strip()
            delivery_id = opts.delivery_id
        _claim("github-event", delivery_id)
        # A delivery ID substitution cannot turn identical original bytes
        # into a new issuance if an old acknowledgement was lost.
        _claim("github-event-content", issue.sha(event)[7:])
        result = issue.attest_original_github_event(
            event_raw=event, signature_header=signature,
            delivery_id=delivery_id, secret=secret,
            registry=registry, authorized_actor=m["authorized_actor"],
            expected_repository_id=m["repository_id"],
            expected_actor_id=m["actor_id"],
            original_commit_sha=m["original_commit_sha"],
            issued_at=now, expires_at=m["expires_at"],
            pinned_issuer_public=pub, sign_issuer=signer)
        return _publish("github-event", delivery_id, result)

    if opts.action == "operator-purpose":
        signer, pub = _key("operator")
        required = {"record", "registry", "origin_evidence",
                    "issuer_public_hex", "pin", "broker_config",
                    "root_row", "readonly_role_arn", "expires_at"}
        if set(m) != required:
            _deny()
        issuer_pub = bytes.fromhex(m["issuer_public_hex"])
        registry = taskc.ProtectedOriginalRegistry(
            m["registry"], pinned_operator_public_key=pub)
        body = issue.prepare_broker_purpose(
            record=m["record"], registry=registry,
            origin_evidence=m["origin_evidence"],
            operator_public=pub, issuer_public=issuer_pub,
            pin=m["pin"], broker_config=m["broker_config"],
            root_row=m["root_row"], readonly_role_arn=m["readonly_role_arn"],
            expires_at=m["expires_at"], now=now)
        _human_confirm("broker read-only purpose", body)
        id_ = body["pin_sha256"][7:]
        _claim("operator-purpose", id_)
        result = issue.issue_broker_purpose(
            body=body, sign_operator=signer, pinned_operator_public=pub)
        return _publish("operator-purpose", id_, result)

    if opts.action == "operator-revoke":
        signer, pub = _key("operator")
        if set(m) != {"approved_scope", "approval_id", "expires_at"}:
            _deny()
        _human_confirm("irrevocable scope revocation", m)
        _claim("operator-revoke", m["approval_id"])
        result = issue.issue_revocation(
            **m, now=now, sign_operator=signer,
            pinned_operator_public=pub)
        return _publish("operator-revoke", m["approval_id"], result)
    _deny()


def main():
    try:
        status = run()
        print(json.dumps(status, sort_keys=True))
    except (issue.IssuanceDenied, owner.OperationDenied, OSError,
            ValueError, TypeError, KeyError):
        # No secret values and no raw event are emitted on failure.
        print("Task C authority issuance held; no accepted receipt", file=sys.stderr)
        raise SystemExit(2)


if __name__ == "__main__":
    main()
