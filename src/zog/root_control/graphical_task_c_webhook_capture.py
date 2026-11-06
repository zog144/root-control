"""Prospective independent original GitHub issue webhook capture.

Source-only WSGI handler to run *behind separately installed HTTPS* on an
isolated capture host. It holds only the GitHub HMAC webhook secret, never any
Ed25519 operator/event key, AWS credential, public pin or SSM authority.

The raw authenticated delivery is stored with exclusive creation and fsync.
No replay after lost acknowledgement, no handling of edited/closed issues,
and no production server is started by importing this module.
"""
from __future__ import annotations

import base64
from datetime import datetime
import hashlib
import hmac
import os
from pathlib import Path
import stat

from . import graphical_task_c_issuance as issuance
from . import graphical_operation_owner_source as owner


class CaptureDenied(ValueError):
    pass


def deny():
    raise CaptureDenied("authenticated original GitHub webhook not admitted")


def validate_delivery(raw, *, signature, delivery_id, webhook_secret,
                      expected_repository_id, expected_actor_id,
                      authorized_actor, observed_at):
    if (type(raw) is not bytes or not 1 <= len(raw) <= issuance.EVENT_LIMIT
            or type(webhook_secret) is not bytes or len(webhook_secret) < 32
            or type(signature) is not str or
            not signature.startswith("sha256=")
            or not owner.match(signature[7:], owner.H64)
            or not hmac.compare_digest(
                signature[7:],
                hmac.new(webhook_secret, raw, hashlib.sha256).hexdigest())
            or type(delivery_id) is not str
            or not 1 <= len(delivery_id) <= 128
            or not all(c.isalnum() or c in "-_" for c in delivery_id)
            or type(expected_repository_id) is not int
            or expected_repository_id <= 0
            or type(expected_actor_id) is not int
            or expected_actor_id <= 0
            or type(observed_at) is not int):
        deny()
    event = issuance.strict(raw)
    if not isinstance(event, dict):
        deny()
    repo, actor, issue = event.get("repository"), event.get("sender"), event.get("issue")
    if (event.get("action") != "opened"
            or not isinstance(repo, dict)
            or repo.get("full_name") != "zog144/host-deploy"
            or repo.get("id") != expected_repository_id
            or not isinstance(actor, dict)
            or actor.get("id") != expected_actor_id
            or actor.get("login") != authorized_actor
            or not isinstance(issue, dict)
            or not isinstance(issue.get("user"), dict)
            or issue["user"].get("id") != expected_actor_id):
        deny()
    try:
        from zog.host_deploy.gateway.github_dispatch import prepare_event
        from zog.host_deploy.gateway.protocol import request_digest
        request = prepare_event(event, frozenset({authorized_actor}))
        stamp = issue["created_at"]
        if type(stamp) is not str or not stamp.endswith("Z"):
            deny()
        created = int(datetime.fromisoformat(
            stamp.replace("Z", "+00:00")).timestamp())
    except (ValueError, KeyError, TypeError, ImportError):
        deny()
    if created > observed_at or observed_at - created > issuance.WEBHOOK_LIFETIME:
        deny()
    return {
        "schema": "zog-task-c-original-github-webhook-capture-v1",
        "event_sha256": issuance.sha(raw),
        "original_request_sha256": request_digest(request),
        "delivery_id": delivery_id,
        "repository_id": expected_repository_id,
        "actor_id": expected_actor_id,
        "issue_number": request["origin"]["issue_number"],
        "request_id": request["request_id"],
        "observed_at": observed_at,
        "raw_event_base64": base64.b64encode(raw).decode("ascii"),
        "signature_header": signature,
    }


def publish_capture(envelope, directory):
    """Append-only receipt for a single original delivery on isolated storage."""
    if type(envelope) is not dict or envelope.get("schema") != (
            "zog-task-c-original-github-webhook-capture-v1"):
        deny()
    delivery = envelope.get("delivery_id")
    if (type(delivery) is not str or not 1 <= len(delivery) <= 128
            or not all(ch.isalnum() or ch in "-_" for ch in delivery)):
        deny()
    p = Path(directory)
    if not p.is_absolute() or p.is_symlink():
        deny()
    info = os.lstat(p)
    if (not stat.S_ISDIR(info.st_mode)
            or info.st_mode & 0o077 or info.st_uid != os.geteuid()):
        deny()
    raw = owner.canonical(envelope) + b"\n"
    filename = p / (envelope["delivery_id"] + ".json")
    fd = os.open(str(filename), os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        d = os.open(str(p), os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(d)
        finally:
            os.close(d)
    except BaseException:
        # Do not unlink on lost ACK / partial fsync or use a new identity.
        raise
    return {"status": "original-delivery-captured-not-signed",
            "delivery_id": envelope["delivery_id"],
            "receipt_sha256": issuance.sha(raw)}


def capture_wsgi(environ, start_response, *, policy, secret, directory, now):
    """One-shot keyless capture handler; HTTPS ingress belongs to native Work."""
    try:
        if (environ.get("REQUEST_METHOD") != "POST"
                or environ.get("PATH_INFO") != "/zog/task-c/original"
                or environ.get("HTTP_X_GITHUB_EVENT") != "issues"
                or environ.get("CONTENT_TYPE", "").split(";")[0] !=
                    "application/json"
                or type(now) is not int):
            deny()
        length = int(environ["CONTENT_LENGTH"])
        if not 1 <= length <= issuance.EVENT_LIMIT:
            deny()
        stream = environ.get("wsgi.input")
        if stream is None:
            deny()
        raw = stream.read(length)
        if type(raw) is not bytes or len(raw) != length:
            deny()
        if (type(policy) is not dict or
                set(policy) != {"repository_id", "actor_id", "actor"}):
            deny()
        envelope = validate_delivery(
            raw, signature=environ.get("HTTP_X_HUB_SIGNATURE_256"),
            delivery_id=environ.get("HTTP_X_GITHUB_DELIVERY"),
            webhook_secret=secret,
            expected_repository_id=policy["repository_id"],
            expected_actor_id=policy["actor_id"],
            authorized_actor=policy["actor"], observed_at=now)
        receipt = publish_capture(envelope, directory)
        start_response("202 Accepted", [("Content-Type", "text/plain")])
        return [b"captured; independent issuer signature not yet admitted\n"]
    except (ValueError, TypeError, KeyError, OSError, issuance.IssuanceDenied):
        # Never disclose original issue content, HMAC, path or pinned identities.
        start_response("403 Forbidden", [("Content-Type", "text/plain")])
        return [b"original webhook not admitted\n"]
