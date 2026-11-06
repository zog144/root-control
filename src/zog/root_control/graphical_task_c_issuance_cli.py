"""Prospective manually invoked Task C signing; never bootstraps authority.

Operator and GitHub event issuer run on separate protected signing hosts.
Their 32-byte Ed25519 seeds and independently installed *counterparty* public
pins must already exist. No key, S3 history or service is created here.
"""
import argparse
import base64
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
    "operator": (ROOT/"operator.private", ROOT/"operator.public"),
    "event": (ROOT/"event.private", ROOT/"event.public"),
}
PINNED_OPERATOR_FOR_EVENT = ROOT/"accepted-operator.public"
PINNED_EVENT_FOR_OPERATOR = ROOT/"accepted-event-issuer.public"
WEBHOOK_SECRET = ROOT/"github-webhook.hmac"
ACCEPTED_ORIGINAL = ROOT/"accepted-original-checkpoint.sha256"
ACCEPTED_DISPATCH = ROOT/"accepted-dispatch-revision.commit"


def deny():
    issue.hold()


def protected(directory):
    p = Path(directory)
    while True:
        st = os.lstat(p)
        if (not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or
                st.st_mode & 0o022):
            deny()
        if str(p) == "/":
            return
        p = p.parent


def read(path, *, limit=65536, mode=0o600):
    p = Path(path)
    if not p.is_absolute() or p.is_symlink():
        deny()
    protected(p.parent)
    fd = os.open(str(p), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or
                st.st_nlink != 1 or stat.S_IMODE(st.st_mode) != mode or
                not 1 <= st.st_size <= limit):
            deny()
        raw = os.read(fd,limit+1)
        if len(raw) != st.st_size:
            deny()
        return raw
    finally:
        os.close(fd)


def key(role):
    secret, public_path = ROLE_NAMES[role]
    other_private = ROLE_NAMES["event" if role == "operator" else "operator"][0]
    if os.path.lexists(str(other_private)):
        deny()
    if role == "operator" and os.path.lexists(str(WEBHOOK_SECRET)):
        deny()
    raw = read(secret,limit=32,mode=0o400)
    pinned = read(public_path,limit=32)
    if len(raw) != 32 or len(pinned) != 32:
        deny()
    k = Ed25519PrivateKey.from_private_bytes(raw)
    derived = k.public_key().public_bytes(
        serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    if derived != pinned:
        deny()
    return k.sign, pinned


def confirm(label, body):
    digest = issue.sha(owner.canonical(body))
    with open("/dev/tty","r+",encoding="ascii") as tty:
        tty.write("Task C " + label + " SHA-256: " + digest + "\n")
        tty.write("Independently inspect original Host, STATE, operator, "
                  "event, S3 genesis, source and expiry.\n")
        tty.write("Type APPROVE " + digest + " to sign: ")
        tty.flush()
        accepted = tty.readline(128).strip()
    if accepted != "APPROVE " + digest:
        deny()


def create_only(path, raw):
    p = Path(path)
    protected(p.parent)
    fd = os.open(str(p),os.O_WRONLY|os.O_CREAT|os.O_EXCL|
                 os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        with os.fdopen(fd,"wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        fd_dir = os.open(str(p.parent),os.O_RDONLY|os.O_DIRECTORY)
        try:
            os.fsync(fd_dir)
        finally:
            os.close(fd_dir)
    except BaseException:
        # Lost acknowledgement or short write is uncertain; never unlink.
        raise


def claimed(kind, identity):
    if (type(identity) is not str or not 1 <= len(identity) <= 128 or
            not all(x.isalnum() or x in "-_" for x in identity)):
        deny()
    create_only(OUTPUT/"claims"/kind/(identity+".claimed"),
                owner.canonical({"schema":"zog-issuance-claim-v1",
                                 "kind":kind,"id":identity})+b"\n")


def published(kind, identity, envelope):
    canonical = owner.canonical(envelope)
    create_only(OUTPUT/"receipts"/kind/(identity+".json"), canonical+b"\n")
    return {"status":"receipt-written-not-installed",
            "kind":kind,"identity":identity,"sha256":issue.sha(canonical)}


def manifest(path):
    return issue.strict(read(path))


def require_peer_key(path, from_manifest, own_key):
    peer = read(path, limit=32)
    if (len(peer) != 32 or from_manifest != peer.hex() or peer == own_key):
        deny()
    return peer


def require_selected_original(record):
    digest = issue.sha(owner.canonical(record))
    if read(ACCEPTED_ORIGINAL, limit=72) != (digest + "\n").encode("ascii"):
        deny()
    return digest


def require_selected_dispatch(commit):
    if not owner.match(commit, owner.H40):
        deny()
    if read(ACCEPTED_DISPATCH, limit=41) != (commit + "\n").encode("ascii"):
        deny()
    return commit


def run(argv=None):
    parser=argparse.ArgumentParser()
    sub=parser.add_subparsers(dest="action",required=True)
    for name in ("operator-registry","operator-purpose","operator-revoke",
                 "event-from-webhook","event-from-capture"):
        p=sub.add_parser(name)
        p.add_argument("--manifest",required=True)
        if name == "event-from-webhook":
            for arg in ("webhook","webhook-signature","delivery-id"):
                p.add_argument("--"+arg,required=True)
        if name == "event-from-capture":
            p.add_argument("--capture",required=True)
    a=parser.parse_args(argv)
    if os.geteuid() != 0 or os.getuid() != 0:
        deny()
    os.umask(0o077)
    m=manifest(a.manifest)
    now=int(time.time())

    if a.action == "operator-registry":
        signer,pub=key("operator")
        if set(m) != {"stage_request","preflight_request","stage_original",
                       "original_checkpoint","approval_ids","expires_at"}:
            deny()
        confirm("original preflight + stage",m)
        identity=m["stage_request"]["operation_id"]
        claimed("operator-registry",identity)
        result=issue.issue_original_registry(
            **m,now=now,sign_operator=signer,pinned_operator_public=pub)
        return published("operator-registry",identity,result)

    if a.action in ("event-from-webhook","event-from-capture"):
        signer,pub=key("event")
        if set(m) != {"registry","operator_public_hex","authorized_actor",
                       "repository_id","actor_id","original_commit_sha",
                       "expires_at"}:
            deny()
        operator_pin=require_peer_key(
            PINNED_OPERATOR_FOR_EVENT,m["operator_public_hex"],pub)
        registry=taskc.ProtectedOriginalRegistry(
            m["registry"],pinned_operator_public_key=operator_pin)
        if a.action=="event-from-capture":
            c=manifest(a.capture)
            if (set(c) != {"schema","event_sha256","original_request_sha256",
                           "delivery_id","repository_id","actor_id",
                           "issue_number","request_id","observed_at",
                           "raw_event_base64","signature_header"} or
                    c["schema"]!="zog-task-c-original-github-webhook-capture-v1"
                    or c["repository_id"]!=m["repository_id"] or
                    c["actor_id"]!=m["actor_id"] or
                    type(c["observed_at"]) is not int or
                    not c["observed_at"]<=now<=c["observed_at"]+issue.WEBHOOK_LIFETIME):
                deny()
            raw=base64.b64decode(c["raw_event_base64"],validate=True)
            if issue.sha(raw)!=c["event_sha256"]:
                deny()
            signature=c["signature_header"]
            delivery=c["delivery_id"]
        else:
            raw=read(a.webhook,limit=issue.EVENT_LIMIT)
            signature=read(a.webhook_signature,limit=80).decode("ascii").strip()
            delivery=a.delivery_id
        claimed("github-event",delivery)
        claimed("github-event-content",issue.sha(raw)[7:])
        envelope=issue.attest_original_github_event(
            event_raw=raw,signature_header=signature,delivery_id=delivery,
            secret=read(WEBHOOK_SECRET,limit=512,mode=0o400),
            registry=registry,authorized_actor=m["authorized_actor"],
            expected_repository_id=m["repository_id"],
            expected_actor_id=m["actor_id"],
            original_commit_sha=m["original_commit_sha"],
            issued_at=now,expires_at=m["expires_at"],
            pinned_issuer_public=pub,sign_issuer=signer)
        return published("github-event",delivery,envelope)

    if a.action=="operator-purpose":
        signer,pub=key("operator")
        if set(m) != {"record","registry","origin_evidence","issuer_public_hex",
                       "pin","broker_config","root_row","readonly_role_arn",
                       "expires_at"}:
            deny()
        issuer_pin=require_peer_key(
            PINNED_EVENT_FOR_OPERATOR,m["issuer_public_hex"],pub)
        registry=taskc.ProtectedOriginalRegistry(
            m["registry"],pinned_operator_public_key=pub)
        body=issue.prepare_broker_purpose(
            record=m["record"],registry=registry,
            origin_evidence=m["origin_evidence"],
            operator_public=pub,issuer_public=issuer_pin,
            pin=m["pin"],broker_config=m["broker_config"],
            root_row=m["root_row"],readonly_role_arn=m["readonly_role_arn"],
            expires_at=m["expires_at"],now=now)
        confirm("broker read-only purpose",body)
        identity=body["pin_sha256"][7:]
        claimed("operator-purpose",identity)
        envelope=issue.issue_broker_purpose(
            body=body,sign_operator=signer,pinned_operator_public=pub)
        return published("operator-purpose",identity,envelope)

    if a.action=="operator-revoke":
        signer,pub=key("operator")
        if set(m)!={"approved_scope","approval_id","expires_at"}:
            deny()
        confirm("irrevocable scope revocation",m)
        claimed("operator-revoke",m["approval_id"])
        result=issue.issue_revocation(
            **m,now=now,sign_operator=signer,pinned_operator_public=pub)
        return published("operator-revoke",m["approval_id"],result)
    deny()


def main():
    try:
        print(json.dumps(run(),sort_keys=True))
    except (issue.IssuanceDenied,owner.OperationDenied,OSError,ValueError,
            TypeError,KeyError):
        print("Task C original authority issuance held; no accepted receipt",
              file=sys.stderr)
        raise SystemExit(2)


if __name__=="__main__":
    main()
