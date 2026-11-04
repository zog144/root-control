"""Native executable for the separately credentialed selected graphical owner.

Disabled unless host-install created and attested exact protected volumes,
service socket, approvals, source/RECORD and temporary SSM credentials.
No default boto3 credential chain and no caller-selected shell command.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import sys
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import graphical_operation_owner_source as contract
from .graphical_native_owner import (
    ProtectedLedger, SelectedOwner, _checked_file, hold, serve_one,
)
from .graphical_owner_checkpoint import SeparateDurableCheckpoint

CONFIG = Path("/etc/zog/graphical-owner/installation.json")
SOCKET = "/run/zog/graphical-owner.sock"
CREDS = Path("/run/credentials/zog-graphical-owner.service/aws-session.json")
SCRIPTS = Path("/etc/zog/graphical-owner/commands")
POLICY_SCHEMA = "zog-installed-graphical-owner-v1"
TOKEN_SCHEMA = "zog-protected-ssm-session-v1"
# Source can be installed for review, but two writable filesystems alone do
# NOT prove nonrollbackable highwater and source tests cannot prove gateway IAM
# SendCommand denial. A separate native reviewed implementation must replace
# this gate after independent evidence, not an operator-controlled JSON flag.
NATIVE_SEND_ADMISSION_IMPLEMENTED = False


def _read_root(path, *, max_bytes=32768, mode=0o600):
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        hold()
    # A fixed installer-owned absolute name. Reject symlinks at every parent.
    current = Path("/")
    for part in path.parts[1:-1]:
        current = current / part
        st = os.lstat(current)
        if (not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or
                st.st_mode & 0o022):
            hold()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        _checked_file(fd, 0, mode)
        st = os.fstat(fd)
        if not 0 < st.st_size <= max_bytes:
            hold()
        data = os.read(fd, max_bytes + 1)
        if len(data) != st.st_size:
            hold()
        return data
    finally:
        os.close(fd)


def installed():
    if os.geteuid() != 0:
        hold()
    row = json.loads(_read_root(CONFIG))
    if (type(row) is not dict or set(row) != {
            "schema", "selection", "operator_public_b64",
            "observation_private_b64", "peer_uid", "peer_gid",
            "ledger_directory", "checkpoint_directory",
            "gateway_state_directory", "aws_region", "aws_account_id",
            "instance_id"
            } or row["schema"] != POLICY_SCHEMA or
            type(row["peer_uid"]) is not int or row["peer_uid"] < 1000 or
            type(row["peer_gid"]) is not int or row["peer_gid"] < 1 or
            type(row["aws_region"]) is not str or
            not re.fullmatch(r"[a-z]{2}-[a-z]+-\d",row["aws_region"]) or
            type(row["aws_account_id"]) is not str or
            not re.fullmatch(r"\d{12}", row["aws_account_id"]) or
            type(row["instance_id"]) is not str or
            not re.fullmatch(r"i-[a-f0-9]{16,17}", row["instance_id"])):
        hold()
    selection = row["selection"]
    if (type(selection) is not dict or
            set(selection) != {"scope", "approved", "identity", "commands"} or
            selection["scope"].get("schema") != contract.SCOPE or
            selection["identity"] != contract.digest(selection["scope"]) or
            type(selection["approved"]) is not dict or
            not selection["approved"] or
            type(selection["commands"]) is not dict or
            set(selection["commands"]) != set(selection["approved"])):
        hold()
    for operation_id, sha in selection["approved"].items():
        if not contract.match(operation_id, contract.H32) or not contract.match(sha, contract.SHA):
            hold()
        cmd = selection["commands"][operation_id]
        if (type(cmd) is not dict or
                set(cmd) != {"approval_id", "script_sha256", "timeout_seconds"} or
                not contract.match(cmd["approval_id"], contract.H32) or
                not contract.match(cmd["script_sha256"], contract.SHA) or
                type(cmd["timeout_seconds"]) is not int or
                not 1 <= cmd["timeout_seconds"] <= 900):
            hold()
    try:
        key = base64.b64decode(row["operator_public_b64"], validate=True)
        signer = Ed25519PrivateKey.from_private_bytes(
            base64.b64decode(row["observation_private_b64"], validate=True))
        if len(key) != 32:
            hold()
    except (TypeError, ValueError):
        hold()

    paths = [Path(row[x]) for x in (
        "ledger_directory", "checkpoint_directory", "gateway_state_directory")]
    if any(not x.is_absolute() or not x.is_mount() for x in paths):
        hold()
    stats = [os.stat(x, follow_symlinks=False) for x in paths]
    if (len({s.st_dev for s in stats}) != 3 or
            any(s.st_uid != 0 or not stat.S_ISDIR(s.st_mode)
                or s.st_mode & 0o022 for s in stats)):
        hold()
    return row, selection, key, signer


class FixedSSMSender:
    def __init__(self, install):
        self.install = install

    def _session(self):
        # No IMDS, environment, inherited ~/.aws credentials, shared role, or
        # fallback. Only explicit owner-private short-lived credential bytes.
        data = json.loads(_read_root(CREDS, max_bytes=4096, mode=0o400))
        if (type(data) is not dict or
                set(data) != {"schema", "access_key", "secret_key",
                              "session_token", "expiry_unix",
                              "account_id", "region"} or
                data["schema"] != TOKEN_SCHEMA or
                data["account_id"] != self.install["aws_account_id"] or
                data["region"] != self.install["aws_region"] or
                type(data["access_key"]) is not str or
                not re.fullmatch(r"[A-Z0-9]{16,32}",data["access_key"]) or
                type(data["secret_key"]) is not str or
                not 30 <= len(data["secret_key"]) <= 128 or
                type(data["session_token"]) is not str or
                not 16 <= len(data["session_token"]) <= 8192 or
                type(data["expiry_unix"]) is not int or
                not time.time() + 60 < data["expiry_unix"] < time.time() + 3600):
            hold()
        import boto3
        return boto3.session.Session(
            aws_access_key_id=data["access_key"],
            aws_secret_access_key=data["secret_key"],
            aws_session_token=data["session_token"],
            region_name=self.install["aws_region"])

    def send_fixed(self, operation_id, command):
        if not contract.match(operation_id, contract.H32):
            hold()
        script = _read_root(SCRIPTS / (operation_id + ".sh"), max_bytes=32000)
        if ("sha256:" + hashlib.sha256(script).hexdigest() !=
                command["script_sha256"]):
            hold()
        # SendCommand has no idempotency token. SDK retries after a lost
        # acknowledgement could execute the same approved operation twice,
        # even though our durable ledger claims it only once.
        from botocore.config import Config
        client = self._session().client(
            "ssm", config=Config(connect_timeout=5, read_timeout=15,
                                 retries={"total_max_attempts": 1}))
        result = client.send_command(
            InstanceIds=[self.install["instance_id"]],
            DocumentName="AWS-RunShellScript",
            TimeoutSeconds=60,
            Parameters={"commands":[script.decode("utf-8")],
                        "executionTimeout":[str(command["timeout_seconds"])]})
        response = result.get("Command", {}).get("CommandId")
        if type(response) is not str or not 1 <= len(response) <= 128:
            hold()
        return response


def _systemd_socket():
    if (os.environ.get("LISTEN_PID") != str(os.getpid()) or
            os.environ.get("LISTEN_FDS") != "1"):
        hold()
    sock = socket.fromfd(3, socket.AF_UNIX, socket.SOCK_SEQPACKET)
    if (sock.getsockname() != SOCKET or
            (sock.type & 0xf) != socket.SOCK_SEQPACKET or
            sock.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1):
        hold()
    st = os.stat(SOCKET, follow_symlinks=False)
    if (not stat.S_ISSOCK(st.st_mode) or st.st_uid != 0 or
            stat.S_IMODE(st.st_mode) != 0o660):
        hold()
    return sock


def main():
    # Deliberately no CLI argument controlling paths, signer, target or AWS.
    # Source-only root/host-install candidates MUST NOT become a live SSM
    # issuer merely because someone manually starts their systemd units.
    if not NATIVE_SEND_ADMISSION_IMPLEMENTED:
        hold()
    if len(sys.argv) != 1:
        hold()
    policy, selection, operator, signer = installed()
    checkpoint = SeparateDurableCheckpoint(
        policy["checkpoint_directory"], owner_uid=0,
        gateway_volume_dev=os.stat(policy["gateway_state_directory"]).st_dev,
        owner_ledger_dev=os.stat(policy["ledger_directory"]).st_dev)
    ledger = ProtectedLedger(policy["ledger_directory"],owner_uid=0,
                             external_checkpoint=checkpoint)
    service = SelectedOwner(ledger,installed=selection,
                            pinned_operator_key=operator,
                            observation_signer=signer,
                            sender=FixedSSMSender(policy))
    sock = _systemd_socket()
    # Single-thread owner service. Locked commits precede any SSM mutation.
    # Interrupted connections cannot undo a durable claim.
    while True:
        connection, _ = sock.accept()
        with connection:
            connection.settimeout(8.0)
            try:
                serve_one(connection,service,
                          expected_uid=policy["peer_uid"],
                          expected_gid=policy["peer_gid"],
                          now=int(time.time()))
            except (OSError, ValueError, contract.OperationDenied):
                # One bounded, secret-free denial. No exception data or token.
                try:
                    connection.send(b'{"error":"protected-owner-denied"}')
                except OSError:
                    pass


if __name__ == "__main__":
    main()
