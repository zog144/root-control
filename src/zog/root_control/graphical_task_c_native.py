"""Protected Task C runtime installation selection and SSM observation.

Copyright (c) 2026 Alex Black. BSD-3-Clause OR GPL-3.0-only.
No runtime bootstrap: missing pinned operator, signed original mapping, genesis,
ledger, peer identity, signer or separately-issued short-lived AWS credentials
must deny. This module does not authorize starting the native owner unit.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time

from botocore.config import Config
from botocore.exceptions import ClientError, BotoCoreError
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from . import graphical_operation_owner_source as contract
from . import graphical_task_c_owner as taskc
from .graphical_native_owner import ProtectedLedger, SelectedOwner, hold, strict
from .graphical_owner_service import FixedSSMSender, _read_root, TOKEN_SCHEMA
from .graphical_s3_checkpoint import S3AppendOnlyCheckpoint
from .graphical_task_c_runtime import TaskCExecutor

RUNTIME_CONFIG = Path("/etc/zog/graphical-owner/task-c-runtime.json")
OPERATOR_PIN = Path("/etc/zog/graphical-owner/operator-public.key")
OBSERVATION_SECRET = Path("/etc/zog/graphical-owner/observation-private.key")
SSM_SESSION = Path("/run/credentials/zog-graphical-owner.service/aws-session.json")
CHECKPOINT_SESSION = Path("/run/credentials/zog-graphical-owner.service/checkpoint-session.json")
LEDGER = Path("/var/lib/zog-graphical-owner-ledger")
RUNTIME_SCHEMA = "zog-protected-task-c-installed-runtime-v2"

S3_TIMEOUT = Config(connect_timeout=5, read_timeout=15,
                    retries={"total_max_attempts": 1})
SSM_TIMEOUT = Config(connect_timeout=5, read_timeout=15,
                     retries={"total_max_attempts": 1})
ROLE = re.compile(r"arn:aws:iam::([0-9]{12}):role/([A-Za-z0-9_+=,.@-]{1,64})\Z")
REGION = re.compile(r"[a-z]{2}-[a-z]+-[0-9]\Z")
INSTANCE = re.compile(r"i-[a-f0-9]{16,17}\Z")


def _session(path, *, account, region, role_arn):
    """Use explicit private credential bytes; never botocore's default chain."""
    row = strict(_read_root(path, max_bytes=12288, mode=0o400))
    if (set(row) != {"schema", "access_key", "secret_key", "session_token",
                     "expiry_unix", "account_id", "region"}
            or row["schema"] != TOKEN_SCHEMA
            or row["account_id"] != account or row["region"] != region
            or type(row["expiry_unix"]) is not int
            or not time.time() + 60 < row["expiry_unix"] < time.time() + 3600
            or type(row["access_key"]) is not str
            or not re.fullmatch(r"[A-Z0-9]{16,32}", row["access_key"])
            or type(row["secret_key"]) is not str
            or not 30 <= len(row["secret_key"]) <= 128
            or type(row["session_token"]) is not str
            or not 16 <= len(row["session_token"]) <= 8192):
        hold()
    import boto3
    session = boto3.session.Session(
        aws_access_key_id=row["access_key"],
        aws_secret_access_key=row["secret_key"],
        aws_session_token=row["session_token"],
        region_name=region)
    # Verify the real assumed-role identity rather than treating a label
    # or a credential file name as proof of independently granted AWS rights.
    try:
        identity = session.client("sts", config=SSM_TIMEOUT).get_caller_identity()
        m = ROLE.fullmatch(role_arn)
        expected = ("arn:aws:sts::" + m.group(1) + ":assumed-role/" +
                    m.group(2) + "/") if m is not None else None
        if (expected is None or identity.get("Account") != account
                or not str(identity.get("Arn", "")).startswith(expected)):
            hold()
    except (ClientError, BotoCoreError, OSError):
        hold()
    return session, row["access_key"]


class FixedSSMSessionSender(FixedSSMSender):
    """Same fixed document/script digest code, using pinned SSM-role session."""
    def __init__(self, install, session):
        super().__init__(install)
        self._selected_session = session

    def _session(self):
        return self._selected_session


class SSMOriginalInspector:
    """Read only one exact original command by CommandId and fixed instance."""
    def __init__(self, session, *, instance_id):
        if type(instance_id) is not str or INSTANCE.fullmatch(instance_id) is None:
            hold()
        self.client = session.client("ssm", config=SSM_TIMEOUT)
        self.instance_id = instance_id

    def inspect(self, command_id):
        from .graphical_task_c_runtime import COMMAND_ID
        if type(command_id) is not str or COMMAND_ID.fullmatch(command_id) is None:
            hold()
        try:
            row = self.client.get_command_invocation(
                CommandId=command_id, InstanceId=self.instance_id)
        except (ClientError, BotoCoreError, OSError):
            # Includes unobserved eventual consistency, expired credentials,
            # loss of network and any ambiguous AWS result. Only a later
            # READ-ONLY observe-original can inspect it; never resend.
            hold()
        if (row.get("CommandId") != command_id
                or row.get("InstanceId") != self.instance_id):
            hold()
        status = row.get("Status")
        if status == "Success" and type(row.get("ResponseCode")) is int:
            return "success" if row["ResponseCode"] == 0 else "failed"
        if status in ("Pending", "InProgress", "Delayed", "Cancelling"):
            return "pending"
        if status in ("Failed", "Cancelled", "TimedOut"):
            return "failed"
        hold()


def installed_runtime():
    """Construct the ONLY candidate Task C service from root-protected bytes.

    This is not a native admission decision. Work must independently attest
    executable/RECORD, genuine Host/STATE, current signer and IAM custody.
    """
    if os.geteuid() != 0:
        hold()
    row = strict(_read_root(RUNTIME_CONFIG, max_bytes=65536))
    expected = {
        "schema", "boot_id", "host_id", "installation_id", "state_volume_id",
        "gateway_uid", "gateway_gid", "gateway_cgroup", "gateway_executable_sha256",
        "ledger_directory", "gateway_state_directory", "operator_key_sha256",
        "observation_public_sha256", "originals", "commands", "checkpoint",
        "ssm", "origin_evidence_sha256",
    }
    if (set(row) != expected or row["schema"] != RUNTIME_SCHEMA
            or row["boot_id"] != Path("/proc/sys/kernel/random/boot_id").read_text().strip()
            or any(not contract.match(row[k], contract.H64)
                   for k in ("host_id", "installation_id", "state_volume_id"))
            or type(row["gateway_uid"]) is not int or row["gateway_uid"] < 1000
            or type(row["gateway_gid"]) is not int or row["gateway_gid"] <= 0
            or type(row["gateway_cgroup"]) is not str
            or not row["gateway_cgroup"].startswith("/system.slice/")
            or not row["gateway_cgroup"].endswith(".service")
            or any(not contract.match(row[k], contract.SHA)
                   for k in ("gateway_executable_sha256", "operator_key_sha256",
                             "observation_public_sha256", "origin_evidence_sha256"))
            or row["ledger_directory"] != str(LEDGER)
            or type(row["gateway_state_directory"]) is not str
            or not row["gateway_state_directory"].startswith("/")):
        hold()
    gateway_mount = Path(row["gateway_state_directory"])
    if (not LEDGER.is_mount() or not gateway_mount.is_mount()
            or os.stat(LEDGER).st_dev == os.stat(gateway_mount).st_dev):
        hold()
    for path in (LEDGER, gateway_mount):
        info = os.lstat(path)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                or info.st_mode & 0o022):
            hold()

    operator = _read_root(OPERATOR_PIN, max_bytes=32, mode=0o600)
    signer_raw = _read_root(OBSERVATION_SECRET, max_bytes=32, mode=0o400)
    if (len(operator) != 32 or len(signer_raw) != 32
            or "sha256:" + hashlib.sha256(operator).hexdigest() != row["operator_key_sha256"]):
        hold()
    try:
        signer = Ed25519PrivateKey.from_private_bytes(signer_raw)
    except ValueError:
        hold()
    signer_pub = signer.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if ("sha256:" + hashlib.sha256(signer_pub).hexdigest() !=
            row["observation_public_sha256"]):
        hold()

    registry = taskc.ProtectedOriginalRegistry(
        row["originals"], pinned_operator_public_key=operator)
    if (type(row["commands"]) is not dict
            or set(row["commands"]) != set(registry.entries)):
        hold()
    selected_scope = None
    selection = {"approved": {}, "commands": dict(row["commands"])}
    for operation_id, entry in registry.entries.items():
        req = entry["owner_request"]
        scope = contract.scope_from_request(req)
        if (selected_scope is not None and scope != selected_scope
                or req["host_id"] != row["host_id"]
                or req["installation_id"] != row["installation_id"]
                or req["state_volume_id"] != row["state_volume_id"]):
            hold()
        selected_scope = scope
        cmd = row["commands"][operation_id]
        if (type(cmd) is not dict
                or set(cmd) != {"approval_id", "script_sha256", "timeout_seconds"}
                or not contract.match(cmd["approval_id"], contract.H32)
                or not contract.match(cmd["script_sha256"], contract.SHA)
                or type(cmd["timeout_seconds"]) is not int
                or not 1 <= cmd["timeout_seconds"] <= 900):
            hold()
        selection["approved"][operation_id] = contract.digest(req)
    selection["scope"] = selected_scope
    selection["identity"] = contract.digest(selected_scope)

    checkpoint_policy = row["checkpoint"]
    ssm_policy = row["ssm"]
    if (type(checkpoint_policy) is not dict
            or set(checkpoint_policy) != {"bucket", "prefix", "account_id",
                                         "region", "genesis_sha256", "role_arn"}
            or type(ssm_policy) is not dict
            or set(ssm_policy) != {"account_id", "region", "instance_id", "role_arn"}
            or checkpoint_policy["account_id"] != ssm_policy["account_id"]
            or checkpoint_policy["region"] != ssm_policy["region"]
            or type(ssm_policy["region"]) is not str
            or REGION.fullmatch(ssm_policy["region"]) is None
            or type(ssm_policy["instance_id"]) is not str
            or INSTANCE.fullmatch(ssm_policy["instance_id"]) is None
            or checkpoint_policy["role_arn"] == ssm_policy["role_arn"]
            or not ROLE.fullmatch(checkpoint_policy["role_arn"])
            or not ROLE.fullmatch(ssm_policy["role_arn"])):
        hold()

    checkpoint_session, checkpoint_access = _session(
        CHECKPOINT_SESSION, account=checkpoint_policy["account_id"],
        region=checkpoint_policy["region"], role_arn=checkpoint_policy["role_arn"])
    ssm_session, ssm_access = _session(
        SSM_SESSION, account=ssm_policy["account_id"],
        region=ssm_policy["region"], role_arn=ssm_policy["role_arn"])
    if checkpoint_access == ssm_access:
        hold()
    checkpoint = S3AppendOnlyCheckpoint(
        checkpoint_session.client("s3", config=S3_TIMEOUT),
        bucket=checkpoint_policy["bucket"], prefix=checkpoint_policy["prefix"],
        account_id=checkpoint_policy["account_id"],
        scope_digest=selection["identity"],
        genesis_sha256=checkpoint_policy["genesis_sha256"])
    # Check genesis/current history BEFORE admitting a socket, never create it.
    if checkpoint.inspect_current(selection["identity"])["revoked"]:
        hold()
    ledger = ProtectedLedger(LEDGER, owner_uid=0, external_checkpoint=checkpoint)
    sender = FixedSSMSessionSender(
        {"instance_id": ssm_policy["instance_id"]}, ssm_session)
    owner = SelectedOwner(ledger, installed=selection,
                          pinned_operator_key=operator,
                          observation_signer=signer, sender=sender)
    executor = TaskCExecutor(
        registry, protected_owner=owner,
        ssm_inspector=SSMOriginalInspector(ssm_session,
                                          instance_id=ssm_policy["instance_id"]))
    return executor, row


def installed_peer(pid, policy):
    """Source-level process witness. Native Work must verify actual cgroup
    ownership/InvocationID and immutable installed bytes independently."""
    if type(pid) is not int or pid <= 0:
        hold()
    directory = Path("/proc") / str(pid)
    try:
        # Hold a proc directory descriptor and check starttime on both sides
        # of source/peer inspection to reject a recycled PID.
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            def proc_read(name):
                child = os.open(name, os.O_RDONLY | os.O_CLOEXEC, dir_fd=fd)
                try:
                    return os.read(child, 65536)
                finally:
                    os.close(child)
            before = proc_read("stat").rsplit(b")", 1)[1].split()[19]
            cgroup = proc_read("cgroup").decode("ascii").splitlines()
            if not any(line == "0::" + policy["gateway_cgroup"] for line in cgroup):
                hold()
            executable = directory / "exe"
            h = hashlib.sha256()
            with open(executable, "rb") as stream:
                while chunk := stream.read(65536):
                    h.update(chunk)
            if "sha256:" + h.hexdigest() != policy["gateway_executable_sha256"]:
                hold()
            after = proc_read("stat").rsplit(b")", 1)[1].split()[19]
            if before != after:
                hold()
        finally:
            os.close(fd)
    except (OSError, ValueError, UnicodeError, IndexError):
        hold()
