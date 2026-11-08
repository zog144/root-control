"""Protected Task C runtime installation selection and SSM observation.

Copyright (c) 2026 Alex Black. BSD-3-Clause OR GPL-3.0-only.
No runtime bootstrap: missing pinned operator, signed original mapping, genesis,
ledger, peer identity, signer or separately-issued short-lived AWS credentials
must deny. This module does not authorize starting the native owner unit.
"""
from __future__ import annotations
from functools import partial

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
from .graphical_s3_installation_checkpoint import S3InstallationCheckpoint
from .graphical_installation_storage_commit import verify_installed_storage_commit
from . import graphical_installation_storage_authority as installation_storage
from . import graphical_task_c_backend_observation as live_backend
from .graphical_task_c_runtime import TaskCExecutor
from .graphical_task_c_origin import verify_installed_evidence

RUNTIME_CONFIG = Path("/etc/zog/graphical-owner/task-c-runtime.json")
OPERATOR_PIN = Path("/etc/zog/graphical-owner/operator-public.key")
OBSERVATION_SECRET = Path("/etc/zog/graphical-owner/observation-private.key")
ORIGIN_ISSUER_PIN = Path("/etc/zog/graphical-owner/origin-issuer-public.key")
ORIGIN_EVIDENCE = Path("/etc/zog/graphical-owner/original-github-evidence.json")
SSM_SESSION = Path("/run/credentials/zog-graphical-owner.service/aws-session.json")
CHECKPOINT_SESSION = Path("/run/credentials/zog-graphical-owner.service/checkpoint-session.json")
LEDGER = Path("/var/lib/zog-graphical-owner-ledger")
RUNTIME_SCHEMA = "zog-protected-task-c-installed-runtime-v2"
INSTALLATION_RUNTIME_SCHEMA = "zog-protected-task-c-installed-runtime-v3"
# Explicit optional remote Task C enrollment; never a host boot prerequisite.
LOCAL_RUNTIME_SCHEMA = "zog-protected-task-c-installed-runtime-local-v1"
STORAGE_REGISTRY = Path("/etc/zog/graphical-owner/registered-installation.json")
REGISTRY_ISSUER_PIN = Path("/etc/zog/graphical-owner/registry-issuer-public.key")
INSTALLER_PIN = Path("/etc/zog/graphical-owner/storage-installer-public.key")
STORAGE_RECORD = LEDGER / "installation-storage-authority.json"
STORAGE_COMMIT = LEDGER / "installation-storage-commit.json"
STORAGE_APPROVAL = Path("/var/lib/zog-graphical-owner-authority/installation-storage-approval.json")
STORAGE_ANCHOR = Path("/var/lib/zog-graphical-owner-authority/installation-storage-anchor.json")

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



def _selected_installation_storage(row, selection, registry, operator, *, now):
    """Selected Task C installation storage requires operator approval and anchor.

    This is a source-side readback of already installed immutable authority.
    Actual mount UUID/PARTUUID, external S3 retention, installed wheel/RECORD,
    and service credentials remain independent native Work acceptance gates.
    """
    external = STORAGE_ANCHOR.parent
    if (not LEDGER.is_mount() or not external.is_mount()
            or os.stat(LEDGER).st_dev == os.stat(external).st_dev):
        hold()
    for mount in (LEDGER, external):
        st = os.lstat(mount)
        if (not stat.S_ISDIR(st.st_mode) or st.st_uid != 0
                or st.st_mode & 0o022):
            hold()
    registry_record = strict(_read_root(STORAGE_REGISTRY, max_bytes=4096))
    local_mode = row.get("schema") == LOCAL_RUNTIME_SCHEMA
    if (local_mode != (registry_record.get("schema") ==
                       installation_storage.LOCAL_SCHEMA)):
        hold()  # No silent downgrade or automatic signed-registry fallback.
    registry_pub = (None if local_mode else
                    _read_root(REGISTRY_ISSUER_PIN, max_bytes=32, mode=0o600))
    installer_pub = _read_root(INSTALLER_PIN, max_bytes=32, mode=0o600)
    storage_record = strict(_read_root(STORAGE_RECORD, max_bytes=4096))
    approval = strict(_read_root(STORAGE_APPROVAL, max_bytes=8192))
    accepted = strict(_read_root(STORAGE_COMMIT, max_bytes=4096))
    anchor = strict(_read_root(STORAGE_ANCHOR, max_bytes=4096))
    if (type(anchor) is not dict
            or set(anchor) != {
                "schema", "registry_sha256", "installation_scope_sha256",
                "anchor_identity_sha256", "commit_sha256",
                "ledger_fs_uuid", "authority_fs_uuid", "state_fs_uuid"}
            or anchor["schema"] !=
                "zog-task-c-installation-storage-external-anchor-v1"
            or any(anchor[k] != accepted[k] for k in (
                "registry_sha256", "installation_scope_sha256",
                "anchor_identity_sha256", "ledger_fs_uuid",
                "authority_fs_uuid", "state_fs_uuid"))
            or type(row.get("storage_authority")) is not dict
            or set(row["storage_authority"]) != {
                "schema", "registry_sha256", "installation_scope_sha256",
                "storage_authority_sha256", "storage_commit_sha256"}
            or row["storage_authority"]["schema"] !=
                "zog-task-c-installed-storage-selection-v1"
            or row["storage_authority"]["registry_sha256"] !=
                anchor["registry_sha256"]
            or row["storage_authority"]["installation_scope_sha256"] !=
                anchor["installation_scope_sha256"]
            or row["storage_authority"]["storage_authority_sha256"] !=
                contract.digest(storage_record)
            or row["storage_authority"]["storage_commit_sha256"] !=
                contract.digest(accepted)):
        hold()
    proof = verify_installed_storage_commit(
        registered_installation=registry_record,
        pinned_registry_public=registry_pub,
        storage_authority=storage_record,
        signed_storage_approval=approval,
        pinned_operator_public=operator,
        independently_retained_anchor_sha256=
            anchor["anchor_identity_sha256"],
        receipt=accepted, pinned_installer_public=installer_pub,
        independently_retained_commit_sha256=anchor["commit_sha256"],
        now=now, allow_local=local_mode)
    if (proof["installation_scope_sha256"] !=
            row["storage_authority"]["installation_scope_sha256"]
            or any(registry_record[k] != row[k] for k in (
                "host_id", "installation_id", "state_volume_id"))):
        hold()
    for item in registry.entries.values():
        req = item["owner_request"]
        scope = installation_storage.bind_operation_to_installation(
            registry=registry_record,
            pinned_registry_public=registry_pub,
            request=req, allow_local=local_mode)
        if (scope["installation_scope_sha256"] !=
                proof["installation_scope_sha256"]
                or scope["operation_scope_sha256"] != selection["identity"]
                or scope["request_sha256"] !=
                    selection["approved"][req["operation_id"]]):
            hold()
    checkpoint_policy = row["checkpoint"]
    for key, installed_key in (
        ("account_id", "checkpoint_account_id"),
        ("region", "checkpoint_region"),
        ("bucket", "checkpoint_bucket"),
        ("prefix", "checkpoint_prefix"),
        ("genesis_sha256", "checkpoint_genesis_sha256"),
        ("role_arn", "checkpoint_writer_role_arn"),
    ):
        if checkpoint_policy.get(key) != storage_record[installed_key]:
            hold()
    # Reopen the current physical STATE descriptor from host-install.
    # No registrar or observer signer is needed for direct privileged reads.
    observed = live_backend.require_live_backend_bound_identity(
        expected_registry=registry_record, allow_local=local_mode)
    if (observed["registry_sha256"] != contract.digest(registry_record)
            or observed["installation_scope_sha256"] !=
                proof["installation_scope_sha256"]):
        hold()
    # A signed and independently anchored installation commitment is
    # persistent after its short-lived provisioning grant expires; this does
    # not make it an operation grant or assert current native service GO.
    return proof["installation_scope_sha256"], storage_record

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
        "ssm", "origin_evidence_sha256", "origin_issuer_public_sha256",
    }
    installation_runtime = row.get("schema") in (
        INSTALLATION_RUNTIME_SCHEMA, LOCAL_RUNTIME_SCHEMA)
    if installation_runtime:
        expected = expected | {"storage_authority"}
    if (set(row) != expected
            or row["schema"] not in (
                RUNTIME_SCHEMA, INSTALLATION_RUNTIME_SCHEMA,
                LOCAL_RUNTIME_SCHEMA)
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
                             "observation_public_sha256", "origin_evidence_sha256",
                             "origin_issuer_public_sha256"))
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
    # The independently trusted GitHub event issuer is NOT the operator
    # grant signer and NOT a key supplied by the gateway or same request.
    origin_issuer = _read_root(ORIGIN_ISSUER_PIN, max_bytes=32, mode=0o600)
    origin_raw = _read_root(ORIGIN_EVIDENCE, max_bytes=16000)
    if (len(origin_issuer) != 32 or
            "sha256:" + hashlib.sha256(origin_issuer).hexdigest() !=
            row["origin_issuer_public_sha256"] or
            "sha256:" + hashlib.sha256(origin_raw).hexdigest() !=
            row["origin_evidence_sha256"] or origin_issuer == operator):
        hold()
    verify_installed_evidence(
        strict(origin_raw), registry=registry,
        pinned_issuer_key=origin_issuer, now=int(time.time()))
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

    if installation_runtime:
        # Authenticate the selected physical STATE backend/registry before
        # even opening privileged checkpoint-writer or SSM sessions.
        stable_scope, storage_record = _selected_installation_storage(
            row, selection, registry, operator, now=int(time.time()))
    checkpoint_session, checkpoint_access = _session(
        CHECKPOINT_SESSION, account=checkpoint_policy["account_id"],
        region=checkpoint_policy["region"], role_arn=checkpoint_policy["role_arn"])
    ssm_session, ssm_access = _session(
        SSM_SESSION, account=ssm_policy["account_id"],
        region=ssm_policy["region"], role_arn=ssm_policy["role_arn"])
    if checkpoint_access == ssm_access:
        hold()
    if installation_runtime:
        checkpoint = S3InstallationCheckpoint(
            checkpoint_session.client("s3", config=S3_TIMEOUT),
            bucket=checkpoint_policy["bucket"],
            prefix=checkpoint_policy["prefix"],
            account_id=checkpoint_policy["account_id"],
            installation_scope_sha256=stable_scope,
            registry_sha256=storage_record["registry_sha256"],
            genesis_sha256=checkpoint_policy["genesis_sha256"],
            approved={selection["identity"]: dict(selection["approved"])})
    else:
        # Historical v2 selection remains exact and unmodified. Never treat
        # its request-bound genesis as the new installation-level genesis.
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
                                          instance_id=ssm_policy["instance_id"]),
        # The local mode is a protected Task C enrollment, not local boot.
        # Re-check actual /state before every claim/SSM or observation.
        backend_recheck=(partial(
            live_backend.require_live_backend_bound_identity,
            expected_registry=strict(_read_root(STORAGE_REGISTRY, max_bytes=4096)),
            allow_local=row["schema"] == LOCAL_RUNTIME_SCHEMA)
            if installation_runtime else None))
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
