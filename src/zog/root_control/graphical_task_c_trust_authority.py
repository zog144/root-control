"""Selected original read-only graphical trust authority; native admission is separate.

This module never issues SSM, performs S3 writes, creates an authority or accepts
gateway-provided configuration. Only independently retained original records,
operator-signed purpose approval, original issuer evidence and root-installed
source/credential bytes can select a broker. Source review is not native GO.
"""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import stat
import sys
import time

from botocore.config import Config
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)

from . import graphical_operation_owner_source as original
from . import graphical_task_c_owner as taskc
from . import graphical_task_c_origin as issuer
from .graphical_native_owner import hold, strict
from .graphical_owner_service import _read_root
from .graphical_task_c_native import _session
from .graphical_s3_checkpoint import S3AppendOnlyCheckpoint
from .graphical_s3_installation_checkpoint import S3InstallationCheckpoint
from . import graphical_installation_storage_authority as installation_storage
from . import graphical_task_c_v3_readonly as v3_readonly
from . import graphical_task_c_native as owner_native
from . import graphical_task_c_backend_observation as live_backend

OWNER_SOURCE = "5ad7d5ed72d1b72edc767a658de28506791a74d4"
BROKER_SOURCE = "0ea6d583fa441527f45dabbbf542731560644a72"
PURPOSE_SCHEMA = "zog-task-c-original-readonly-broker-approval-v1"
PURPOSE_DOMAIN = b"zog-task-c-original-readonly-broker-approval-v1\0"
ORIGINAL_SCHEMA = "zog-task-c-original-checkpoint-installation-v1"
RESERVATION_SCHEMA = "zog-task-c-original-checkpoint-reservation-v1"
ORIGINAL_FIELDS = frozenset((
    "schema", "host_id", "installation_id", "state_volume_id",
    "checkpoint_account_id", "checkpoint_region", "checkpoint_bucket",
    "checkpoint_prefix", "checkpoint_scope_sha256",
    "checkpoint_genesis_sha256", "checkpoint_role_arn",
    "root_source_revision",
))
APPROVAL_FIELDS = frozenset((
    "schema", "pin_sha256", "original_checkpoint_sha256",
    "original_event_sha256", "operator_public_sha256", "issuer_public_sha256",
    "owner_source_revision", "broker_source_revision",
    "readonly_role_arn", "writer_role_arn", "ssm_role_arn",
    "host_id", "installation_id", "state_volume_id", "scope_sha256",
    "gateway_uid", "gateway_gid", "gateway_cgroup",
    "gateway_executable_sha256", "expires_at", "signature_ed25519",
))
ROLE = re.compile(r"arn:aws:iam::([0-9]{12}):role/[A-Za-z0-9_+=,.@-]{1,64}\Z")
S3_CONFIG = Config(connect_timeout=5, read_timeout=15,
                   retries={"total_max_attempts": 1})

# Independently installed paths; no RPC, gateway STATE, ENV or fallback.
ROOT = Path("/etc/zog/graphical-owner")
OWNER_REGISTRY = ROOT / "task-c-runtime.json"
OPERATOR = ROOT / "operator-public.key"
ISSUER = ROOT / "origin-issuer-public.key"
ISSUER_EVENT = ROOT / "original-github-evidence.json"
OBSERVATION_PUBLIC = ROOT / "observation-public.key"
GATEWAY_PIN = ROOT / "gateway-trust-pin.json"
BROKER_CONFIG = ROOT / "trust-broker-identity.json"
LOCAL_ORIGINAL = Path("/var/lib/zog-graphical-owner-ledger")
ANCHOR = Path("/var/lib/zog-graphical-owner-authority")
ORIGINAL_FILE = LOCAL_ORIGINAL / "original-checkpoint-installation.json"
ORIGINAL_RESERVED = LOCAL_ORIGINAL / "original-checkpoint-installation.reserved"
EXTERNAL_RESERVED = ANCHOR / "original-checkpoint-installation.external-anchor"
PURPOSE_APPROVAL = ANCHOR / "trust-broker-approval.json"
READ_CREDENTIAL = Path(
    "/run/credentials/zog-graphical-trust.service/read-only-checkpoint.json")
SIGNING_CREDENTIAL = Path(
    "/run/credentials/zog-graphical-trust.service/broker-private.key")


def digest_bytes(raw):
    if type(raw) is not bytes:
        hold()
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _checked_json(path, *, maximum=65536, mode=0o600):
    raw = _read_root(path, max_bytes=maximum, mode=mode)
    return raw, strict(raw)


def read_original_record():
    """Read original plus irreversible local and independent anchor.

    Never create or repair a missing record. Different mounted storage is
    necessary, but Work must separately prove its external retention/custody.
    """
    if (os.geteuid() != 0 or not LOCAL_ORIGINAL.is_mount()
            or not ANCHOR.is_mount()
            or os.stat(LOCAL_ORIGINAL).st_dev == os.stat(ANCHOR).st_dev):
        hold()
    original_raw, record = _checked_json(ORIGINAL_FILE, maximum=4096)
    _, local = _checked_json(ORIGINAL_RESERVED, maximum=4096)
    _, external = _checked_json(EXTERNAL_RESERVED, maximum=4096)
    if (set(record) != ORIGINAL_FIELDS
            or record["schema"] != ORIGINAL_SCHEMA
            or record["root_source_revision"] != OWNER_SOURCE):
        hold()
    reservation = {"schema": RESERVATION_SCHEMA,
                   "identity_sha256": digest_bytes(original_raw)}
    if local != reservation or external != reservation:
        hold()
    return record, digest_bytes(original_raw)


def verify_original_selection(
    *, record, record_sha, root_row, broker_config, registry, evidence,
    operator_key, issuer_key, observation_public, pin,
    pin_sha, approval, broker_signer, selected_broker_sha, now,
):
    """Pure verification of pre-existing protected bytes; cannot mint approvals.

    This function requires an *independently signed* purpose approval bound to
    the original checkpoint, selected read-only role and exact broker pin.
    It does not assert IAM effective policies, storage or native installation.
    """
    from zog.host_deploy.gateway import graphics_owner_trust_history as trust

    if (type(record) is not dict or set(record) != ORIGINAL_FIELDS
            or record.get("schema") != ORIGINAL_SCHEMA
            or record.get("root_source_revision") != OWNER_SOURCE
            or record_sha != digest_bytes(original.canonical(record))
            or not isinstance(registry, taskc.ProtectedOriginalRegistry)
            or type(root_row) is not dict
            or type(broker_config) is not dict
            or set(broker_config) != {
                "schema", "broker_source_revision", "root_source_revision",
                "gateway_uid", "gateway_gid", "gateway_cgroup",
                "gateway_executable_sha256", "boot_id"}
            or broker_config["schema"] !=
                "zog-task-c-readonly-broker-native-selection-v1"
            or broker_config["broker_source_revision"] != BROKER_SOURCE
            or broker_config["root_source_revision"] != OWNER_SOURCE
            or type(broker_config["gateway_uid"]) is not int
            or broker_config["gateway_uid"] < 1000
            or type(broker_config["gateway_gid"]) is not int
            or broker_config["gateway_gid"] <= 0
            or type(broker_config["gateway_cgroup"]) is not str
            or not broker_config["gateway_cgroup"].startswith("/system.slice/")
            or not broker_config["gateway_cgroup"].endswith(".service")
            or not original.match(broker_config["gateway_executable_sha256"], original.SHA)
            or root_row.get("schema") !=
                "zog-protected-task-c-installed-runtime-v2"
            or type(operator_key) is not bytes or len(operator_key) != 32
            or type(issuer_key) is not bytes or len(issuer_key) != 32
            or operator_key == issuer_key
            or registry.key != operator_key
            or type(observation_public) is not bytes
            or len(observation_public) != 32
            or not isinstance(broker_signer, Ed25519PrivateKey)
            or type(pin) is not dict or set(pin) != trust.PIN_KEYS
            or pin.get("schema") != "zog-graphical-task-c-gateway-trust-pin-v1"
            or type(approval) is not dict or set(approval) != APPROVAL_FIELDS
            or approval.get("schema") != PURPOSE_SCHEMA
            or type(now) is not int
            or type(approval.get("expires_at")) is not int
            or not now <= approval["expires_at"] <= now + 900
            or not original.match(selected_broker_sha, original.SHA)):
        hold()
    if (record["host_id"] != root_row.get("host_id")
            or record["installation_id"] != root_row.get("installation_id")
            or record["state_volume_id"] != root_row.get("state_volume_id")):
        hold()
    try:
        source = original.digest(
            original.scope_from_request(next(iter(registry.entries.values()))[
                "owner_request"]))
    except (StopIteration, KeyError, TypeError):
        hold()
    if (record["checkpoint_scope_sha256"] != source
            or type(root_row.get("checkpoint")) is not dict
            or type(root_row.get("ssm")) is not dict):
        hold()
    # Even a signed registry may contain several individually signed entries;
    # an installed broker must not combine different Host/STATE/scope epochs.
    for selected in registry.entries.values():
        req = selected["owner_request"]
        if (original.digest(original.scope_from_request(req)) != source
                or req["host_id"] != record["host_id"]
                or req["installation_id"] != record["installation_id"]
                or req["state_volume_id"] != record["state_volume_id"]):
            hold()

    expected_public = broker_signer.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if (pin["broker_public_key"] != expected_public.hex()
            or pin["owner_observation_public_key"] != observation_public.hex()
            or pin["scope_sha256"] != source
            or pin["installation_id"] != record["installation_id"]
            or pin["state_volume_id"] != record["state_volume_id"]
            or pin["original_checkpoint_sha256"] != record_sha
            or pin["installed_owner_source"] != OWNER_SOURCE
            or pin["installed_broker_source"] != selected_broker_sha[7:]
            or pin_sha != digest_bytes(trust.canonical(pin))):
        hold()

    expected_approval = {
        "schema": PURPOSE_SCHEMA,
        "pin_sha256": pin_sha,
        "original_checkpoint_sha256": record_sha,
        "original_event_sha256": digest_bytes(original.canonical(evidence)),
        "operator_public_sha256": digest_bytes(operator_key),
        "issuer_public_sha256": digest_bytes(issuer_key),
        "owner_source_revision": OWNER_SOURCE,
        "broker_source_revision": BROKER_SOURCE,
        "readonly_role_arn": approval.get("readonly_role_arn"),
        "writer_role_arn": record["checkpoint_role_arn"],
        "ssm_role_arn": root_row.get("ssm", {}).get("role_arn"),
        "host_id": record["host_id"],
        "installation_id": record["installation_id"],
        "state_volume_id": record["state_volume_id"],
        "scope_sha256": source,
        "gateway_uid": broker_config["gateway_uid"],
        "gateway_gid": broker_config["gateway_gid"],
        "gateway_cgroup": broker_config["gateway_cgroup"],
        "gateway_executable_sha256": broker_config["gateway_executable_sha256"],
        "expires_at": approval["expires_at"],
    }
    if (not original.match(approval["pin_sha256"], original.SHA)
            or not ROLE.fullmatch(approval["readonly_role_arn"])
            or not ROLE.fullmatch(expected_approval["writer_role_arn"])
            or not ROLE.fullmatch(expected_approval["ssm_role_arn"])
            or len({
                approval["readonly_role_arn"], expected_approval["writer_role_arn"],
                expected_approval["ssm_role_arn"]}) != 3
            or ROLE.fullmatch(approval["readonly_role_arn"]).group(1) !=
                    record["checkpoint_account_id"]
            or any(approval.get(k) != v for k, v in expected_approval.items())):
        hold()
    try:
        signature = base64.b64decode(
            approval["signature_ed25519"], validate=True)
        if (len(signature) != 64 or
                base64.b64encode(signature).decode("ascii") !=
                approval["signature_ed25519"]):
            hold()
        Ed25519PublicKey.from_public_bytes(operator_key).verify(
            signature, PURPOSE_DOMAIN + original.canonical(expected_approval))
    except (ValueError, TypeError, InvalidSignature):
        hold()

    issuer.verify_installed_evidence(
        evidence, registry=registry, pinned_issuer_key=issuer_key, now=now)
    if (root_row.get("operator_key_sha256") != digest_bytes(operator_key)
            or root_row.get("origin_issuer_public_sha256") != digest_bytes(issuer_key)
            or root_row.get("origin_evidence_sha256") !=
                digest_bytes(original.canonical(evidence))
            or root_row.get("observation_public_sha256") !=
                digest_bytes(observation_public)
            or root_row.get("checkpoint", {}).get("account_id") !=
                record["checkpoint_account_id"]
            or root_row["checkpoint"].get("region") !=
                record["checkpoint_region"]
            or root_row["checkpoint"].get("bucket") !=
                record["checkpoint_bucket"]
            or root_row["checkpoint"].get("prefix") !=
                record["checkpoint_prefix"]
            or root_row["checkpoint"].get("genesis_sha256") !=
                record["checkpoint_genesis_sha256"]
            or root_row["checkpoint"].get("role_arn") !=
                record["checkpoint_role_arn"]):
        hold()
    return approval["readonly_role_arn"], source


class GetObjectOnly:
    """Capability-reduced SDK adapter: no PutObject/ListBucket/SSM methods.

    This does NOT prove the actual principal lacks extra effective AWS rights.
    A missing GetObject that returns AccessDenied holds in S3AppendOnlyCheckpoint.
    """
    __slots__ = ("__get",)

    def __init__(self, s3_client):
        self.__get = s3_client.get_object

    def get_object(self, **kwargs):
        return self.__get(**kwargs)


def _installed_gateway_source_digest():
    from zog.host_deploy.gateway.graphics_owner_trust_install import SOURCES
    raw = bytearray()
    for name in sorted(SOURCES):
        spec = importlib.util.find_spec(name)
        if spec is None or spec.origin is None or not spec.origin.endswith(".py"):
            hold()
        contents = _read_root(Path(spec.origin), max_bytes=131072, mode=0o644)
        raw.extend(name.encode("ascii") + b"\0" + contents + b"\0")
    return digest_bytes(bytes(raw))


ROOT_V3_SOURCES = (
    "zog.root_control.graphical_task_c_trust_authority",
    "zog.root_control.graphical_task_c_v3_readonly",
    "zog.root_control.graphical_task_c_native",
    "zog.root_control.graphical_task_c_runtime",
    "zog.root_control.graphical_task_c_backend_observation",
    "zog.root_control.graphical_installation_storage_authority",
    "zog.root_control.graphical_installation_storage_commit",
    "zog.root_control.graphical_s3_installation_checkpoint",
    "zog.root_control.graphical_task_c_owner",
)


def _installed_v3_root_source_digest():
    """Exact installed readable module bytes, separately pinned by installer."""
    buf = bytearray()
    for name in sorted(ROOT_V3_SOURCES):
        spec = importlib.util.find_spec(name)
        if spec is None or spec.origin is None or not spec.origin.endswith(".py"):
            hold()
        raw = _read_root(Path(spec.origin), max_bytes=131072, mode=0o644)
        buf.extend(name.encode("ascii") + b"\0" + raw + b"\0")
    return digest_bytes(bytes(buf))


def installed_readonly_authority():
    """Read-only constructor for the *separately disabled* trust broker.

    No first-install, external S3 genesis, IMDS, writer/SSM credential source,
    pin generation, service enablement or gateway-controlled environment.
    """
    from zog.host_deploy.gateway.graphics_owner_trust_daemon import (
        InstalledReadOnlyAuthority,
    )
    if os.geteuid() != 0 or sys.argv != [sys.argv[0]]:
        hold()
    _, config = _checked_json(BROKER_CONFIG, maximum=8192)
    _, root_row = _checked_json(OWNER_REGISTRY)
    selected_v3 = root_row.get("schema") in (
        owner_native.INSTALLATION_RUNTIME_SCHEMA, owner_native.LOCAL_RUNTIME_SCHEMA)
    required_config_schema = (v3_readonly.BROKER_CONFIG_SCHEMA if selected_v3
                              else "zog-task-c-readonly-broker-native-selection-v1")
    expected_config = (
        {"schema", "broker_source_sha256", "root_source_sha256",
         "gateway_uid", "gateway_gid", "gateway_cgroup",
         "gateway_executable_sha256", "boot_id"} if selected_v3 else
        {"schema", "broker_source_revision", "root_source_revision",
         "gateway_uid", "gateway_gid", "gateway_cgroup",
         "gateway_executable_sha256", "boot_id"})
    if (type(config) is not dict or set(config) != expected_config
            or config["schema"] != required_config_schema
            or (selected_v3 and (
                config["root_source_sha256"] != _installed_v3_root_source_digest()
                or config["broker_source_sha256"] !=
                    _installed_gateway_source_digest()))
            or (not selected_v3 and (
                config["broker_source_revision"] != BROKER_SOURCE
                or config["root_source_revision"] != OWNER_SOURCE))
            or config["boot_id"] != Path("/proc/sys/kernel/random/boot_id").read_text().strip()
            or type(config["gateway_uid"]) is not int
            or config["gateway_uid"] < 1000
            or type(config["gateway_gid"]) is not int
            or config["gateway_gid"] <= 0
            or type(config["gateway_cgroup"]) is not str
            or not config["gateway_cgroup"].startswith("/system.slice/")
            or not config["gateway_cgroup"].endswith(".service")
            or not original.match(config["gateway_executable_sha256"], original.SHA)):
        hold()

    # For v3, original storage identity is the independently committed
    # installation authority, not a manufactured v1 request-bound record.
    # V2 retains the original reserved-record/anchor selector verbatim.
    if not selected_v3:
        record, record_sha = read_original_record()
    operator_key = _read_root(OPERATOR, max_bytes=32)
    issuer_key = _read_root(ISSUER, max_bytes=32)
    _, evidence = _checked_json(ISSUER_EVENT, maximum=16000)
    observation_public = _read_root(OBSERVATION_PUBLIC, max_bytes=32)
    pin_raw, pin = _checked_json(GATEWAY_PIN, maximum=2048, mode=0o644)
    _, approval = _checked_json(PURPOSE_APPROVAL, maximum=8192)
    secret = _read_root(SIGNING_CREDENTIAL, max_bytes=32, mode=0o400)
    if len(secret) != 32:
        hold()
    try:
        signer = Ed25519PrivateKey.from_private_bytes(secret)
    except ValueError:
        hold()
    registry = taskc.ProtectedOriginalRegistry(
        root_row["originals"], pinned_operator_public_key=operator_key)
    if selected_v3:
        scopes = {
            original.digest(original.scope_from_request(e["owner_request"]))
            for e in registry.entries.values()
        }
        if len(scopes) != 1:
            hold()
        scope = scopes.pop()
        selection = {"identity": scope, "approved": {
            e["owner_request"]["operation_id"]:
                original.digest(e["owner_request"])
            for e in registry.entries.values()
        }}
        # Checks two independent protected mounts, existing operator-signed
        # storage approval, immutable installer commit and external anchor.
        # Local mode requires no invented registry or observation signer.
        _, record = owner_native._selected_installation_storage(
            root_row, selection, registry, operator_key, now=int(time.time()))
        # The root selector has now checked this fresh protected backend
        # against the signed registry. Recheck on each broker IPC as well.
        _, commit = _checked_json(owner_native.STORAGE_COMMIT, maximum=4096)
        readonly_role, scope = v3_readonly.verify_installation_broker_selection(
            storage_record=record, storage_commit=commit, root_row=root_row,
            broker_config=config, registry=registry, evidence=evidence,
            operator_key=operator_key, issuer_key=issuer_key,
            observation_public=observation_public, pin=pin,
            pin_sha=digest_bytes(pin_raw), approval=approval,
            broker_signer=signer,
            selected_broker_sha=_installed_gateway_source_digest(),
            selected_root_source_sha=_installed_v3_root_source_digest(),
            now=int(time.time()))
    else:
        readonly_role, scope = verify_original_selection(
            record=record, record_sha=record_sha, root_row=root_row,
            broker_config=config, registry=registry, evidence=evidence,
            operator_key=operator_key,
            issuer_key=issuer_key, observation_public=observation_public,
            pin=pin, pin_sha=digest_bytes(pin_raw), approval=approval,
            broker_signer=signer,
            selected_broker_sha=_installed_gateway_source_digest(),
            now=int(time.time()))

    # The only S3 session derives from this fixed systemd LoadCredential file.
    # No owner writer/SSM credential, default SDK chain or IMDS fallback.
    session, _ = _session(
        READ_CREDENTIAL, account=record["checkpoint_account_id"],
        region=record["checkpoint_region"], role_arn=readonly_role)
    readonly = GetObjectOnly(session.client("s3", config=S3_CONFIG))
    if selected_v3:
        checkpoint = S3InstallationCheckpoint(
            readonly, bucket=record["checkpoint_bucket"],
            prefix=record["checkpoint_prefix"],
            account_id=record["checkpoint_account_id"],
            installation_scope_sha256=record["installation_scope_sha256"],
            registry_sha256=record["registry_sha256"],
            genesis_sha256=record["checkpoint_genesis_sha256"],
            approved={scope: selection["approved"]})
    else:
        checkpoint = S3AppendOnlyCheckpoint(
            readonly, bucket=record["checkpoint_bucket"],
            prefix=record["checkpoint_prefix"],
            account_id=record["checkpoint_account_id"],
            scope_digest=scope,
            genesis_sha256=record["checkpoint_genesis_sha256"])
    # A 403 for the first missing event is NOT a valid end-of-history.
    checkpoint.current_witness(scope)

    return InstalledReadOnlyAuthority(
        registry=registry, issuer_evidence=evidence,
        issuer_public_key=issuer_key,
        observation_public_key=observation_public,
        checkpoint=checkpoint, signed_pin=pin,
        broker_signer=signer,
        installed_source_sha256=_installed_gateway_source_digest(),
        original_checkpoint=record,
        gateway_uid=config["gateway_uid"],
        gateway_gid=config["gateway_gid"],
        gateway_executable_sha256=config["gateway_executable_sha256"],
        gateway_cgroup=config["gateway_cgroup"],
        backend_recheck=(__import__("functools").partial(
            live_backend.require_live_backend_bound_identity,
            expected_registry=__import__("zog.root_control.graphical_native_owner",
                fromlist=["strict"]).strict(_read_root(
                    owner_native.STORAGE_REGISTRY, max_bytes=4096)),
            allow_local=root_row["schema"] == owner_native.LOCAL_RUNTIME_SCHEMA)
            if selected_v3 else None),
    )
