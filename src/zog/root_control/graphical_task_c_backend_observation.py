"""Fresh, protected v2 STATE backend observation for the Task C native services.

Neither registrar-signed mapping JSON nor a caller's "verified" flag can prove
an actual backend. The independently enrolled native observer signs a short
boot-bound readback; the root-owned consumer MUST also re-open/recheck the
host-install STATE descriptor and Linux block/mount topology *on every call*.
This module cannot issue, repair or accept a native enrollment.
"""
from __future__ import annotations

import base64
import os
from pathlib import Path
import stat
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import graphical_operation_owner_source as op
from . import graphical_installation_storage_authority as storage
from .graphical_native_owner import hold, strict
from .graphical_owner_service import _read_root

ROOT = Path("/etc/zog/graphical-owner")
MAPPING = ROOT / "registry-identity-mapping-v2.json"
LEGACY = ROOT / "enrolled-legacy-identity.json"
REGISTRAR_PIN = ROOT / "identity-registrar-public.key"
OBSERVATION_PIN = ROOT / "native-state-observer-public.key"
OBSERVATION = ROOT / "native-state-observation.json"
REGISTRY_PIN = ROOT / "registry-issuer-public.key"
REGISTRY = ROOT / "registered-installation.json"
SCHEMA = "zog-task-c-native-state-observation-v1"
DOMAIN = b"zog-task-c-native-state-observation-v1\0"
FIELDS = frozenset((
    "schema", "mapping_sha256", "observation_sha256", "backend",
    "host_uuid", "aws_instance_id", "aws_region", "volume_id",
    "boot_id", "issued_at", "expires_at", "signature_ed25519",
))
MAX_AGE = 90


def _safe_json(path, size=8192):
    return strict(_read_root(path, max_bytes=size, mode=0o600))


def _context_observation(context, attested):
    """Reconstruct backend fields from kernel, not signed/caller JSON."""
    from zog.host_install import state_inspect as inspect
    from zog.host_install.state_contract import canonical
    context.recheck()
    bundle = context.bundle
    expected = bundle["bootstrap"]["state"]
    controls = bundle["bootstrap"].get("registries")
    authority = bundle["bootstrap"].get("control_authority")
    # host-install may legitimately run a standalone non-resident /state with
    # no registry. That mode MUST NOT acquire the Task C command-center
    # authority merely because a separately signed mapping file exists.
    if (type(controls) is not list or not controls
            or type(authority) is not dict
            or type(authority.get("registry_id")) is not str
            or [r.get("registry_id") for r in controls
                   if type(r) is dict and r.get("role") == "control"] !=
                [authority["registry_id"]]):
        hold()
    root = bundle["marker"]
    fdstat = os.fstat(context.fd)
    mount = context.mount
    backend = expected.get("storage_backend", "mounted-volume")
    if (backend not in ("mounted-volume", "root-directory")
            or not stat.S_ISDIR(fdstat.st_mode)
            or (fdstat.st_uid, fdstat.st_gid, stat.S_IMODE(fdstat.st_mode))
                != (0, 0, 0o755)
            or canonical(root) != canonical(
                inspect.decode(inspect.read_at(context.fd, ".zog-state.json")))):
        hold()
    # inspect_live already checked complete config, root/superblock rw state,
    # the selected unique lsblk UUID/PARTUUID, nested-mount exclusions and
    # the retained path descriptor. Recheck again after signed verification.
    shared = {
        "host_uuid":attested["host_uuid"],
        "aws_instance_id":attested["aws_instance_id"],
        "aws_region":attested["aws_region"],
        "mountpoint":"/state",
        "filesystem_uuid":expected["filesystem_uuid"],
        "partuuid":expected["partition_partuuid"],
        "state_marker_sha256":"sha256:" + __import__("hashlib").sha256(
            canonical(root)).hexdigest(),
    }
    if backend == "root-directory":
        if (mount.get("backend") != "root-directory"
                or mount.get("state_path") != "/state"
                or mount["device"] !=
                    f"{os.major(fdstat.st_dev)}:{os.minor(fdstat.st_dev)}"):
            hold()
        result = {**shared, "mounted":False,
                  "root_mount_id":int(mount["id"]),
                  "root_device":mount["device"], "state_device":mount["device"],
                  "state_inode":fdstat.st_ino,
                  "state_uid":fdstat.st_uid, "state_gid":fdstat.st_gid,
                  "state_mode":stat.S_IMODE(fdstat.st_mode)}
    else:
        if (mount.get("target") != "/state"
                or mount["device"] !=
                    f"{os.major(fdstat.st_dev)}:{os.minor(fdstat.st_dev)}"
                or attested["volume_id"] is None):
            hold()
        result = {**shared, "mounted":True,
                  "state_mount_id":int(mount["id"]),
                  "state_device":mount["device"],
                  "volume_id":attested["volume_id"]}
    context.recheck()
    return backend, result


def _signed_observation(row, *, pin, mapping, now):
    if (type(row) is not dict or set(row) != FIELDS
            or row.get("schema") != SCHEMA
            or type(pin) is not bytes or len(pin) != 32
            or type(now) is not int
            or type(row.get("issued_at")) is not int
            or type(row.get("expires_at")) is not int
            or not now - MAX_AGE <= row["issued_at"] <= now
            or not now <= row["expires_at"] <= row["issued_at"] + MAX_AGE
            or row.get("mapping_sha256") != op.digest(mapping)
            or row.get("backend") not in ("mounted-volume", "root-directory")
            or type(row.get("boot_id")) is not str
            or row["boot_id"] !=
                Path("/proc/sys/kernel/random/boot_id").read_text().strip()
            or type(row.get("host_uuid")) is not str
            or type(row.get("aws_instance_id")) is not str
            or type(row.get("aws_region")) is not str
            or row.get("volume_id") is not None
                and type(row["volume_id"]) is not str):
        hold()
    body = {k:v for k,v in row.items() if k != "signature_ed25519"}
    try:
        sig = base64.b64decode(row["signature_ed25519"], validate=True)
        if (len(sig) != 64 or base64.b64encode(sig).decode("ascii") !=
                row["signature_ed25519"]):
            hold()
        Ed25519PublicKey.from_public_bytes(pin).verify(
            sig, DOMAIN + op.canonical(body))
    except (InvalidSignature, ValueError, TypeError):
        hold()
    return body


def require_live_backend_bound_identity(*, expected_registry=None):
    """Protected root-service call, NOT an IPC/RPC boolean or mapping flag.

    Native Work must separately enroll the observer signing custodian, verify
    actual AWS IID/host-identify and attested installed package/RECORD. In
    particular, a signed observation is not by itself trusted: independently
    inspect Linux kernel topology again in this very invocation.
    """
    from zog.host_install import state_inspect as inspect
    from zog.host_install import graphical_registry_identity_mapping_v2 as v2
    from zog.host_install.state_contract import StateError
    from zog.host_install.graphical_readonly_trust_broker_install import BrokerInstallHeld

    if os.geteuid() != 0:
        hold()
    try:
        registry = _safe_json(REGISTRY)
        if expected_registry is not None and expected_registry != registry:
            hold()
        pinned_registry = _read_root(REGISTRY_PIN, max_bytes=32, mode=0o600)
        registrar = _read_root(REGISTRAR_PIN, max_bytes=32, mode=0o600)
        observer = _read_root(OBSERVATION_PIN, max_bytes=32, mode=0o600)
        if (len({pinned_registry, registrar, observer}) != 3
                or any(len(k) != 32 for k in (
                    pinned_registry, registrar, observer))):
            hold()
        # Do not silently convert the previously enrolled v1 identity.
        mapping = _safe_json(MAPPING)
        legacy = _safe_json(LEGACY)
        receipt = _safe_json(OBSERVATION)
        now = int(time.time())
        signed = _signed_observation(
            receipt, pin=observer, mapping=mapping, now=now)
        with inspect.inspect_live() as state:
            backend, live = _context_observation(state, signed)
            if (backend != signed["backend"]
                    or op.digest(live) != signed["observation_sha256"]
                    or state.bundle["bootstrap"]["installation_id"] !=
                        state.bundle["installation"]["installation_id"]):
                hold()
            verified = v2.verify_signed(
                signed_mapping=mapping, legacy=legacy,
                registered_installation=registry, observation=live,
                backend=backend, pinned_registrar_public=registrar,
                pinned_registry_public=pinned_registry)
            if (verified["native_accepted"] is not False
                    or verified["broker_admission"] is not False
                    or verified["ssm_authorized"] is not False):
                hold()
            scope, installed_sha = storage.installation_scope(
                registry, pinned_registry_public=pinned_registry)
            state.recheck()
            if (signed["boot_id"] != Path(
                    "/proc/sys/kernel/random/boot_id").read_text().strip()
                    or int(time.time()) > signed["expires_at"]):
                hold()
            return {"backend":backend, "registry_sha256":op.digest(registry),
                    "installation_scope_sha256":installed_sha,
                    "mapping_sha256":op.digest(mapping),
                    "observation_sha256":op.digest(live)}
    except (StateError, BrokerInstallHeld, OSError, ValueError, TypeError,
            KeyError, AttributeError, OverflowError):
        hold()
