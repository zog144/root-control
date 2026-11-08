"""Fresh protected native STATE observation for Task C v3.

The real host-install inspector reopens a retained /state descriptor, verifies
the canonical marker/configuration and actual block/mount topology, and checks
the descriptor again. A separately protected, short-lived observer signature
binds its readback to the *already signed* opaque installation registry. No
obsolete registrar mapping, UUID conversion, gateway flag or cached JSON may
replace either independent check. This module never signs or installs evidence.
"""
from __future__ import annotations

import base64
import hashlib
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
REGISTRY = ROOT / "registered-installation.json"
REGISTRY_PIN = ROOT / "registry-issuer-public.key"
OBSERVER_PIN = ROOT / "native-state-observer-public.key"
OBSERVATION = ROOT / "native-state-observation.json"
SCHEMA = "zog-task-c-native-state-observation-v2"
DOMAIN = b"zog-task-c-native-state-observation-v2\0"
MAX_AGE = 90
FIELDS = frozenset((
    "schema", "registry_sha256", "installation_scope_sha256",
    "host_fingerprint_sha256", "legacy_host_uuid", "legacy_state_uuid",
    "aws_instance_id", "aws_region", "iid_document_sha256",
    "backend", "observation_sha256", "boot_id", "issued_at",
    "expires_at", "signature_ed25519",
))


def _safe_json(path):
    return strict(_read_root(path, max_bytes=8192, mode=0o600))


def _live_snapshot(context):
    from zog.host_install import state_inspect as inspect
    from zog.host_install.state_contract import canonical
    context.recheck()
    bundle = context.bundle
    bootstrap = bundle["bootstrap"]
    configured = bootstrap["state"]
    controls = bootstrap.get("registries")
    authority = bootstrap.get("control_authority")
    # PR35 legitimately permits standalone non-resident STATE. No Command
    # Center selected, so it MUST NOT authorize any Task C service.
    if (type(controls) is not list or not controls
            or type(authority) is not dict
            or type(authority.get("registry_id")) is not str
            or [r.get("registry_id") for r in controls
                if type(r) is dict and r.get("role")=="control"] !=
                   [authority["registry_id"]]):
        hold()
    fdstat = os.fstat(context.fd)
    marker = bundle["marker"]
    if (not stat.S_ISDIR(fdstat.st_mode)
            or (fdstat.st_uid,fdstat.st_gid,stat.S_IMODE(fdstat.st_mode))
                != (0,0,0o755)
            or canonical(marker) != canonical(
                inspect.decode(inspect.read_at(context.fd,".zog-state.json")))):
        hold()
    backend = configured.get("storage_backend","mounted-volume")
    mount = context.mount
    device = f"{os.major(fdstat.st_dev)}:{os.minor(fdstat.st_dev)}"
    base = {
        "backend":backend,
        "state_volume_uuid":configured["state_volume_id"],
        "filesystem_uuid":configured["filesystem_uuid"],
        "partuuid":configured["partition_partuuid"],
        "state_marker_sha256":"sha256:"+hashlib.sha256(
            canonical(marker)).hexdigest(),
        "mountpoint":"/state",
        "state_device":device,
    }
    if backend=="root-directory":
        if (mount.get("backend")!="root-directory"
                or mount.get("state_path")!="/state"
                or mount.get("device")!=device):
            hold()
        row={**base,"mounted":False,"root_mount_id":int(mount["id"]),
             "root_device":mount["device"],"state_inode":fdstat.st_ino,
             "state_uid":fdstat.st_uid,"state_gid":fdstat.st_gid,
             "state_mode":stat.S_IMODE(fdstat.st_mode)}
    elif backend=="mounted-volume":
        if mount.get("target")!="/state" or mount.get("device")!=device:
            hold()
        row={**base,"mounted":True,"state_mount_id":int(mount["id"])}
    else:
        hold()
    context.recheck()
    return row


def _verify_witness(receipt, *, registry, scope, observer_key, now):
    # Identity UUIDs and opaque IDs are never converted to each other:
    # the independent observer custodian must authenticate their binding
    # using the real enrolled Host and the original AWS IID evidence.
    if (type(receipt) is not dict or set(receipt)!=FIELDS
            or receipt.get("schema")!=SCHEMA
            or type(observer_key) is not bytes or len(observer_key)!=32
            or type(now) is not int
            or receipt.get("registry_sha256")!=op.digest(registry)
            or receipt.get("installation_scope_sha256")!=scope
            or receipt.get("host_fingerprint_sha256")!=
                registry["host_fingerprint"]
            or type(receipt.get("legacy_host_uuid")) is not str
            or type(receipt.get("legacy_state_uuid")) is not str
            or type(receipt.get("aws_instance_id")) is not str
            or type(receipt.get("aws_region")) is not str
            or not op.match(receipt.get("iid_document_sha256"),op.SHA)
            or not op.match(receipt.get("observation_sha256"),op.SHA)
            or receipt.get("backend") not in ("root-directory","mounted-volume")
            or type(receipt.get("issued_at")) is not int
            or type(receipt.get("expires_at")) is not int
            or not now-MAX_AGE<=receipt["issued_at"]<=now
            or not now<=receipt["expires_at"]<=receipt["issued_at"]+MAX_AGE
            or receipt.get("boot_id")!=Path(
                "/proc/sys/kernel/random/boot_id").read_text().strip()):
        hold()
    body={k:v for k,v in receipt.items() if k!="signature_ed25519"}
    try:
        sig=base64.b64decode(receipt["signature_ed25519"],validate=True)
        if (len(sig)!=64 or base64.b64encode(sig).decode("ascii")!=
                receipt["signature_ed25519"]):
            hold()
        Ed25519PublicKey.from_public_bytes(observer_key).verify(
            sig,DOMAIN+op.canonical(body))
    except (ValueError,TypeError,InvalidSignature):
        hold()
    return body


def require_live_backend_bound_identity(*,expected_registry=None):
    """Root-owned service rereads live /state; never consumes RPC acceptance.

    Work still must authenticate the observer signer/custody and original
    Host AWS IID / identity history, attest installed wheel RECORD, and
    provision protected storage and credentials before admitting services.
    """
    from zog.host_install import state_inspect as inspect
    from zog.host_install.state_contract import StateError
    if os.geteuid()!=0:
        hold()
    try:
        registry=_safe_json(REGISTRY)
        if expected_registry is not None and expected_registry!=registry:
            hold()
        registry_key=_read_root(REGISTRY_PIN,max_bytes=32,mode=0o600)
        observer_key=_read_root(OBSERVER_PIN,max_bytes=32,mode=0o600)
        if (type(registry_key) is not bytes or len(registry_key)!=32
                or type(observer_key) is not bytes or len(observer_key)!=32
                or observer_key==registry_key):
            hold()
        _, scope=storage.installation_scope(
            registry,pinned_registry_public=registry_key)
        receipt=_safe_json(OBSERVATION)
        witness=_verify_witness(
            receipt,registry=registry,scope=scope,
            observer_key=observer_key,now=int(time.time()))
        with inspect.inspect_live() as context:
            live=_live_snapshot(context)
            if (live["backend"]!=witness["backend"]
                    or live["state_volume_uuid"]!=
                        witness["legacy_state_uuid"]
                    or op.digest(live)!=witness["observation_sha256"]):
                hold()
            context.recheck()
            if (Path("/proc/sys/kernel/random/boot_id").read_text().strip()
                    !=witness["boot_id"]
                    or int(time.time())>witness["expires_at"]):
                hold()
            return {"backend":live["backend"],
                    "registry_sha256":op.digest(registry),
                    "installation_scope_sha256":scope,
                    "native_observer_sha256":op.digest(receipt),
                    "observation_sha256":op.digest(live)}
    except (StateError,OSError,ValueError,TypeError,KeyError,
            AttributeError,OverflowError):
        hold()
