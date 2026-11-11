"""Task C protected local STATE readback without registrar/observer signers.

An owner/broker running on the trusted Host reopens host-install's validated
STATE descriptor and verifies live mount/block/marker topology in-process.
No gateway JSON, Signed Mapping, observer receipt, or "native_accepted" flag
is an authority. For local Task C the distinct operator-signed storage
approval and installation commit (checked separately) bind this selection.
Local Host identity and boot/recovery do not depend on a Command Center.
"""
from __future__ import annotations

import hashlib
import os
import stat

from . import graphical_installation_storage_authority as authority
from . import graphical_operation_owner_source as op
from .graphical_native_owner import hold, strict
from .graphical_owner_service import _read_root

REGISTRY = "/etc/zog/graphical-owner/registered-installation.json"
REGISTRY_PIN = "/etc/zog/graphical-owner/registry-issuer-public.key"


def _snapshot(context, *, allow_local):
    from zog.host_install import state_inspect as inspect
    from zog.host_install.state_contract import canonical

    context.recheck()
    bundle = context.bundle
    bootstrap = bundle["bootstrap"]
    state = bootstrap["state"]
    if not allow_local:
        controls = bootstrap.get("registries")
        selected = bootstrap.get("control_authority")
        if (type(controls) is not list or not controls
                or type(selected) is not dict
                or type(selected.get("registry_id")) is not str
                or [r.get("registry_id") for r in controls
                     if type(r) is dict and r.get("role") == "control"]
                     != [selected["registry_id"]]):
            hold()
    # A standalone Host has no control authority. Task C, if explicitly
    # enrolled later, is separately approved by the original operator.
    fdstat = os.fstat(context.fd)
    marker = bundle["marker"]
    if (not stat.S_ISDIR(fdstat.st_mode)
            or (fdstat.st_uid, fdstat.st_gid,
                stat.S_IMODE(fdstat.st_mode)) != (0, 0, 0o755)
            or canonical(marker) != canonical(inspect.decode(
                inspect.read_at(context.fd, ".zog-state.json")))):
        hold()
    backend = state.get("storage_backend", "mounted-volume")
    mount = context.mount
    device = f"{os.major(fdstat.st_dev)}:{os.minor(fdstat.st_dev)}"
    common = {
        "backend": backend,
        "host_install_installation_uuid": bootstrap["installation_id"],
        "host_install_state_uuid": state["state_volume_id"],
        "filesystem_uuid": state["filesystem_uuid"],
        "partuuid": state["partition_partuuid"],
        "state_marker_sha256": "sha256:" + hashlib.sha256(
            canonical(marker)).hexdigest(),
        "state_device": device,
    }
    if backend == "root-directory":
        if (mount.get("backend") != "root-directory"
                or mount.get("state_path") != "/state"
                or mount.get("device") != device):
            hold()
        result = {
            **common, "mounted": False,
            "root_mount_id": int(mount["id"]),
            "state_inode": fdstat.st_ino,
            "state_uid": fdstat.st_uid,
            "state_gid": fdstat.st_gid,
            "state_mode": stat.S_IMODE(fdstat.st_mode),
        }
    elif backend == "mounted-volume":
        if mount.get("target") != "/state" or mount.get("device") != device:
            hold()
        result = {**common, "mounted": True,
                  "state_mount_id": int(mount["id"])}
    else:
        hold()
    context.recheck()
    return result


def require_live_backend_bound_identity(*, expected_registry=None,
                                         allow_local=False):
    """Fresh protected Host inspection, not a signer or an IPC authorization.

    Local mode is explicit from an independently selected Task C runtime.
    The authenticated storage establishment and operation authorization are
    separate and MUST pass before any service/SSM acceptance.
    """
    from zog.host_install import state_inspect as inspect
    from zog.host_install.state_contract import StateError

    if os.geteuid() != 0 or type(allow_local) is not bool:
        hold()
    try:
        selected = strict(_read_root(REGISTRY, max_bytes=4096))
        if expected_registry is not None and selected != expected_registry:
            hold()
        if allow_local:
            if selected.get("schema") != authority.LOCAL_SCHEMA:
                hold()
            _, scope = authority.installation_scope(
                selected, allow_local=True)
        else:
            if selected.get("schema") != authority.REGISTRY_SCHEMA:
                hold()
            pub = _read_root(REGISTRY_PIN, max_bytes=32, mode=0o600)
            _, scope = authority.installation_scope(
                selected, pinned_registry_public=pub)
        with inspect.inspect_live() as context:
            snapshot = _snapshot(context, allow_local=allow_local)
            if (allow_local and any(
                    snapshot[k] != selected[k] for k in
                    authority.LOCAL_EXTRA)):
                hold()
            context.recheck()
            return {
                "backend": snapshot["backend"],
                "registry_sha256": op.digest(selected),  # historical field name
                "installation_scope_sha256": scope,
                "live_snapshot_sha256": op.digest(snapshot),
                "observation_sha256": op.digest(snapshot),
            }
    except (StateError, OSError, ValueError, TypeError, KeyError,
            AttributeError, OverflowError):
        hold()
