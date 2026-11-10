"""Read-only systemd readiness check for *explicit* root-backed Task C v4.

Runs as trusted Host root before owner/broker, without any IAM session.
Checks the exact signed establishment and directory identities; it cannot
authorize SSM without the owner subsequently verifying monotonic S3 history.
Nothing is created, mounted, signed, repaired, or sent here.
"""
from __future__ import annotations

import os
import time
from pathlib import Path

from .graphical_native_owner import hold, strict
from .graphical_owner_service import _read_root
from . import graphical_task_c_native as native
from . import graphical_task_c_root_backed_storage as root
from . import graphical_operation_owner_source as operation


def inspect_disabled_local_readiness():
    if os.geteuid() != 0:
        hold()
    runtime = strict(_read_root(native.RUNTIME_CONFIG, max_bytes=65536))
    if runtime.get("schema") not in native.ROOT_BACKED_SCHEMAS:
        hold()
    local = runtime["schema"] == native.ROOT_BACKED_LOCAL_RUNTIME_SCHEMA
    selected = strict(_read_root(native.STORAGE_REGISTRY, max_bytes=4096))
    authority = strict(_read_root(native.STORAGE_RECORD, max_bytes=4096))
    approval = strict(_read_root(native.STORAGE_APPROVAL, max_bytes=8192))
    commit = strict(_read_root(native.STORAGE_COMMIT, max_bytes=4096))
    anchor = strict(_read_root(native.STORAGE_ANCHOR, max_bytes=4096))
    operator = _read_root(native.OPERATOR_PIN, max_bytes=32, mode=0o600)
    installer = _read_root(native.INSTALLER_PIN, max_bytes=32, mode=0o600)
    registry_public = (None if local else
        _read_root(native.REGISTRY_ISSUER_PIN, max_bytes=32, mode=0o600))
    root.verify_root_backed_anchor(anchor, commit, authority)
    result = root.verify_root_backed_commit(
        registry=selected, pinned_registry_public=registry_public,
        authority=authority, signed_storage_approval=approval,
        pinned_operator_public=operator,
        independently_retained_anchor_sha256=anchor["anchor_identity_sha256"],
        receipt=commit, pinned_installer_public=installer,
        independently_retained_commit_sha256=anchor["commit_sha256"],
        now=int(time.time()), allow_local=local, verify_directories=True)
    if (runtime["host_id"] != selected["host_id"]
            or runtime["installation_id"] != selected["installation_id"]
            or runtime["state_volume_id"] != selected["state_volume_id"]
            or runtime.get("storage_authority") != {
                "schema":root.SELECTION_SCHEMA,
                "registry_sha256":result["registry_sha256"],
                "installation_scope_sha256":result["installation_scope_sha256"],
                "storage_authority_sha256":operation.digest(authority),
                "storage_commit_sha256":operation.digest(commit)}):
        hold()
    # Check the live /state reader separately. No new signer or registry
    # migration is needed; this does not create protected SSM authority.
    from .graphical_task_c_backend_observation import (
        require_live_backend_bound_identity)
    observed = require_live_backend_bound_identity(
        expected_registry=selected, allow_local=local)
    if (observed["registry_sha256"] != result["registry_sha256"]
            or observed["installation_scope_sha256"] !=
                result["installation_scope_sha256"]):
        hold()
    return {"directory_identities_verified":True,
            "native_ssm_accepted":False,
            "checkpoint_history_verified":False}


def main():
    inspect_disabled_local_readiness()


if __name__ == "__main__":
    main()
