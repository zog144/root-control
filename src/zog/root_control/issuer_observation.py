"""Trusted, read-only issuer operation evidence from grant-owned persistent state.

Never accepts a caller-supplied issuer JSON, file path, UID, certificate ID or
fingerprint. Only an exact saved controller request chooses what is observed.
The result authenticates the issuer journal's private filesystem provenance; it
does not assert externally served TLS readiness or publish private material.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from zog.box_control.project import Project
from zog.box_control.operations import OperationStore
from zog.box_control.requests import ApplicationRequestStore
from .identities import verify

_ID = re.compile(r"[a-z][a-z0-9-]{0,62}\Z")
_SHA = re.compile(r"[a-f0-9]{64}\Z")
_REQ = re.compile(r"[A-Za-z0-9-]{1,64}\Z")
_MAX_JOURNAL = 65536


class IssuerEvidenceError(ValueError):
    pass


def _owned_directory(fd, uid, gid, *, private=True):
    value = os.fstat(fd)
    if (not stat.S_ISDIR(value.st_mode)
            or (value.st_uid, value.st_gid) != (uid, gid)
            or (private and stat.S_IMODE(value.st_mode) != 0o700)):
        raise IssuerEvidenceError("issuer private directory ownership or DAC disagrees")


def _private_journal(path: Path, *, uid: int, gid: int):
    """Open each untrusted directory component relative to anchored descriptors."""
    mount = path.parent.parent
    _prefix = mount.parent
    if mount.name != "certificate-data" or path.parent.name != "operations":
        raise IssuerEvidenceError("unexpected issuer journal location")
    fd = os.open(mount, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        _owned_directory(fd, uid, gid)
        child = os.open("operations", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
        try:
            _owned_directory(child, uid, gid)
            try:
                leaf = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=child)
            except FileNotFoundError:
                return None
            try:
                info = os.fstat(leaf)
                if (not stat.S_ISREG(info.st_mode)
                        or (info.st_uid, info.st_gid) != (uid, gid)
                        or info.st_mode & 0o077 or info.st_nlink != 1
                        or info.st_size > _MAX_JOURNAL):
                    raise IssuerEvidenceError("issuer journal ownership or format disagrees")
                data = os.read(leaf, _MAX_JOURNAL + 1)
                if len(data) > _MAX_JOURNAL:
                    raise IssuerEvidenceError("issuer journal exceeds size bound")
                return json.loads(data)
            finally:
                os.close(leaf)
        finally:
            os.close(child)
    finally:
        os.close(fd)


def observe_issuer_request(*, project_root, request_id):
    """Derive a secret-free issuer journal attestation, never an nginx claim."""
    if not isinstance(request_id, str) or not _REQ.fullmatch(request_id):
        raise IssuerEvidenceError("invalid controller request identity")
    project = Project(Path(project_root))
    requests = ApplicationRequestStore(
        project.application_request_dir, project.application_request_result_dir
    )
    request = requests.load(requests.request_dir / (request_id + ".json"))
    if (request.request_id != request_id or request.operation.value != "launch"
            or request.application != "certify-manage"
            or request.program_name not in ("issue", "renew")
            or request.workspace_id is not None):
        raise IssuerEvidenceError("request is not an issuer mutation")
    records = [r for r in OperationStore(project).records() if r["request_id"] == request_id]
    if len(records) != 1:
        raise IssuerEvidenceError("no unique durable issuer operation")
    record = records[0]
    snapshot = record["application"]
    if (record["operation"] != "launch"
            or record.get("selected_program") != request.program_name
            or snapshot.get("selected_program") != request.program_name
            or snapshot.get("name") != "certify-manage"
            or len(snapshot["programs"]) != 1
            or snapshot["programs"][0]["name"] != request.program_name
            or not record["new_runtime_id"]):
        raise IssuerEvidenceError("issuer selected operation is not authoritative")
    from zog.box_control.runtime.reference import RuntimeReferenceStore
    reference = RuntimeReferenceStore.decode(record["references"]).get(record["new_runtime_id"])
    if (reference is None or reference.request_id != request_id
            or reference.application != "certify-manage"
            or len(reference.programs) != 1
            or reference.programs[0].program != request.program_name
            or reference.execution_binding != snapshot.get("execution_binding")):
        raise IssuerEvidenceError("issuer runtime identity differs from durable operation")
    storage = snapshot.get("storage_id")
    binding = snapshot.get("execution_binding")
    if not isinstance(storage, str) or not re.fullmatch(r"[a-f0-9]{32}", storage):
        raise IssuerEvidenceError("issuer storage is not controller bound")
    grant = verify(project.path, "certify-manage", binding, storage_id=storage)
    uid, gid = grant["uid"], grant["gid"]
    # The administrator's exact policy is read through the same root-owned,
    # symlink-resistant validation used at the service start boundary.
    from zog.box_control.host_bindings import _certify_policy_digest, _CERT_POLICY_SOURCE
    policy_digest = _certify_policy_digest(_CERT_POLICY_SOURCE)
    raw_policy = json.loads((Path(_CERT_POLICY_SOURCE) / "policy.json").read_text())
    certificate_id = raw_policy.get("certificate_id")
    if not isinstance(certificate_id, str) or not _ID.fullmatch(certificate_id):
        raise IssuerEvidenceError("invalid approved certificate identity")
    # cert-manager stores the hash of canonical strict Authorization, not the
    # bytes of the root policy file (different JSON whitespace is permitted).
    issuer_policy_hash = hashlib.sha256(
        json.dumps(raw_policy, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    from zog.box_control.host_bindings import resolve
    approved = resolve(project.path, "certify-manage", request.program_name)
    if (len(approved) != 1 or approved[0].get("policy_digest") != policy_digest
            or approved[0].get("capability") != "certify-policy"):
        raise IssuerEvidenceError("issuer policy capability grant unavailable")
    if not any(
            b.get("capability") == "certify-policy"
            and b.get("policy_digest") == policy_digest
            for b in snapshot.get("host_bindings", ())):
        # host_bindings are captured on the privileged per-service definition,
        # not necessarily on ApplicationSpec; consult runtime inventory below.
        if not any(
                p.mount_inventory and any(
                    m.get("policy_digest") == policy_digest
                    for m in p.mount_inventory.get("mounts", ())
                ) for p in reference.programs):
            raise IssuerEvidenceError("issuer runtime lacks matching host policy evidence")
    outcome = requests.result(request_id)
    current = RuntimeReferenceStore(project.runtime_reference_file).load().get(
        record["new_runtime_id"]
    )
    if current is not None and (
            current.request_id != reference.request_id
            or current.execution_binding != reference.execution_binding
            or current.application != reference.application
            or current.generation != reference.generation
            or len(current.programs) != 1
            or current.programs[0].program != request.program_name
            or current.programs[0].unit_name != reference.programs[0].unit_name):
        raise IssuerEvidenceError("current runtime reference contradicts issuer operation")
    from zog.box_control.model import ApplicationRuntimeState
    terminal_success = (
        current is not None
        and current.state == ApplicationRuntimeState.TERMINATED
        and not current.cleanup_pending
        and not current.error
        and current.programs[0].result == "success"
        and current.programs[0].invocation_id is not None
        and current.programs[0].active_state == "inactive"
    )
    journal_path = (project.mounts_dir / "persistent" / storage /
                    "certificate-data" / "operations" / (certificate_id + ".json"))
    journal = _private_journal(journal_path, uid=uid, gid=gid)
    result = {
        "schema": "zog-trusted-issuer-observation-v1",
        "request_id": request_id,
        "runtime_id": record["new_runtime_id"],
        "program": request.program_name,
        "storage_id": storage,
        "grant_id": grant["grant_id"],
        "issuer_uid": uid,
        "issuer_gid": gid,
        "policy_sha256": issuer_policy_hash,
        "host_policy_digest": policy_digest,
        "certificate_id": certificate_id,
        "certificate_fingerprint_sha256": None,
        "journal_updated_at": None,
        "outcome": None,
        "status": "ongoing",
        "tls_ready": False,
    }
    if journal is None:
        if record["phase"] in ("failed", "abandoned"):
            result["status"] = "uncertain"
        elif outcome is not None and outcome.status.value != "pending":
            result["status"] = "stale"
        return result
    if (not isinstance(journal, dict)
            or journal.get("schema") != "zog-certify-operation-v1"
            or journal.get("policy_sha256") != issuer_policy_hash):
        raise IssuerEvidenceError("issuer journal policy binding disagrees")
    journal_status = journal.get("status")
    if journal_status not in ("ready", "uncertain", "failed"):
        raise IssuerEvidenceError("unrecognized issuer journal state")
    digest = journal.get("certificate_fingerprint")
    if digest is not None and (not isinstance(digest, str) or not _SHA.fullmatch(digest)):
        raise IssuerEvidenceError("issuer certificate fingerprint is malformed")
    updated = journal.get("updated_at")
    try:
        observed_time = datetime.fromisoformat(updated)
        if observed_time.tzinfo is None:
            raise ValueError("naive issuer time")
        updated_epoch = observed_time.timestamp()
    except (ValueError, TypeError, OverflowError) as exc:
        raise IssuerEvidenceError("invalid issuer journal update timestamp") from exc
    result.update(
        certificate_fingerprint_sha256=digest,
        journal_updated_at=updated,
        outcome=journal.get("outcome"),
    )
    if (journal_status == "uncertain" or journal_status == "failed"
            or record["phase"] in ("failed", "abandoned")
            or (outcome is not None and outcome.status.value in ("failed", "abandoned"))):
        result["status"] = "uncertain"
    elif (journal.get("operation") != request.program_name
          or updated_epoch < record["created_at"]
          or (outcome is not None and outcome.status.value == "satisfied"
              and journal.get("outcome") not in ("issued", "renewed", "unchanged"))):
        result["status"] = "stale"
    elif (record["phase"] != "committed" or not record["finished"]
          or not record["published"] or outcome is None
          or outcome.status.value == "pending"):
        result["status"] = "ongoing"
    elif (digest is not None and journal_status == "ready"
          and outcome.status.value == "satisfied" and terminal_success):
        result["status"] = "journal-ready"
    elif not terminal_success and current is not None and (
            current.state in (ApplicationRuntimeState.RUNNING, ApplicationRuntimeState.STARTING,
                              ApplicationRuntimeState.TERMINATING)
            or current.cleanup_pending):
        result["status"] = "ongoing"
    else:
        result["status"] = "stale"
    return result
