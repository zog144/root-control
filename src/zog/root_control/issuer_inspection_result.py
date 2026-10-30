"""Exact saved systemd InvocationID -> one bounded issuer-owned X.509 record.

Only root-control may query journald; no user-controlled file, unit, project
relative path, command, cursor or invocation selector crosses the RPC boundary.
The returned snapshot is LOCAL issuer evidence, never nginx/TLS readiness.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import time

from zog.box_control.project import Project
from zog.box_control.operations import OperationStore
from zog.box_control.requests import ApplicationRequestStore
from zog.box_control.runtime.reference import RuntimeReferenceStore
from zog.box_control.model import ApplicationRuntimeState
from .identities import verify
from .journal import run_bounded, _identity

_REQUEST = re.compile(r"[A-Za-z0-9-]{1,200}\Z")
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_CERT = re.compile(r"[a-z][a-z0-9-]{0,62}\Z")
_PREFIX = "ZOG_CERTIFY_INSPECT_RESULT_V1 "
_FIELDS = frozenset({
    "schema", "certificate_id", "hostnames", "policy_sha256",
    "health", "certificate_fingerprint_sha256", "valid_from", "expires_at",
    "days_remaining", "operation", "outcome", "operation_updated_at",
    "issuer_verified", "observed_at", "tls_ready",
})
_HEALTH = frozenset({"valid", "missing", "invalid", "uncertain",
                     "expired-or-not-yet-valid"})
_OUTCOMES = frozenset({None, "issued", "renewed", "unchanged",
                       "recovered-unverified", "failed"})
_OPERATIONS = frozenset({None, "issue", "renew", "recover"})


class IssuerInspectionEvidenceError(ValueError):
    pass


def _fail(message):
    raise IssuerInspectionEvidenceError(message)


def _time(value, *, nullable=False):
    if nullable and value is None:
        return None
    if type(value) is not str or not 1 <= len(value) <= 80:
        _fail("invalid issuer inspection timestamp")
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.utcoffset() is None:
            raise ValueError("naive")
        return parsed.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        _fail("invalid issuer inspection timestamp")


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            _fail("duplicate issuer inspection field")
        result[key] = value
    return result


def _record(line, *, policy, created_at):
    if type(line) is not str or not line.startswith(_PREFIX):
        _fail("missing issuer inspection result marker")
    if len(line.encode("utf-8")) > 4096:
        _fail("oversized issuer inspection result")
    try:
        raw = json.loads(line[len(_PREFIX):], object_pairs_hook=_pairs,
                         parse_constant=lambda _: _fail("nonfinite issuer inspection number"))
    except (ValueError, UnicodeError):
        _fail("malformed issuer inspection result")
    if (type(raw) is not dict or set(raw) != _FIELDS
            or raw["schema"] != "zog-certify-inspection-result-v1"
            or raw["certificate_id"] != policy["certificate_id"]
            or raw["hostnames"] != policy["hostnames"]
            or raw["policy_sha256"] != policy["fingerprint"]
            or raw["health"] not in _HEALTH
            or raw["operation"] not in _OPERATIONS
            or raw["outcome"] not in _OUTCOMES
            or type(raw["issuer_verified"]) is not bool
            or raw["tls_ready"] is not False):
        _fail("issuer inspection schema/policy disagrees")
    for key in ("valid_from", "expires_at", "operation_updated_at"):
        _time(raw[key], nullable=True)
    observed = _time(raw["observed_at"])
    now = datetime.now(timezone.utc)
    if (not created_at <= observed.timestamp() + 120
            or observed > now + timedelta(minutes=2)
            or observed < now - timedelta(minutes=15)):
        # Recovery may still inspect the saved controller request/result.
        # A new selected inspection is required for actionable fresh status.
        _fail("issuer inspection observation is stale or outside runtime")
    leaf = raw["certificate_fingerprint_sha256"]
    if leaf is not None and (type(leaf) is not str or _HEX.fullmatch(leaf) is None):
        _fail("issuer inspection fingerprint malformed")
    days = raw["days_remaining"]
    if days is not None and (type(days) is not int or not -365000 <= days <= 365000):
        _fail("issuer inspection days malformed")
    if raw["issuer_verified"]:
        start = _time(raw["valid_from"])
        end = _time(raw["expires_at"])
        if (raw["health"] != "valid" or leaf is None
                or raw["operation"] not in {"issue", "renew"}
                or raw["outcome"] not in {"issued", "renewed", "unchanged"}
                or _time(raw["operation_updated_at"]) > observed + timedelta(minutes=2)
                or not start <= observed <= end or days is None):
            _fail("positive X.509 issuer evidence is inconsistent")
    return raw


def _resolved_request(project, request_id):
    requests = ApplicationRequestStore(
        project.application_request_dir, project.application_request_result_dir
    )
    request = requests.load(requests.request_dir / (request_id + ".json"))
    result = requests.result(request_id)
    if (request.request_id != request_id or request.operation.value != "launch"
            or request.application != "certify-manage" or request.program_name != "inspect"
            or request.workspace_id is not None or result is None
            or result.request_id != request_id or result.operation.value != "launch"
            or result.application != "certify-manage" or result.program_name != "inspect"
            or result.status.value != "satisfied" or not result.runtime_id):
        _fail("selected inspect request has no satisfied identity")
    records = [r for r in OperationStore(project).records()
               if r["request_id"] == request_id]
    if len(records) != 1:
        _fail("missing unique prepared issuer inspection operation")
    record = records[0]
    snapshot = record["application"]
    if (record["operation"] != "launch"
            or record["new_runtime_id"] != result.runtime_id
            or record.get("selected_program") != "inspect"
            or snapshot.get("name") != "certify-manage"
            or snapshot.get("selected_program") != "inspect"
            or len(snapshot.get("programs", ())) != 1
            or snapshot["programs"][0]["name"] != "inspect"
            or record["phase"] != "committed" or record["finished"] is not True
            or record["published"] is not True):
        _fail("saved inspection operation incomplete or mismatched")
    frozen = RuntimeReferenceStore.decode(record["references"]).get(result.runtime_id)
    current = RuntimeReferenceStore(project.runtime_reference_file).load().get(result.runtime_id)
    if (frozen is None or current is None or frozen.request_id != request_id
            or current.request_id != request_id
            or frozen.application != "certify-manage"
            or current.application != "certify-manage"
            or frozen.purpose != "application" or current.purpose != "application"
            or frozen.execution_binding != snapshot.get("execution_binding")
            or current.execution_binding != frozen.execution_binding
            or current.generation != frozen.generation
            or current.software_view != frozen.software_view
            or current.software_binding_digest != frozen.software_binding_digest
            or current.boot_id != frozen.boot_id
            or len(current.programs) != 1 or len(frozen.programs) != 1):
        _fail("issuer inspect runtime differs from frozen operation")
    member, frozen_member = current.programs[0], frozen.programs[0]
    if (member.program != frozen_member.program or member.program != "inspect"
            or member.unit_name != frozen_member.unit_name
            or member.command != frozen_member.command
            or member.expected_properties != frozen_member.expected_properties
            or member.mount_inventory != frozen_member.mount_inventory
            or current.state != ApplicationRuntimeState.TERMINATED
            or current.cleanup_pending or current.error
            or member.result != "success" or member.active_state != "inactive"):
        _fail("inspection process success or invocation unresolved")
    boot, invocation = _identity(current.boot_id), _identity(member.invocation_id)
    if frozen_member.invocation_id is not None and (
            _identity(frozen_member.invocation_id) != invocation):
        _fail("prepared inspection invocation disagrees")
    storage = snapshot.get("storage_id")
    if type(storage) is not str or not re.fullmatch(r"[0-9a-f]{32}", storage):
        _fail("unbound issuer inspect storage")
    grant = verify(project.path, "certify-manage",
                   snapshot.get("execution_binding"), storage_id=storage)
    if grant != current.execution_binding:
        _fail("issuer execution identity grant rotated")
    return record, current, grant, boot, invocation, storage


def read_selected_inspection(*, project_root, request_id):
    if type(request_id) is not str or _REQUEST.fullmatch(request_id) is None:
        _fail("invalid selected inspect request identity")
    project = Project(Path(project_root))
    record, runtime, grant, boot, invocation, storage = _resolved_request(
        project, request_id
    )
    # Exact protected host-policy selector, not caller-supplied certificate,
    # config path or untrusted stdout content.
    from zog.box_control.host_bindings import (
        _certify_policy_digest, _CERT_POLICY_SOURCE, resolve
    )
    host_digest = _certify_policy_digest(_CERT_POLICY_SOURCE)
    policy_file = Path(_CERT_POLICY_SOURCE) / "policy.json"
    policy = json.loads(policy_file.read_text())
    certificate_id = policy.get("certificate_id")
    hostnames = policy.get("hostnames")
    if (type(certificate_id) is not str or _CERT.fullmatch(certificate_id) is None
            or type(hostnames) is not list or not hostnames
            or len(hostnames) > 100 or not all(type(x) is str and
            1 <= len(x) <= 253 for x in hostnames)):
        _fail("unapproved issuer policy identity")
    issuer_fingerprint = hashlib.sha256(
        json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    approved = resolve(project.path, "certify-manage", "inspect")
    if (len(approved) != 1
            or approved[0].get("capability") != "certify-policy"
            or approved[0].get("policy_digest") != host_digest
            or not any(p.mount_inventory and any(
                m.get("policy_digest") == host_digest
                for m in p.mount_inventory.get("mounts", ()))
                for p in runtime.programs)):
        _fail("issuer inspect policy capability differs")
    policy_identity = dict(certificate_id=certificate_id, hostnames=hostnames,
                           fingerprint=issuer_fingerprint)
    # Query the *saved* boot and systemd InvocationID. No '--lines' truncation:
    # either scan the entire bounded stream or reject, never accept a record
    # while silently missing a duplicate in older logs.
    command = [
        "journalctl", "--no-pager", "--quiet", "--output=json",
        "--output-fields=MESSAGE,_BOOT_ID,_SYSTEMD_INVOCATION_ID,_SYSTEMD_UNIT,_UID,_TRANSPORT,__REALTIME_TIMESTAMP",
        "_BOOT_ID=" + boot, "_SYSTEMD_INVOCATION_ID=" + invocation,
    ]
    rows = run_bounded(command, deadline=time.monotonic() + 5)
    found = []
    for entry in rows:
        if (type(entry) is not dict or
                entry.get("_BOOT_ID") != boot or
                entry.get("_SYSTEMD_INVOCATION_ID") != invocation):
            _fail("issuer inspection journal returned wrong invocation")
        message = entry.get("MESSAGE")
        if isinstance(message, str) and message.startswith("ZOG_CERTIFY_INSPECT_RESULT_V1"):
            if (entry.get("_SYSTEMD_UNIT") != runtime.programs[0].unit_name
                    or entry.get("_TRANSPORT") != "stdout"
                    or str(entry.get("_UID")) != str(grant["uid"])):
                _fail("issuer inspect stdout attribution disagrees")
            if len(found) != 0:
                _fail("duplicate issuer inspection stdout records")
            verified = _record(message, policy=policy_identity,
                               created_at=record["created_at"])
            stamp = entry.get("__REALTIME_TIMESTAMP")
            if (type(stamp) is not str or not stamp.isascii()
                    or not stamp.isdecimal() or not 1 <= len(stamp) <= 20):
                _fail("journal message timestamp unavailable")
            try:
                logged = datetime.fromtimestamp(int(stamp)/1_000_000, timezone.utc)
            except (OverflowError, OSError, ValueError):
                _fail("journal message timestamp malformed")
            if abs((logged - _time(verified["observed_at"])).total_seconds()) > 120:
                _fail("issuer journal and inspection clocks disagree")
            found.append(verified)
    if len(found) != 1:
        _fail("issuer inspection has no unique authenticated record")
    evidence = found[0]
    return {
        "schema": "zog-trusted-issuer-inspection-v1",
        "request_id": request_id,
        "runtime_id": runtime.runtime_id,
        "program": "inspect",
        "boot_id": boot,
        "invocation_id": invocation,
        "storage_id": storage,
        "grant_id": grant["grant_id"],
        "issuer_uid": grant["uid"],
        "issuer_gid": grant["gid"],
        "host_policy_digest": host_digest,
        "inspection": evidence,
        "status": "verified" if evidence["issuer_verified"] else "unverified",
        "tls_ready": False,
    }
