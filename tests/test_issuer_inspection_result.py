"""Synthetic trust-boundary tests; no real journal, issuance or root mount."""
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path

import pytest

from zog.box_control.model import ApplicationRuntimeState
from zog.box_control.operations import OperationStore
from zog.box_control.project import Project
from zog.box_control.requests import (ApplicationRequest, ApplicationRequestOperation,
    ApplicationRequestResult, ApplicationRequestStatus, ApplicationRequestStore)
from zog.box_control.runtime.reference import (ApplicationRuntimeReference,
    ProgramRuntimeReference, RuntimeReferenceStore)
from zog.root_control import issuer_inspection_result as ir

BOOT = "b" * 32
INVOCATION = "c" * 32
REQ = "INSPECT123"
RID = "ABCD23"
UNIT = "zog-issuer-ABCD23-inspect.service"


@pytest.fixture
def observed(tmp_path, monkeypatch):
    project = Project(tmp_path / "project")
    project.state_dir.mkdir(parents=True)
    policy = {"schema": "zog-certify-manage-v1", "certificate_id": "demo",
              "hostnames": ["cert.example.test"], "email": "admin@example.test",
              "acme_directory": "https://acme.example.test/directory",
              "challenge": "http-01", "dns_plugin": None}
    policy_hash = hashlib.sha256(
        json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    protected = tmp_path / "policy"
    protected.mkdir()
    (protected / "policy.json").write_text(json.dumps(policy))
    from zog.box_control import host_bindings
    monkeypatch.setattr(host_bindings, "_CERT_POLICY_SOURCE", str(protected))
    monkeypatch.setattr(host_bindings, "_certify_policy_digest",
                        lambda _: "sha256:" + "d" * 64)
    monkeypatch.setattr(host_bindings, "resolve", lambda *a: (
        {"capability": "certify-policy", "policy_digest": "sha256:" + "d" * 64},
    ))
    grant = {"schema": "zog-execution-identity-v1", "uid": 200001,
             "gid": 200001, "grant_id": "e" * 32}
    monkeypatch.setattr(ir, "verify", lambda *a, **k: dict(grant))
    program = ProgramRuntimeReference(
        program="inspect", unit_name=UNIT, command=("/applications/certify-manage/bin/python3",
                                                     "-m", "zog.certify_manage", "inspect"),
        invocation_id=INVOCATION,
        expected_properties=(("RootDirectory", "/protected/runtime"),),
        result="success", active_state="inactive",
        mount_inventory={"mounts": [{"policy_digest": "sha256:" + "d" * 64}]},
    )
    runtime = ApplicationRuntimeReference(
        runtime_id=RID, application="certify-manage", instance_id="certify-manage",
        generation="generation", software_view="sha256:" + "f" * 64,
        boot_id=BOOT, state=ApplicationRuntimeState.TERMINATED, request_id=REQ,
        execution_binding=grant, programs=(program,), cleanup_pending=False,
    )
    RuntimeReferenceStore(project.runtime_reference_file).save({RID: runtime})
    requests = ApplicationRequestStore(project.application_request_dir,
                                       project.application_request_result_dir)
    now = datetime.now(timezone.utc)
    requests.submit(ApplicationRequest(
        REQ, ApplicationRequestOperation.LAUNCH, "certify-manage",
        program_name="inspect", created_at=now.timestamp()-100,
    ))
    requests.save_result(ApplicationRequestResult(
        REQ, ApplicationRequestOperation.LAUNCH, ApplicationRequestStatus.SATISFIED,
        application="certify-manage", runtime_id=RID, program_name="inspect",
    ))
    record = {
        "request_id": REQ, "operation": "launch", "new_runtime_id": RID,
        "selected_program": "inspect", "phase": "committed",
        "finished": True, "published": True, "created_at": now.timestamp()-100,
        "application": {"name": "certify-manage", "selected_program": "inspect",
                        "programs": [{"name": "inspect"}], "execution_binding": grant,
                        "storage_id": "a" * 32},
        "references": RuntimeReferenceStore.encode({RID: runtime}),
    }
    monkeypatch.setattr(OperationStore, "records", lambda self: [record])
    value = {
        "schema": "zog-certify-inspection-result-v1",
        "certificate_id": "demo", "hostnames": ["cert.example.test"],
        "policy_sha256": policy_hash,
        "health": "valid", "certificate_fingerprint_sha256": "1" * 64,
        "valid_from": (now-timedelta(days=5)).isoformat(),
        "expires_at": (now+timedelta(days=50)).isoformat(),
        "days_remaining": 50, "operation": "renew",
        "outcome": "renewed", "operation_updated_at": (now-timedelta(hours=1)).isoformat(),
        "issuer_verified": True, "observed_at": now.isoformat(), "tls_ready": False,
    }
    entry = {"_BOOT_ID": BOOT, "_SYSTEMD_INVOCATION_ID": INVOCATION,
             "_SYSTEMD_UNIT": UNIT, "_UID": "200001", "_TRANSPORT": "stdout",
             "MESSAGE": "ZOG_CERTIFY_INSPECT_RESULT_V1 " +
                 json.dumps(value, sort_keys=True, separators=(",", ":"))}
    seen = []
    def read(cmd, *, deadline):
        seen.append(cmd)
        return [entry]
    monkeypatch.setattr(ir, "run_bounded", read)
    return project, runtime, record, value, entry, seen


def test_exact_invocation_one_record_is_proven_but_not_public_tls(observed):
    project, runtime, operation, record, entry, seen = observed
    result = ir.read_selected_inspection(project_root=project.path, request_id=REQ)
    assert result["status"] == "verified"
    assert result["tls_ready"] is False
    assert result["request_id"] == REQ and result["invocation_id"] == INVOCATION
    assert result["issuer_uid"] == 200001 and result["storage_id"] == "a" * 32
    assert result["inspection"]["certificate_fingerprint_sha256"] == "1" * 64
    assert "_BOOT_ID="+BOOT in seen[0]
    assert "_SYSTEMD_INVOCATION_ID="+INVOCATION in seen[0]
    assert not any(x.startswith("--lines") or x.startswith("--cursor") for x in seen[0])
    assert "/protected/runtime" not in json.dumps(result)


@pytest.mark.parametrize("failure", [
    "missing", "duplicate", "wrong-boot", "wrong-invocation", "wrong-unit",
    "wrong-uid", "wrong-transport", "bad-schema", "wrong-policy", "wrong-san",
    "trailing-duplicate-json", "expired", "future-observation", "stale-observation",
    "false-positive", "malformed-mark", "oversized",
])
def test_journal_and_policy_fail_closed(observed, monkeypatch, failure):
    project, runtime, operation, record, entry, seen = observed
    if failure == "missing":
        monkeypatch.setattr(ir, "run_bounded", lambda *a, **k: [])
    elif failure == "duplicate":
        monkeypatch.setattr(ir, "run_bounded", lambda *a, **k: [entry, entry])
    elif failure in ("wrong-boot", "wrong-invocation", "wrong-unit",
                     "wrong-uid", "wrong-transport"):
        key = {"wrong-boot": "_BOOT_ID", "wrong-invocation": "_SYSTEMD_INVOCATION_ID",
               "wrong-unit": "_SYSTEMD_UNIT", "wrong-uid": "_UID",
               "wrong-transport": "_TRANSPORT"}[failure]
        entry[key] = "WRONG"
    elif failure == "malformed-mark":
        entry["MESSAGE"] = "ZOG_CERTIFY_INSPECT_RESULT_V1 garbage"
    elif failure == "oversized":
        entry["MESSAGE"] = "ZOG_CERTIFY_INSPECT_RESULT_V1 " + ("x"*5000)
    else:
        if failure == "bad-schema": record["schema"] = "forged"
        if failure == "wrong-policy": record["policy_sha256"] = "9" * 64
        if failure == "wrong-san": record["hostnames"] = ["unapproved.test"]
        if failure == "expired": record["expires_at"] = (
            datetime.now(timezone.utc)-timedelta(days=1)).isoformat()
        if failure == "future-observation": record["observed_at"] = (
            datetime.now(timezone.utc)+timedelta(hours=1)).isoformat()
        if failure == "stale-observation": record["observed_at"] = (
            datetime.now(timezone.utc)-timedelta(days=1)).isoformat()
        if failure == "false-positive": record["health"] = "invalid"
        entry["MESSAGE"] = "ZOG_CERTIFY_INSPECT_RESULT_V1 " + json.dumps(record)
        if failure == "trailing-duplicate-json":
            entry["MESSAGE"] += "\nZOG_CERTIFY_INSPECT_RESULT_V1 {}"
    with pytest.raises(Exception):
        ir.read_selected_inspection(project_root=project.path, request_id=REQ)


@pytest.mark.parametrize("failure", [
    "pending-request", "selector", "operation-incomplete", "new-runtime",
    "wrong-grant", "wrong-member", "unfinished", "failed-process",
    "missing-invocation", "reboot-drift", "software-view-drift",
])
def test_saved_controller_and_runtime_identity_is_mandatory(observed, failure):
    project, runtime, operation, record, entry, seen = observed
    from dataclasses import replace
    store = RuntimeReferenceStore(project.runtime_reference_file)
    if failure == "pending-request":
        request_store = ApplicationRequestStore(project.application_request_dir,
                                                project.application_request_result_dir)
        request_store.save_result(ApplicationRequestResult(
            REQ, ApplicationRequestOperation.LAUNCH, ApplicationRequestStatus.PENDING,
            application="certify-manage", runtime_id=RID, program_name="inspect"))
    if failure == "selector": operation["selected_program"] = "renew"
    if failure == "operation-incomplete": operation["finished"] = False
    if failure == "new-runtime": operation["new_runtime_id"] = "DIFFERENT"
    if failure == "wrong-grant":
        store.save({RID: replace(runtime, execution_binding={"uid": 1})})
    if failure == "wrong-member":
        store.save({RID: replace(runtime, programs=(replace(runtime.programs[0], program="renew"),))})
    if failure == "unfinished":
        store.save({RID: replace(runtime, cleanup_pending=True)})
    if failure == "failed-process":
        store.save({RID: replace(runtime, programs=(replace(runtime.programs[0], result="exit-code"),))})
    if failure == "missing-invocation":
        store.save({RID: replace(runtime, programs=(replace(runtime.programs[0], invocation_id=None),))})
    if failure == "reboot-drift": store.save({RID: replace(runtime, boot_id="f"*32)})
    if failure == "software-view-drift": store.save({RID: replace(runtime, software_view="sha256:"+"a"*64)})
    with pytest.raises(Exception):
        ir.read_selected_inspection(project_root=project.path, request_id=REQ)


def test_unverified_inspection_remains_unverified_without_readiness(observed):
    project, runtime, operation, record, entry, seen = observed
    record["health"] = "missing"
    record["issuer_verified"] = False
    record["certificate_fingerprint_sha256"] = None
    record["valid_from"] = record["expires_at"] = None
    record["days_remaining"] = None
    entry["MESSAGE"] = "ZOG_CERTIFY_INSPECT_RESULT_V1 " + json.dumps(record)
    result = ir.read_selected_inspection(project_root=project.path, request_id=REQ)
    assert result["status"] == "unverified"
    assert result["tls_ready"] is False


def test_absent_or_truncated_journal_never_verifies(observed, monkeypatch):
    project, runtime, operation, record, entry, seen = observed
    monkeypatch.setattr(ir, "run_bounded",
                        lambda *a, **k: (_ for _ in ()).throw(ValueError("journal over budget")))
    with pytest.raises(ValueError, match="budget"):
        ir.read_selected_inspection(project_root=project.path, request_id=REQ)
