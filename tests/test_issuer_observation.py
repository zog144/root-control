"""Native-free validation of trusted issuer evidence from private state."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from zog.box_control.model import ApplicationRuntimeState
from zog.box_control.operations import OperationStore
from zog.box_control.project import Project
from zog.box_control.requests import (
    ApplicationRequest, ApplicationRequestOperation, ApplicationRequestResult,
    ApplicationRequestStatus, ApplicationRequestStore,
)
from zog.box_control.runtime.reference import (
    ApplicationRuntimeReference, ProgramRuntimeReference, RuntimeReferenceStore,
)
from zog.root_control import issuer_observation


def fixture(tmp_path, monkeypatch, *, selected="renew", status="ready"):
    project = Project(tmp_path / "project")
    project.state_dir.mkdir(parents=True)
    uid, gid = os.getuid(), os.getgid()
    storage = "a" * 32
    owner = {"uid": uid, "gid": gid, "grant_id": "b" * 32}
    policy = {"schema": "zog-certify-manage-v1", "certificate_id": "example",
              "hostnames": ["test.example"], "email": "admin@example.test",
              "acme_directory": "https://acme.example.test/directory",
              "challenge": "http-01", "dns_plugin": None}
    directory = tmp_path / "cert-policy"
    directory.mkdir()
    (directory / "policy.json").write_text(json.dumps(policy))
    import zog.box_control.host_bindings as hb
    monkeypatch.setattr(hb, "_CERT_POLICY_SOURCE", str(directory))
    monkeypatch.setattr(hb, "_certify_policy_digest", lambda value: "sha256:" + "c" * 64)
    monkeypatch.setattr(hb, "resolve", lambda *args: ({
        "capability": "certify-policy", "policy_digest": "sha256:" + "c" * 64
    },))
    monkeypatch.setattr("zog.root_control.issuer_observation.verify",
                        lambda *args, **kwargs: dict(owner))
    binding = {"schema": "zog-execution-identity-v1", **owner}
    ref = ApplicationRuntimeReference(
        runtime_id="ABCD23", application="certify-manage",
        instance_id="certify-manage", generation="g", state=ApplicationRuntimeState.RUNNING,
        request_id="REQ1", execution_binding=binding,
        programs=(ProgramRuntimeReference(
            program=selected, unit_name="zog-project-ABCD23-" + selected + ".service",
            mount_inventory={"mounts": [{"policy_digest": "sha256:" + "c" * 64}]},
        ),),
    )
    record = {
        "request_id": "REQ1", "operation": "launch",
        "new_runtime_id": "ABCD23", "selected_program": selected,
        "phase": "committed", "finished": True, "published": True,
        "created_at": 500.0,
        "application": {"name": "certify-manage", "selected_program": selected,
                        "programs": [{"name": selected}], "execution_binding": binding,
                        "storage_id": storage},
        "references": RuntimeReferenceStore.encode({"ABCD23": ref}),
    }
    monkeypatch.setattr(OperationStore, "records", lambda self: [record])
    from dataclasses import replace
    completed = replace(
        ref, state=ApplicationRuntimeState.TERMINATED, cleanup_pending=False,
        programs=(replace(ref.programs[0], result="success",
                          invocation_id="invocation-1", active_state="inactive"),),
    )
    RuntimeReferenceStore(project.runtime_reference_file).save({"ABCD23": completed})
    requests = ApplicationRequestStore(project.application_request_dir,
                                       project.application_request_result_dir)
    requests.submit(ApplicationRequest(
        "REQ1", ApplicationRequestOperation.LAUNCH, "certify-manage",
        created_at=500.0, program_name=selected,
    ))
    requests.save_result(ApplicationRequestResult(
        "REQ1", ApplicationRequestOperation.LAUNCH, ApplicationRequestStatus.SATISFIED,
        application="certify-manage", runtime_id="ABCD23", program_name=selected,
    ))
    parent = project.mounts_dir / "persistent" / storage / "certificate-data"
    operations = parent / "operations"
    operations.mkdir(parents=True)
    parent.chmod(0o700)
    operations.chmod(0o700)
    cert_hash = hashlib.sha256(json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    file = operations / "example.json"
    file.write_text(json.dumps({
        "schema": "zog-certify-operation-v1", "policy_sha256": cert_hash,
        "certificate_fingerprint": "d" * 64, "status": status,
        "operation": selected, "outcome": "renewed",
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }))
    file.chmod(0o600)
    return project, file, record


def test_verified_root_owned_journal_is_read_only_and_not_tls_readiness(tmp_path, monkeypatch):
    project, file, record = fixture(tmp_path, monkeypatch)
    before = file.read_bytes()
    result = issuer_observation.observe_issuer_request(
        project_root=project.path, request_id="REQ1",
    )
    assert result["status"] == "journal-ready"
    assert result["tls_ready"] is False
    assert result["request_id"] == "REQ1"
    assert result["certificate_fingerprint_sha256"] == "d" * 64
    assert result["storage_id"] == "a" * 32
    assert result["issuer_uid"] == os.getuid()
    assert "account_id" not in result
    assert file.read_bytes() == before


@pytest.mark.parametrize("mutation,expected", [
    ("uncertain", "uncertain"),
    ("failed", "uncertain"),
    ("old-time", "stale"),
    ("old-operation", "stale"),
    ("missing", "stale"),
])
def test_observer_fails_closed_for_unproven_issuer_status(tmp_path, monkeypatch, mutation, expected):
    project, file, record = fixture(tmp_path, monkeypatch)
    raw = json.loads(file.read_text())
    if mutation == "missing":
        file.unlink()
    else:
        if mutation in ("uncertain", "failed"):
            raw["status"] = mutation
        if mutation == "old-time":
            raw["updated_at"] = "1970-01-01T00:00:00+00:00"
        if mutation == "old-operation":
            raw["operation"] = "issue"
        file.write_text(json.dumps(raw))
    result = issuer_observation.observe_issuer_request(
        project_root=project.path, request_id="REQ1",
    )
    assert result["status"] == expected


def test_running_command_does_not_claim_journal_ready(tmp_path, monkeypatch):
    from dataclasses import replace
    project, file, record = fixture(tmp_path, monkeypatch)
    store = RuntimeReferenceStore(project.runtime_reference_file)
    ref = store.load()["ABCD23"]
    store.save({"ABCD23": replace(
        ref, state=ApplicationRuntimeState.RUNNING, cleanup_pending=True
    )})
    result = issuer_observation.observe_issuer_request(
        project_root=project.path, request_id="REQ1")
    assert result["status"] == "ongoing"
    assert result["tls_ready"] is False


def test_failed_one_shot_does_not_claim_journal_ready(tmp_path, monkeypatch):
    from dataclasses import replace
    project, file, record = fixture(tmp_path, monkeypatch)
    store = RuntimeReferenceStore(project.runtime_reference_file)
    ref = store.load()["ABCD23"]
    store.save({"ABCD23": replace(
        ref, state=ApplicationRuntimeState.FAILED, cleanup_pending=False,
        programs=(replace(ref.programs[0], result="exit-code"),),
    )})
    result = issuer_observation.observe_issuer_request(
        project_root=project.path, request_id="REQ1")
    assert result["status"] != "journal-ready"


def test_pending_controller_result_stays_ongoing(tmp_path, monkeypatch):
    project, file, record = fixture(tmp_path, monkeypatch)
    from zog.box_control.requests import ApplicationRequestStore
    store = ApplicationRequestStore(project.application_request_dir, project.application_request_result_dir)
    path = store.result_dir / "REQ1.json"
    raw = json.loads(path.read_text())
    raw["status"] = "pending"
    path.write_text(json.dumps(raw))
    assert issuer_observation.observe_issuer_request(
        project_root=project.path, request_id="REQ1")["status"] == "ongoing"


@pytest.mark.parametrize("mutate", ["symlink", "world-readable", "wrong-policy", "wrong-selector"])
def test_observer_rejects_redirected_file_and_identity_mismatch(tmp_path, monkeypatch, mutate):
    project, file, record = fixture(tmp_path, monkeypatch)
    if mutate == "symlink":
        file.rename(file.with_suffix(".saved"))
        file.symlink_to(file.with_suffix(".saved"))
    elif mutate == "world-readable":
        file.chmod(0o644)
    elif mutate == "wrong-policy":
        raw = json.loads(file.read_text())
        raw["policy_sha256"] = "0" * 64
        file.write_text(json.dumps(raw))
    else:
        record["selected_program"] = "issue"
    with pytest.raises(Exception):
        issuer_observation.observe_issuer_request(project_root=project.path, request_id="REQ1")


def test_no_arbitrary_project_path_or_request_content(tmp_path):
    with pytest.raises(Exception):
        issuer_observation.observe_issuer_request(
            project_root=tmp_path, request_id="../private.json")
