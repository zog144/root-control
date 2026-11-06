"""Exactly selected trust semantics; synthetic source verification only."""
import json
import inspect
from pathlib import Path

from zog.root_control import graphical_task_c_capture_app
from zog.root_control import graphical_task_c_webhook_capture
from zog.root_control import graphical_task_c_issuance

ROOT=Path(__file__).resolve().parents[1]


def test_shared_host_contract_keeps_owner_and_original_history():
    model=json.loads((ROOT/"docs/graphical-task-c-shared-host-trust-v1.json").read_text())
    assert model["schema"]=="zog-graphical-shared-host-trust-model-v1"
    assert model["trust_boundary"]=="one_trusted_administrative_host"
    assert model["administrator_can_access_local_ssm_authority"] is True
    assert model["root_admin_inaccessibility_proof_required"] is False
    assert model["owner_claims_required"] is True
    assert model["revocation_required"] is True
    assert model["original_s3_history_and_genesis_required"] is True
    assert model["normal_owner_path_bypass_permitted"] is False
    assert model["synthetic_source_test_is_native_acceptance"] is False


def test_shared_capture_is_not_an_original_approval_or_ssm_sender():
    m=json.loads((ROOT/"docs/graphical-task-c-shared-host-trust-v1.json").read_text())
    assert m["separate_physical_signing_hosts_required"] is False
    assert m["separate_cryptographic_role_identities_required"] is True
    capture=inspect.getsource(graphical_task_c_capture_app)
    webhook=inspect.getsource(graphical_task_c_webhook_capture)
    assert "capture_wsgi" in capture
    assert "validate_delivery" in webhook
    assert "hmac.compare_digest" in webhook
    for source in (capture,webhook):
        assert "send_command(" not in source
        assert "send_message(" not in source
        assert "put_object(" not in source


def test_issuer_still_has_distinct_approval_and_github_evidence():
    m=json.loads((ROOT/"docs/graphical-task-c-shared-host-trust-v1.json").read_text())
    assert m["operator_approval_required"] is True
    assert m["original_github_event_provenance_required"] is True
    assert callable(graphical_task_c_issuance.issue_original_registry)
    assert callable(graphical_task_c_issuance.attest_original_github_event)
    assert callable(graphical_task_c_issuance.issue_revocation)
