"""Source-only deployment checks for bounded keyless capture.

No native TLS endpoint, original delivery, public-pin enrollment or Host policy
is tested by these fixtures.
"""
from pathlib import Path
import json

ROOT = Path(__file__).resolve().parents[1]


def test_capture_unit_has_only_hmac_and_policy_credentials():
    unit = (ROOT/"examples/github-capture/zog-github-capture.service").read_text()
    expected = {
        "LoadCredential=policy.json:/etc/zog/github-capture/policy.json",
        "LoadCredential=webhook.hmac:/etc/zog/github-capture/webhook.hmac",
    }
    actual = {line for line in unit.splitlines()
              if line.startswith(("LoadCredential=", "SetCredential=", "LoadCredentialEncrypted="))}
    assert actual == expected
    assert "User=zog-github-capture" in unit
    assert "StateDirectoryMode=0700" in unit
    assert "ProtectSystem=strict" in unit
    assert "RestrictAddressFamilies=AF_UNIX" in unit
    assert "IPAddressDeny=any" in unit
    assert "NoNewPrivileges=true" in unit
    assert "zog.root_control.graphical_task_c_capture_app:create_app()" in unit
    assert "ssm:SendCommand" not in unit
    assert "aws-session.json" not in unit
    assert "broker-private.key" not in unit
    assert "operator.private" not in unit
    assert "event.private" not in unit
    assert "ExecStartPost=" not in unit


def test_public_https_route_does_not_forward_compiler_launch():
    nginx = (ROOT/"examples/github-capture/nginx-location.conf").read_text()
    assert "location = /zog/task-c/original {" in nginx
    assert "client_max_body_size 64k;" in nginx
    assert "proxy_request_buffering on;" in nginx
    assert "proxy_pass http://unix:/run/zog-github-capture/capture.sock;" in nginx
    assert "proxy_set_header Host $host;" in nginx
    assert "proxy_pass http://localhost:8080" not in nginx
    assert "ssm" not in nginx.lower()


def test_shared_admin_model_preserves_event_and_owner_gates():
    selected = json.loads((ROOT/"docs/graphical-task-c-shared-host-trust-v1.json").read_text())
    assert selected["administrator_can_access_local_ssm_authority"] is True
    assert selected["separate_cryptographic_role_identities_required"] is True
    assert selected["original_github_event_provenance_required"] is True
    assert selected["operator_approval_required"] is True
    assert selected["owner_claims_required"] is True
    assert selected["normal_owner_path_bypass_permitted"] is False
    assert selected["original_history_recreation_permitted"] is False
