"""Task C protected S3/SSM owner source end-to-end regressions.

Copyright (c) 2026 Alex Black. BSD-3-Clause OR GPL-3.0-only.
All approvals, signers, ledger files and SendCommand results are local fixtures.
Never call AWS, create native services or authorize a production operation.
"""
import base64
import copy
import os
from pathlib import Path
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import pytest

from zog.root_control import graphical_operation_owner_source as contract
from zog.root_control import graphical_task_c_owner as taskc
from zog.root_control.graphical_native_owner import SelectedOwner
from zog.root_control.graphical_task_c_runtime import (
    TaskCExecutor, RESULT_DOMAIN, RESULT_SCHEMA)
from zog.root_control.graphical_task_c_native import SSMOriginalInspector

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_graphical_native_owner import storage
from test_graphical_task_c_owner import _fixture


class Sender:
    def __init__(self):
        self.sent = []
        self.uncertain = False

    def send_fixed(self, operation_id, command):
        self.sent.append((operation_id, dict(command)))
        if self.uncertain:
            raise TimeoutError("simulated lost SSM reply after one send")
        return "command-%d" % len(self.sent)


class Inspector:
    def __init__(self):
        self.states = {}

    def inspect(self, command_id):
        return self.states.get(command_id, "pending")


def setup(tmp_path):
    registry, records, frames, operator_public = _fixture()
    local, remote, checkpoint, ledger = storage(tmp_path)
    one = next(iter(registry.entries.values()))
    scope = contract.scope_from_request(one["owner_request"])
    approved = {op: contract.digest(item["owner_request"])
                for op, item in registry.entries.items()}
    commands = {op: {
        "approval_id": item["approval"]["approval_id"],
        "script_sha256": "sha256:" + "a" * 64,
        "timeout_seconds": 60,
    } for op, item in registry.entries.items()}
    selection = {
        "scope": scope, "identity": contract.digest(scope),
        "approved": approved, "commands": commands,
    }
    signer = Ed25519PrivateKey.generate()
    sender = Sender()
    inspector = Inspector()
    owner = SelectedOwner(
        ledger, installed=selection, pinned_operator_key=operator_public,
        observation_signer=signer, sender=sender)
    return (TaskCExecutor(registry, protected_owner=owner,
                          ssm_inspector=inspector),
            frames, signer, sender, inspector, ledger)


def observe(frame, nonce="e" * 48):
    return {**frame, "action": "observe-original", "nonce": nonce}


def verify_signed(row, signer):
    signature = base64.b64decode(row["signature_ed25519"], validate=True)
    body = {key: value for key, value in row.items()
            if key != "signature_ed25519"}
    assert body["schema"] == RESULT_SCHEMA
    signer.public_key().verify(signature, RESULT_DOMAIN + contract.canonical(body))


def test_preflight_must_finish_before_distinct_stage_claim(tmp_path):
    executor, frames, signer, sender, inspector, ledger = setup(tmp_path)
    preflight = frames["preflight-original"]
    stage = frames["submit-original"]
    first = executor.handle(preflight, now=400)
    assert first["status"] == "preflight-pending"
    assert first["ssm_state"] == "pending"
    assert first["command_id"] == "command-1"
    verify_signed(first, signer)

    # No stage send may occur while original preflight is still pending.
    with pytest.raises(contract.OperationDenied):
        executor.handle(stage, now=400)
    assert len(sender.sent) == 1

    # Read-only observation is idempotent, never a second SendCommand.
    pending = executor.handle(observe(preflight), now=400)
    assert pending["status"] == "preflight-pending"
    assert len(sender.sent) == 1

    inspector.states["command-1"] = "success"
    ready = executor.handle(observe(preflight), now=400)
    assert ready["status"] == "preflight-ready"
    verify_signed(ready, signer)

    submitted = executor.handle(stage, now=400)
    assert submitted["status"] == "stage-pending"
    assert submitted["command_id"] == "command-2"
    assert len(sender.sent) == 2
    assert sender.sent[0][0] != sender.sent[1][0]
    verify_signed(submitted, signer)

    inspector.states["command-2"] = "success"
    observed = executor.handle(observe(stage, "d"*48), now=400)
    assert observed["status"] == "stage-observed"
    assert observed["nonce"] == "d"*48
    verify_signed(observed, signer)
    with pytest.raises(contract.OperationDenied):
        executor.handle(stage, now=400)
    assert len(sender.sent) == 2


def test_lost_ssm_ack_does_not_reopen_preflight_claim(tmp_path):
    executor, frames, _, sender, _, ledger = setup(tmp_path)
    sender.uncertain = True
    with pytest.raises(TimeoutError):
        executor.handle(frames["preflight-original"], now=400)
    assert len(sender.sent) == 1
    with pytest.raises(contract.OperationDenied):
        executor.handle(frames["preflight-original"], now=400)
    assert len(sender.sent) == 1
    uncertain = executor.handle(observe(frames["preflight-original"]), now=400)
    assert uncertain["status"] == "claimed-uncertain"
    assert uncertain["command_id"] is None


def test_failed_or_unsigned_preflight_cannot_enable_stage(tmp_path):
    executor, frames, signer, sender, inspector, ledger = setup(tmp_path)
    executor.handle(frames["preflight-original"], now=400)
    inspector.states["command-1"] = "failed"
    result = executor.handle(observe(frames["preflight-original"]), now=400)
    assert result["status"] == "preflight-failed"
    verify_signed(result, signer)
    with pytest.raises(contract.OperationDenied):
        executor.handle(frames["submit-original"], now=400)
    assert len(sender.sent) == 1


def test_revocation_serializes_and_halts_all_followup_sends(tmp_path):
    executor, frames, signer, sender, inspector, ledger = setup(tmp_path)
    executor.handle(frames["preflight-original"], now=400)
    inspector.states["command-1"] = "success"
    with ledger.locked():
        ledger.revoke(executor.owner.installed)
    with pytest.raises(contract.OperationDenied):
        executor.handle(frames["submit-original"], now=400)
    with pytest.raises(contract.OperationDenied):
        executor.handle(observe(frames["preflight-original"]), now=400)
    assert len(sender.sent) == 1


def test_signed_mapping_and_short_lived_approval_remain_mandatory(tmp_path):
    executor, frames, _, sender, _, ledger = setup(tmp_path)
    # No installation may create a new operation from gateway-only hints.
    tampered = {**frames["preflight-original"], "origin_trigger_actor":"intruder"}
    with pytest.raises(contract.OperationDenied):
        executor.handle(tampered, now=400)
    with pytest.raises(contract.OperationDenied):
        executor.handle(frames["preflight-original"], now=551)
    assert sender.sent == []


def test_read_only_observe_refuses_unclaimed_operation(tmp_path):
    executor, frames, _, sender, _, _ = setup(tmp_path)
    with pytest.raises(contract.OperationDenied):
        executor.handle(observe(frames["preflight-original"]), now=400)
    assert sender.sent == []


def test_preflight_can_be_held_in_real_s3_adapter_without_send(tmp_path):
    from zog.root_control.graphical_s3_checkpoint import (
        S3AppendOnlyCheckpoint, SCHEMA)
    from test_graphical_s3_checkpoint import Remote
    executor, frames, _, sender, _, ledger = setup(tmp_path)
    identity = executor.owner.installed["identity"]
    genesis = {"schema":SCHEMA, "scope_sha256":identity,
               "sequence":0, "action":"genesis"}
    remote = Remote()
    remote.rows["acceptance/run/000000.json"] = contract.canonical(genesis)
    checkpoint = S3AppendOnlyCheckpoint(
        remote, bucket="test-bucket", prefix="acceptance/run/",
        account_id="123456789012", scope_digest=identity,
        genesis_sha256=contract.digest(genesis))
    ledger.checkpoint = checkpoint
    first = executor.handle(frames["preflight-original"], now=400)
    assert first["status"] == "preflight-pending"
    assert remote.puts == 1 and len(sender.sent) == 1
    with pytest.raises(contract.OperationDenied):
        executor.handle(frames["preflight-original"], now=400)
    assert len(sender.sent) == 1


def test_ssm_observer_requires_matching_original_target_and_success_code():
    class Client:
        def __init__(self):
            self.response = {}
        def get_command_invocation(self, **kwargs):
            assert kwargs == {"CommandId":"command-1",
                              "InstanceId":"i-0123456789abcdef0"}
            return dict(self.response)
    class Session:
        def __init__(self, client):
            self.client_value = client
        def client(self, name, config):
            assert name == "ssm"
            assert config.retries["total_max_attempts"] == 1
            return self.client_value
    client = Client()
    inspector = SSMOriginalInspector(
        Session(client), instance_id="i-0123456789abcdef0")
    client.response = {"CommandId":"command-1","InstanceId":"i-0123456789abcdef0",
                       "Status":"Success","ResponseCode":0}
    assert inspector.inspect("command-1") == "success"
    client.response["ResponseCode"] = 1
    assert inspector.inspect("command-1") == "failed"
    client.response["ResponseCode"] = 0
    client.response["InstanceId"] = "i-fffffffffffffffff"
    with pytest.raises(contract.OperationDenied):
        inspector.inspect("command-1")
