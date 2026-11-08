"""V3 Task C owner rechecks independently protected backend BEFORE any SSM.

Synthetic root-owned ledger and S3 only; no native send or credential issuance.
"""
import sys
from pathlib import Path

import pytest

from zog.root_control import graphical_operation_owner_source as op
from zog.root_control.graphical_task_c_runtime import TaskCExecutor
from zog.root_control.graphical_installation_storage_authority import (
    prospective_genesis)
from zog.root_control.graphical_s3_installation_checkpoint import (
    S3InstallationCheckpoint)

sys.path.insert(0,str(Path(__file__).resolve().parent))
from test_graphical_task_c_runtime import setup
from test_graphical_s3_checkpoint import Remote


def selected(tmp_path, *, attestation):
    original,frames,signer,sender,inspector,ledger=setup(tmp_path)
    selection=original.owner.installed
    registry_sha="sha256:"+"2"*64
    scope_sha="sha256:"+"3"*64
    genesis=prospective_genesis(scope_sha,registry_sha)
    remote=Remote()
    remote.rows["v3/protected/000000.json"]=op.canonical(genesis)
    ledger.checkpoint=S3InstallationCheckpoint(
        remote,bucket="synthetic-bucket",prefix="v3/protected/",
        account_id="123456789012",
        installation_scope_sha256=scope_sha,
        registry_sha256=registry_sha,
        genesis_sha256=op.digest(genesis),
        approved={selection["identity"]:dict(selection["approved"])})
    executor=TaskCExecutor(original.registry,protected_owner=original.owner,
        ssm_inspector=inspector,backend_recheck=attestation)
    return executor,frames,sender,remote


def proof():
    return {
        "backend":"root-directory",
        "registry_sha256":"sha256:"+"2"*64,
        "installation_scope_sha256":"sha256:"+"3"*64,
        "live_snapshot_sha256":"sha256:"+"4"*64,
        "observation_sha256":"sha256:"+"5"*64,
    }


def test_installed_v3_executor_refuses_missing_backend_recheck(tmp_path):
    original,frames,_,sender,inspector,ledger=setup(tmp_path)
    scope_sha="sha256:"+"3"*64
    registry_sha="sha256:"+"2"*64
    genesis=prospective_genesis(scope_sha,registry_sha)
    remote=Remote()
    remote.rows["v3/protected/000000.json"]=op.canonical(genesis)
    ledger.checkpoint=S3InstallationCheckpoint(
        remote,bucket="synthetic-bucket",prefix="v3/protected/",
        account_id="123456789012",installation_scope_sha256=scope_sha,
        registry_sha256=registry_sha,genesis_sha256=op.digest(genesis),
        approved={original.owner.installed["identity"]:dict(
            original.owner.installed["approved"])})
    with pytest.raises(op.OperationDenied):
        TaskCExecutor(original.registry,protected_owner=original.owner,
                      ssm_inspector=inspector)


def test_failed_v3_backend_observation_denies_before_any_external_claim(tmp_path):
    checks=[]
    def reject():
        checks.append("live-observer-rejected")
        raise op.OperationDenied("selected STATE no longer verified")
    executor,frames,sender,remote=selected(tmp_path,attestation=reject)
    with pytest.raises(op.OperationDenied):
        executor.handle(frames["preflight-original"],now=400)
    assert checks==["live-observer-rejected"]
    assert sender.sent==[]
    assert remote.puts==0


@pytest.mark.parametrize("false_proof",(
    None, True, {"native_accepted":True},
    {**proof(),"installation_scope_sha256":"sha256:"+"e"*64},
    {**proof(),"registry_sha256":"sha256:"+"e"*64},
    {**proof(),"backend":"opaque-caller-mode"},
    {**proof(),"ssm_authorized":True},
))
def test_v3_caller_boolean_or_unbound_proof_never_sends(tmp_path,false_proof):
    executor,frames,sender,remote=selected(tmp_path,attestation=lambda:false_proof)
    with pytest.raises(op.OperationDenied):
        executor.handle(frames["preflight-original"],now=400)
    assert sender.sent==[]
    assert remote.puts==0


def test_v3_preflight_uses_single_claim_then_single_send_with_live_check(tmp_path):
    calls=[]
    def attest():
        calls.append("fresh")
        return proof()
    executor,frames,sender,remote=selected(tmp_path,attestation=attest)
    r=executor.handle(frames["preflight-original"],now=400)
    assert r["status"]=="preflight-pending"
    assert len(calls)==1
    assert len(sender.sent)==1
    assert remote.puts==1
    # Rechecking the live backend is mandatory also for observe-only frames.
    def deny():
        calls.append("closed")
        raise op.OperationDenied("changed")
    executor.backend_recheck=deny
    with pytest.raises(op.OperationDenied):
        executor.handle({
            **frames["preflight-original"],"action":"observe-original"
        },now=400)
    assert len(sender.sent)==1
    assert remote.puts==1
