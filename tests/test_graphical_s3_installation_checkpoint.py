"""Synthetic S3 installation authority: no AWS calls and no SSM admission."""
import copy
import sys
from pathlib import Path
import pytest

from zog.root_control import graphical_operation_owner_source as op
from zog.root_control import graphical_installation_storage_authority as authority
from zog.root_control.graphical_s3_installation_checkpoint import (
    S3InstallationCheckpoint, SCHEMA)

sys.path.insert(0,str(Path(__file__).resolve().parent))
from test_graphical_s3_checkpoint import Remote
from test_graphical_installation_storage_authority import selected


def setup_remote(*, add_genesis=True):
    pick=selected()
    r=pick["request"]
    req2={**r, "operation_id":"e"*32,
          "approval_sha256":"sha256:"+"c"*64,
          "catalogue_sha256":"sha256:"+"d"*64}
    scope1=op.digest(op.scope_from_request(r))
    scope2=op.digest(op.scope_from_request(req2))
    approved={scope1:{r["operation_id"]:op.digest(r)},
              scope2:{req2["operation_id"]:op.digest(req2)}}
    remote=Remote()
    genesis=authority.prospective_genesis(
        pick["authority"]["installation_scope_sha256"],
        pick["authority"]["registry_sha256"])
    if add_genesis:
        remote.rows["new/installation/000000.json"]=op.canonical(genesis)
    def ctor():
        return S3InstallationCheckpoint(
            remote,bucket="synthetic-accepted-new",
            prefix="new/installation/",account_id="123456789012",
            installation_scope_sha256=pick["authority"]["installation_scope_sha256"],
            registry_sha256=pick["authority"]["registry_sha256"],
            genesis_sha256=op.digest(genesis),approved=approved)
    return remote,ctor,(scope1,r),(scope2,req2)


def test_missing_genesis_never_creates_new_scope():
    remote,ctor,(scope,r),_=setup_remote(add_genesis=False)
    with pytest.raises(op.OperationDenied):
        ctor().claim_once(scope,r["operation_id"],op.digest(r))
    assert remote.puts==0


def test_two_distinct_request_scopes_share_installation_history_without_cross_revocation():
    remote,ctor,(first,a),(second,b)=setup_remote()
    ledger=ctor()
    assert ledger.scope != first and ledger.scope != second
    ledger.claim_once(first,a["operation_id"],op.digest(a))
    ledger.revoke(first)
    assert ctor().inspect_current(first)=={"revoked":True}
    with pytest.raises(op.OperationDenied):
        ctor().claim_once(first,a["operation_id"],op.digest(a))
    ctor().claim_once(second,b["operation_id"],op.digest(b))
    assert ctor().inspect_current(second)=={"revoked":False}
    assert ctor().inspect_claim(second,b["operation_id"],op.digest(b))[
        "operation_id"]==b["operation_id"]
    assert ctor().current_witness(first)["revoked"] is True
    assert ctor().current_witness(second)["revoked"] is False
    assert len(remote.rows)==4


def test_duplicate_or_cross_scope_claim_never_resends():
    remote,ctor,(scope,a),(other,b)=setup_remote()
    ctor().claim_once(scope,a["operation_id"],op.digest(a))
    for wrong in [
        (scope,a["operation_id"],op.digest(a)),
        (other,a["operation_id"],op.digest(a)),
        (scope,b["operation_id"],op.digest(b)),
    ]:
        with pytest.raises(op.OperationDenied):
            ctor().claim_once(*wrong)
    assert remote.puts==1


def test_lost_ack_is_hard_hold_even_after_remote_claim_exists():
    remote,ctor,(scope,a),_=setup_remote()
    remote.lost_ack=True
    with pytest.raises(op.OperationDenied):
        ctor().claim_once(scope,a["operation_id"],op.digest(a))
    remote.lost_ack=False
    with pytest.raises(op.OperationDenied):
        ctor().claim_once(scope,a["operation_id"],op.digest(a))
    assert remote.puts==1


@pytest.mark.parametrize("failure", (
    "unrecognized-genesis", "tampered-history",
    "missing-history-denied", "wrong-authority", "wrong-request"))
def test_corrupt_or_ambiguous_installation_history_denied(failure):
    remote,ctor,(scope,a),_=setup_remote()
    ctor().claim_once(scope,a["operation_id"],op.digest(a))
    if failure=="unrecognized-genesis":
        remote.rows["new/installation/000000.json"]=b'{}'
    elif failure=="tampered-history":
        remote.rows["new/installation/000001.json"]=b'{"action":"claim"}'
    elif failure=="missing-history-denied":
        remote.denied=True
    elif failure=="wrong-authority":
        with pytest.raises(op.OperationDenied):
            S3InstallationCheckpoint(
                remote,bucket="synthetic-accepted-new",
                prefix="new/installation/",account_id="123456789012",
                installation_scope_sha256="sha256:"+"0"*64,
                registry_sha256=selected()["authority"]["registry_sha256"],
                genesis_sha256=selected()["authority"]["checkpoint_genesis_sha256"],
                approved={scope:{a["operation_id"]:op.digest(a)}})
        return
    elif failure=="wrong-request":
        with pytest.raises(op.OperationDenied):
            ctor().inspect_claim(scope,a["operation_id"],"sha256:"+"0"*64)
        return
    with pytest.raises(op.OperationDenied):
        ctor().inspect_claim(scope,a["operation_id"],op.digest(a))


def test_later_request_can_scan_older_immutable_scopes_after_runtime_restart():
    remote,ctor,(first,a),(second,b)=setup_remote()
    previous=ctor()
    previous.claim_once(first,a["operation_id"],op.digest(a))
    previous.revoke(first)
    # A later owner's installed registry contains only its *new* separately
    # signed operation. It must not need expired old approvals to validate
    # old immutable chain links, but it must still reject duplicate IDs.
    later=S3InstallationCheckpoint(
        remote,bucket="synthetic-accepted-new",
        prefix="new/installation/",account_id="123456789012",
        installation_scope_sha256=previous.scope,
        registry_sha256=previous.registry_sha,
        genesis_sha256=previous.genesis_sha,
        approved={second:{b["operation_id"]:op.digest(b)}})
    later.claim_once(second,b["operation_id"],op.digest(b))
    assert later.inspect_current(second)=={"revoked":False}
    assert later.inspect_claim(second,b["operation_id"],op.digest(b))[
        "request_sha256"]==op.digest(b)
    with pytest.raises(op.OperationDenied):
        later.claim_once(second,b["operation_id"],op.digest(b))
    assert remote.puts==3
