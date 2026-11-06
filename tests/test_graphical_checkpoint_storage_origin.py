"""Checkpoint scope classification: only original evidence or distinct new approval."""
import copy
import pytest
from zog.root_control import graphical_checkpoint_storage_origin as s
from zog.root_control import graphical_operation_owner_source as o
from zog.root_control.graphical_native_owner import NativeHold

def original():
    return {
      "schema":s.ORIGINAL_RECORD,"host_id":"a"*64,
      "installation_id":"b"*64,"state_volume_id":"c"*64,
      "checkpoint_scope_sha256":"sha256:"+"d"*64,
      "checkpoint_account_id":"123456789012","checkpoint_region":"us-east-1",
      "checkpoint_bucket":"retained-original",
      "checkpoint_prefix":"original/source/",
      "checkpoint_genesis_sha256":"sha256:"+"e"*64,
      "checkpoint_role_arn":"arn:aws:iam::123456789012:role/OriginalWriter",
      "root_source_revision":"5ad7d5ed72d1b72edc767a658de28506791a74d4",
    }

def fixture():
    record=original()
    row={"schema":s.SCHEMA,"mode":s.ORIGINAL,
         "host_id":record["host_id"],"installation_id":record["installation_id"],
         "state_volume_id":record["state_volume_id"],
         "scope_sha256":record["checkpoint_scope_sha256"],
         "account_id":record["checkpoint_account_id"],
         "region":record["checkpoint_region"],"bucket":record["checkpoint_bucket"],
         "prefix":record["checkpoint_prefix"],"genesis_sha256":record["checkpoint_genesis_sha256"],
         "writer_role_arn":record["checkpoint_role_arn"],
         "authorization_sha256":"sha256:"+"f"*64,
         "original_record_sha256":o.digest(record),
         "anchor_identity_sha256":"sha256:"+"1"*64,
         "external_genesis_verified":False,"external_chain_verified":False,
         "original_operator_authorization_verified":False,
         "independent_anchor_verified":False}
    return row,record

def test_original_source_review_does_not_claim_remote_history_or_native_authority():
    row,record=fixture()
    found=s.assess_checkpoint_origin(row,original_record=record,
        independently_retained_record_digest=o.digest(record))
    assert found["classification"]=="ORIGINAL_HISTORY_EXTERNAL_AUTHENTICATION_REQUIRED"
    assert all(x is False for k,x in found.items() if k!="classification")

@pytest.mark.parametrize("field,new",[
    ("account_id","999999999999"),("region","eu-west-1"),
    ("bucket","replacement"),("prefix","different/"),
    ("genesis_sha256","sha256:"+"9"*64),
    ("writer_role_arn","arn:aws:iam::123456789012:role/Replaced"),
    ("scope_sha256","sha256:"+"8"*64),
    ("state_volume_id","f"*64),("installation_id","f"*64)])
def test_original_substitutions_denied(field,new):
    row,record=fixture();row[field]=new
    with pytest.raises(ValueError):
        s.assess_checkpoint_origin(row,original_record=record,
            independently_retained_record_digest=o.digest(record))

def test_original_missing_or_ambiguous_history_is_not_new_genesis():
    row,record=fixture()
    for kwargs in ({},{ "original_record":record },
                   {"original_record":record,
                    "independently_retained_record_digest":"sha256:"+"0"*64}):
        with pytest.raises(ValueError):
            s.assess_checkpoint_origin(row,**kwargs)

def test_new_scope_distinct_and_not_historical_continuation():
    row,record=fixture()
    row.update(mode=s.NEW,original_record_sha256=None,anchor_identity_sha256=None,
               scope_sha256="sha256:"+"8"*64,genesis_sha256="sha256:"+"9"*64)
    found=s.assess_checkpoint_origin(row)
    assert found["classification"]=="NEW_SCOPE_SEPARATE_AUTHORIZATION_REQUIRED"
    assert found["native_accepted"] is False
    with pytest.raises(ValueError):
        s.assess_checkpoint_origin(row,original_record=record)
    with pytest.raises(ValueError):
        s.assess_checkpoint_origin(row,independently_retained_record_digest=o.digest(record))

@pytest.mark.parametrize("key",["external_genesis_verified","external_chain_verified",
    "original_operator_authorization_verified","independent_anchor_verified"])
def test_caller_asserted_verification_cannot_issue_proof(key):
    row,record=fixture();row[key]=True
    with pytest.raises(ValueError):
        s.assess_checkpoint_origin(row,original_record=record,
            independently_retained_record_digest=o.digest(record))
