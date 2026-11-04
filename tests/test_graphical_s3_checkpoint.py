"""External checkpoint source tests; no AWS or native admission claim.
Copyright (c) 2026 Alex Black. BSD-3-Clause OR GPL-3.0-only.
"""
import io
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from botocore.exceptions import ClientError, ReadTimeoutError

from zog.root_control import graphical_operation_owner_source as contract
from zog.root_control.graphical_s3_checkpoint import S3AppendOnlyCheckpoint, SCHEMA

SCOPE = "sha256:" + "a" * 64
DIGEST = "sha256:" + "b" * 64
OP = "c" * 32


class Remote:
    def __init__(self):
        self.rows = {}
        self.lock = threading.Lock()
        self.puts = 0
        self.lost_ack = False
        self.conflict = False
        self.barrier = None
        self.denied = False

    def get_object(self, **kw):
        assert kw["ExpectedBucketOwner"] == "123456789012"
        with self.lock:
            raw = self.rows.get(kw["Key"])
        if self.denied:
            raise ClientError({"Error": {"Code": "AccessDenied"},
                               "ResponseMetadata": {"HTTPStatusCode": 403}}, "GetObject")
        if raw is None:
            raise ClientError({"Error": {"Code": "NoSuchKey"},
                               "ResponseMetadata": {"HTTPStatusCode": 404}}, "GetObject")
        return {"ContentLength": len(raw), "Body": io.BytesIO(raw)}

    def put_object(self, **kw):
        assert kw["IfNoneMatch"] == "*"
        assert kw["ExpectedBucketOwner"] == "123456789012"
        if self.barrier:
            self.barrier.wait(timeout=3)
        with self.lock:
            self.puts += 1
            if kw["Key"] in self.rows or self.conflict:
                raise ClientError({"Error": {"Code": "PreconditionFailed"},
                                   "ResponseMetadata": {"HTTPStatusCode": 412}}, "PutObject")
            self.rows[kw["Key"]] = kw["Body"]
        if self.lost_ack:
            raise ReadTimeoutError(endpoint_url="https://s3.invalid")
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}


def backend(remote):
    genesis = {"schema": SCHEMA, "scope_sha256": SCOPE,
               "sequence": 0, "action": "genesis"}
    return S3AppendOnlyCheckpoint(remote, bucket="test-bucket", prefix="acceptance/run/",
        account_id="123456789012", scope_digest=SCOPE,
        genesis_sha256=contract.digest(genesis))


def provision(remote):
    remote.rows["acceptance/run/000000.json"] = contract.canonical({
        "schema": SCHEMA, "scope_sha256": SCOPE, "sequence": 0, "action": "genesis"})
    return backend(remote)


def test_missing_genesis_never_bootstraps_authority():
    remote = Remote()
    with pytest.raises(contract.OperationDenied):
        backend(remote).claim_once(SCOPE, OP, DIGEST)
    assert remote.puts == 0


def test_full_local_reconstruction_cannot_replay_remote_claim():
    remote = Remote()
    provision(remote).claim_once(SCOPE, OP, DIGEST)
    fresh = backend(remote)
    assert fresh.inspect_claim(SCOPE, OP, DIGEST)["request_sha256"] == DIGEST
    with pytest.raises(contract.OperationDenied):
        fresh.claim_once(SCOPE, OP, DIGEST)
    assert remote.puts == 1


def test_lost_ack_is_not_retried_or_reclaimed():
    remote = Remote()
    checkpoint = provision(remote)
    remote.lost_ack = True
    with pytest.raises(contract.OperationDenied):
        checkpoint.claim_once(SCOPE, OP, DIGEST)
    remote.lost_ack = False
    with pytest.raises(contract.OperationDenied):
        backend(remote).claim_once(SCOPE, OP, DIGEST)
    assert remote.puts == 1


def test_concurrent_distinct_claims_do_not_advance_after_cas_conflict():
    remote = Remote()
    provision(remote)
    remote.barrier = threading.Barrier(2)
    def claim(op):
        try:
            backend(remote).claim_once(SCOPE, op, DIGEST)
            return True
        except contract.OperationDenied:
            return False
    with ThreadPoolExecutor(2) as pool:
        assert sorted(pool.map(claim, [OP, "d" * 32])) == [False, True]
    assert remote.puts == 2
    assert set(remote.rows) == {"acceptance/run/000000.json", "acceptance/run/000001.json"}


def test_revocation_survives_local_rollback():
    remote = Remote()
    checkpoint = provision(remote)
    checkpoint.claim_once(SCOPE, OP, DIGEST)
    checkpoint.revoke(SCOPE)
    fresh = backend(remote)
    assert fresh.inspect_current(SCOPE) == {"revoked": True}
    with pytest.raises(contract.OperationDenied):
        fresh.claim_once(SCOPE, "e" * 32, DIGEST)
    assert remote.puts == 2


@pytest.mark.parametrize("failure", ["denied", "changed-genesis", "changed-event", "wrong-scope"])
def test_uncertain_or_changed_history_blocks_without_write(failure):
    remote = Remote()
    checkpoint = provision(remote)
    checkpoint.claim_once(SCOPE, OP, DIGEST)
    if failure == "denied":
        remote.denied = True
    elif failure == "changed-genesis":
        remote.rows["acceptance/run/000000.json"] = b'{}'
    elif failure == "changed-event":
        remote.rows["acceptance/run/000001.json"] = b'{}'
    with pytest.raises(contract.OperationDenied):
        checkpoint.claim_once("sha256:" + "f" * 64 if failure == "wrong-scope" else SCOPE,
                              "e" * 32, DIGEST)
    assert remote.puts == 1


def test_failed_checkpoint_prevents_actual_ledger_sender(tmp_path):
    from test_graphical_native_owner import setup
    req, selection, _, _, _, grant, owner, sender, _, _ = setup(tmp_path)
    # Existing SelectedOwner exercises the actual claim-before-send integration.
    owner.ledger.checkpoint = backend(Remote())
    with pytest.raises(contract.OperationDenied):
        owner.submit(req, grant, now=400)
    assert sender.calls == []


def test_real_sdk_serializes_conditional_create():
    import boto3
    from botocore.config import Config
    from botocore.stub import Stubber
    client = boto3.client('s3', region_name='us-east-1',
        aws_access_key_id='AKIA' + 'A' * 16, aws_secret_access_key='x' * 40,
        config=Config(retries={'total_max_attempts': 1}))
    checkpoint = backend(client)
    with Stubber(client) as stub:
        genesis = {"schema": SCHEMA, "scope_sha256": SCOPE, "sequence": 0, "action": "genesis"}
        raw = contract.canonical(genesis)
        stub.add_response('get_object', {'ContentLength': len(raw), 'Body': io.BytesIO(raw)},
                          checkpoint._args(0))
        stub.add_client_error('get_object', service_error_code='NoSuchKey', http_status_code=404,
                              expected_params=checkpoint._args(1))
        event = {"schema": SCHEMA, "scope_sha256": SCOPE, "sequence": 1,
                 "previous_sha256": contract.digest(genesis), "action": "claim",
                 "operation_id": OP, "request_sha256": DIGEST}
        raw = contract.canonical(event)
        stub.add_response('put_object', {'ResponseMetadata': {'HTTPStatusCode': 200}},
            {**checkpoint._args(1), 'Body': raw, 'ContentType': 'application/json', 'IfNoneMatch': '*'})
        stub.add_response('get_object', {'ContentLength': len(raw), 'Body': io.BytesIO(raw)},
                          checkpoint._args(1))
        checkpoint.claim_once(SCOPE, OP, DIGEST)
        stub.assert_no_pending_responses()


def test_invalid_absent_claim_does_not_compare_equal_to_none():
    remote = Remote()
    checkpoint = provision(remote)
    with pytest.raises(contract.OperationDenied):
        checkpoint.inspect_claim(SCOPE, OP, None)
