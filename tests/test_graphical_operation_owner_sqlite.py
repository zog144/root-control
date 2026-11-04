"""Disk-backed graphical owner source regression; NOT native antirollback."""
import concurrent.futures
import pathlib
import threading
import pytest
from zog.root_control import graphical_operation_owner_source as protocol
from zog.root_control import graphical_operation_owner_sqlite as durable
from test_graphical_operation_owner_source import request

def create(tmp_path):
    req=request()
    scope=protocol.scope_from_request(req)
    storage_id="e"*64
    root=tmp_path/"independent-owner"
    durable.provision_synthetic_fixture(root,scope=scope,operations={
        req["operation_id"]:protocol.digest(req)},storage_id=storage_id)
    checkpoint={"schema":"zog-graphical-owner-independent-highwater-v1",
                "storage_id":storage_id,"scope_sha256":protocol.digest(scope),
                "minimum_sequence":0}
    return root,scope,checkpoint

def owner(root,scope,checkpoint):
    return durable.ExistingOwnerLedger(root,approved_scope=scope,
                                      external_checkpoint=checkpoint)

def test_irreversible_send_survives_reopen_and_gateway_rollback(tmp_path):
    root,scope,cp=create(tmp_path)
    sends=[]
    result=owner(root,scope,cp).claim_and_send(request(),sender=lambda r: sends.append(r) or "cmd-1")
    assert result["outcome"]=="SENT_ORIGINAL"
    assert owner(root,scope,cp).inspect(request()["operation_id"])["command_id"]=="cmd-1"
    with pytest.raises(protocol.OperationDenied):
        owner(root,scope,cp).claim_and_send(request(),sender=lambda _:pytest.fail("replay"))
    assert len(sends)==1

def test_lost_ack_durable_claim_never_resends(tmp_path):
    root,scope,cp=create(tmp_path)
    def lose(_):raise TimeoutError("SSM accepted, response lost")
    with pytest.raises(TimeoutError):
        owner(root,scope,cp).claim_and_send(request(),sender=lose)
    assert owner(root,scope,cp).inspect(request()["operation_id"])["outcome"]=="CLAIMED_UNCERTAIN"
    with pytest.raises(protocol.OperationDenied):
        owner(root,scope,cp).claim_and_send(request(),sender=lambda _:pytest.fail("resend"))

def test_revoked_before_send_and_after_restart(tmp_path):
    root,scope,cp=create(tmp_path)
    assert owner(root,scope,cp).revoke(scope)==1
    assert owner(root,scope,cp).revoke(scope)==1
    with pytest.raises(protocol.OperationDenied):
        owner(root,scope,cp).claim_and_send(request(),sender=lambda _:pytest.fail("revoked"))

def test_two_distinct_owner_instances_serialize_claim_and_revocation(tmp_path):
    root,scope,cp=create(tmp_path)
    entered=threading.Event(); release=threading.Event()
    sent=[]
    def sender(req):
        sent.append(req);entered.set()
        assert release.wait(4)
        return "cmd"
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        a=pool.submit(owner(root,scope,cp).claim_and_send,request(),sender=sender)
        assert entered.wait(4)
        duplicate=pool.submit(owner(root,scope,cp).claim_and_send,request(),sender=lambda _:pytest.fail("second"))
        revoked=pool.submit(owner(root,scope,cp).revoke,scope)
        assert not duplicate.done() and not revoked.done()
        release.set()
        assert a.result(timeout=5)["command_id"]=="cmd"
        with pytest.raises(protocol.OperationDenied):duplicate.result(timeout=5)
        assert revoked.result(timeout=5)==2
    assert len(sent)==1

def test_missing_replaced_or_rolled_back_source_highwater_denied(tmp_path):
    root,scope,cp=create(tmp_path)
    with pytest.raises(protocol.OperationDenied):
        owner(root,scope,{**cp,"minimum_sequence":2}).inspect(request()["operation_id"])
    (root/"owner.sqlite3").unlink()
    with pytest.raises(protocol.OperationDenied):
        owner(root,scope,cp).inspect(request()["operation_id"])

def test_exact_original_approval_and_same_id_conflict(tmp_path):
    root,scope,cp=create(tmp_path)
    changed={**request(),"remote_request_sha256":"sha256:"+"0"*64}
    with pytest.raises(protocol.OperationDenied):
        owner(root,scope,cp).claim_and_send(changed,sender=lambda _:pytest.fail("unauthorized"))
    assert owner(root,scope,cp).claim_and_send(request(),sender=lambda _:"accepted")["outcome"]=="SENT_ORIGINAL"
