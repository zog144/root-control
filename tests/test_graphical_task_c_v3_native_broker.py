"""Whole installed v3 broker constructor uses only GetObject and exact signed source.

The mount/anchor reader is stubbed at its separately tested verification seam;
no real filesystem, AWS call, SSM session or native enablement is performed.
"""
import sys
from pathlib import Path

import pytest

from zog.root_control import graphical_operation_owner_source as op
from zog.root_control import graphical_installation_storage_authority as storage
from zog.root_control import graphical_task_c_trust_authority as trust
from zog.root_control import graphical_task_c_native as native
from zog.root_control.graphical_s3_installation_checkpoint import S3InstallationCheckpoint

sys.path.insert(0,str(Path(__file__).resolve().parent))
from test_graphical_task_c_v3_readonly import selected
from test_graphical_s3_checkpoint import Remote


def selection(monkeypatch, *, wrong_reader=False):
    row=selected()
    record=row["storage_record"]
    remote=Remote()
    remote.rows[record["checkpoint_prefix"]+"000000.json"]=op.canonical(
        storage.prospective_genesis(
            record["installation_scope_sha256"],record["registry_sha256"]))
    inputs={
        trust.BROKER_CONFIG:row["broker_config"],
        trust.OWNER_REGISTRY:row["root_row"],
        trust.ISSUER_EVENT:row["evidence"],
        trust.GATEWAY_PIN:row["pin"],
        trust.PURPOSE_APPROVAL:row["approval"],
        native.STORAGE_COMMIT:row["storage_commit"],
    }
    def read_json(path,**kw):
        assert path in inputs
        data=inputs[path]
        return op.canonical(data),data
    keys={
        trust.OPERATOR:row["operator_key"],
        trust.ISSUER:row["issuer_key"],
        trust.OBSERVATION_PUBLIC:row["observation_public"],
        trust.SIGNING_CREDENTIAL:row["broker_signer"].private_bytes_raw(),
    }
    def read_key(path,**kw):
        if path==native.STORAGE_REGISTRY:
            # Constructor captures protected selected bytes, but the
            # native selector remains separately mocked in this unit test.
            return op.canonical({"schema":"synthetic-only"})
        assert path in keys
        return keys[path]
    monkeypatch.setattr(trust,"_checked_json",read_json)
    monkeypatch.setattr(trust,"_read_root",read_key)
    monkeypatch.setattr(trust.os,"geteuid",lambda:0)
    monkeypatch.setattr(trust.sys,"argv",["broker"])
    monkeypatch.setattr(trust,"_installed_gateway_source_digest",
                        lambda:row["selected_broker_sha"])
    monkeypatch.setattr(trust,"_installed_v3_root_source_digest",
                        lambda:row["selected_root_source_sha"])
    monkeypatch.setattr(trust.time,"time",lambda:400)
    monkeypatch.setattr(trust.Path,"read_text",
                        lambda p,**kw:row["broker_config"]["boot_id"])
    def selected_storage(root_row,selection,registry,operator,*,now):
        assert root_row is row["root_row"]
        assert now==400
        assert selection["identity"]==row["pin"]["scope_sha256"]
        assert operator==row["operator_key"]
        return record["installation_scope_sha256"],record
    monkeypatch.setattr(native,"_selected_installation_storage",selected_storage)
    role=record["checkpoint_reader_role_arn"]
    def session(path,*,account,region,role_arn):
        assert path==trust.READ_CREDENTIAL
        assert account==record["checkpoint_account_id"]
        assert region==record["checkpoint_region"]
        assert role_arn==("arn:aws:iam::123456789012:role/Wrong" if wrong_reader
                         else role)
        class Session:
            def client(self,name,config):
                assert name=="s3"
                return remote
        return Session(),{"role":"synthetic-readonly"}
    monkeypatch.setattr(trust,"_session",session)
    return row,remote


def test_whole_v3_constructor_uses_signed_commit_and_readonly_genesis(monkeypatch):
    row,remote=selection(monkeypatch)
    from zog.host_deploy.gateway.graphics_owner_trust_daemon import InstalledReadOnlyAuthority
    accepted=trust.installed_readonly_authority()
    assert type(accepted) is InstalledReadOnlyAuthority
    assert isinstance(accepted.checkpoint,S3InstallationCheckpoint)
    assert accepted.checkpoint.scope==row["storage_record"][
        "installation_scope_sha256"]
    assert accepted.signed_pin["scope_sha256"]!=accepted.checkpoint.scope
    assert accepted.original_checkpoint==row["storage_record"]
    assert accepted.checkpoint.current_witness(
        row["pin"]["scope_sha256"])["sequence"]==0
    assert not hasattr(accepted.checkpoint.client,"put_object")
    assert not hasattr(accepted.checkpoint.client,"send_command")
    assert remote.puts==0


def test_v3_constructor_never_reads_old_original_checkpoint(monkeypatch):
    row,remote=selection(monkeypatch)
    def fail_old():
        pytest.fail("historical v2 original selector was invoked")
    monkeypatch.setattr(trust,"read_original_record",fail_old)
    assert trust.installed_readonly_authority().signed_pin==row["pin"]


def test_v3_constructor_holds_on_misplaced_root_source(monkeypatch):
    row,_=selection(monkeypatch)
    monkeypatch.setattr(trust,"_installed_v3_root_source_digest",
                        lambda:"sha256:"+"0"*64)
    with pytest.raises(op.OperationDenied):
        trust.installed_readonly_authority()
