"""Privileged same-Host STATE readback: neither registrar nor new observer key.

All context and signed remote data here are *synthetic tests*, never native GO.
"""
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from zog.root_control import graphical_task_c_backend_observation as native
from zog.root_control import graphical_installation_storage_authority as storage
from zog.root_control import graphical_operation_owner_source as op
from zog.host_install import state_inspect
from zog.host_install.state_contract import canonical, StateError
from test_graphical_installation_storage_authority import selected


class Context:
    def __init__(self, fd, backend, standalone):
        self.fd=fd
        stat=os.fstat(fd)
        dev=f"{os.major(stat.st_dev)}:{os.minor(stat.st_dev)}"
        self.marker={
            "schema":2 if backend=="root-directory" else 1,
            "state_volume_id":"33333333-3333-4333-8333-333333333333",
            "filesystem_uuid":"44444444-4444-4444-8444-444444444444",
            "partition_partuuid":"55555555-5555-4555-8555-555555555555"}
        self.bundle={
            "bootstrap":{
                "installation_id":"22222222-2222-4222-8222-222222222222",
                "registries":[] if standalone else [
                    {"registry_id":"selected-control","role":"control"}],
                "control_authority":None if standalone else {
                    "registry_id":"selected-control"},
                "state":{
                    "storage_backend":backend,
                    "state_volume_id":self.marker["state_volume_id"],
                    "filesystem_uuid":self.marker["filesystem_uuid"],
                    "partition_partuuid":self.marker["partition_partuuid"]}},
            "marker":self.marker}
        self.mount={
            "id":"19" if backend=="root-directory" else "20",
            "device":dev,"backend":backend if backend=="root-directory" else None,
            "state_path":"/state" if backend=="root-directory" else None,
            "target":"/" if backend=="root-directory" else "/state"}
        self.rechecks=0
    def recheck(self):self.rechecks+=1
    def __enter__(self):return self
    def __exit__(self,*_):return False


def make(monkeypatch,*,backend="root-directory",local=False):
    prior=selected()
    fd=os.open("/",os.O_RDONLY|os.O_DIRECTORY)
    context=Context(fd,backend,local)
    if local:
        req=prior["request"]
        identity={
            "schema":storage.LOCAL_SCHEMA,
            **{k:req[k] for k in ("host_id","host_fingerprint",
                                   "target_identity_sha256",
                                   "installation_id","state_volume_id")},
            "host_install_installation_uuid":context.bundle[
                "bootstrap"]["installation_id"],
            "host_install_state_uuid":context.marker["state_volume_id"],
        }
    else:
        identity=prior["registry"]
    monkeypatch.setattr(state_inspect,"inspect_live",lambda:context)
    monkeypatch.setattr(state_inspect,"read_at",
                        lambda fd,name:canonical(context.marker))
    monkeypatch.setattr(native.os,"geteuid",lambda:0)
    monkeypatch.setattr(native,"_read_root",lambda path,**kw:
        (prior["registrar"] if str(path)==native.REGISTRY_PIN else
         op.canonical(identity)))
    return SimpleNamespace(identity=identity,context=context,fd=fd,local=local)


@pytest.mark.parametrize("backend",("root-directory","mounted-volume"))
@pytest.mark.parametrize("local",(False,True))
def test_live_state_from_host_install_requires_no_observer_signer(
        monkeypatch,backend,local):
    fixture=make(monkeypatch,backend=backend,local=local)
    try:
        proof=native.require_live_backend_bound_identity(
            expected_registry=fixture.identity,allow_local=local)
        assert proof["backend"]==backend
        assert proof["registry_sha256"]==op.digest(fixture.identity)
        assert proof["live_snapshot_sha256"]==proof["observation_sha256"]
        assert fixture.context.rechecks>=3
        assert not any(k in proof for k in
                       ("native_accepted","ssm_authorized","registrar_signed"))
    finally:os.close(fixture.fd)


@pytest.mark.parametrize("attack",(
    "missing_state","substituted_local_record","changed_marker",
    "changed_state_uuid","changed_install_uuid","changed_mount",
    "changed_descriptor","backend_switch","native_true","wrong_mode",
    "local_record_with_legacy_mode","legacy_without_registry",
))
def test_untrusted_local_record_never_satisfies_live_backend(monkeypatch,attack):
    local=attack not in ("local_record_with_legacy_mode",
                         "legacy_without_registry")
    fixture=make(monkeypatch,local=local)
    try:
        if attack=="missing_state":
            def fail():raise StateError("not-installed","no /state")
            monkeypatch.setattr(state_inspect,"inspect_live",fail)
        elif attack=="substituted_local_record":
            fixture.identity["host_id"]="f"*64
        elif attack=="changed_marker":
            fixture.context.marker["state_volume_id"]="foreign"
        elif attack=="changed_state_uuid":
            fixture.context.bundle["bootstrap"]["state"]["state_volume_id"]="foreign"
        elif attack=="changed_install_uuid":
            fixture.context.bundle["bootstrap"]["installation_id"]="foreign"
        elif attack=="changed_mount":
            fixture.context.mount["device"]="0:1"
        elif attack=="changed_descriptor":
            fixture.context.fd=os.open("/tmp",os.O_RDONLY|os.O_DIRECTORY)
        elif attack=="backend_switch":
            fixture.context.bundle["bootstrap"]["state"]["storage_backend"]="mounted-volume"
        elif attack=="native_true":
            fixture.identity["native_accepted"]=True
        elif attack=="wrong_mode":
            pass
        elif attack=="local_record_with_legacy_mode":
            fixture.identity={"schema":storage.LOCAL_SCHEMA}
        elif attack=="legacy_without_registry":
            fixture.context.bundle["bootstrap"]["registries"]=[]
            fixture.context.bundle["bootstrap"]["control_authority"]=None
        allow=(not local if attack=="wrong_mode" else local)
        with pytest.raises(op.OperationDenied):
            native.require_live_backend_bound_identity(
                expected_registry=fixture.identity,allow_local=allow)
    finally:
        os.close(fixture.fd)
        if attack=="changed_descriptor":os.close(fixture.context.fd)
