"""Live STATE descriptor and independent signed observer, no withdrawn registrar mapping.

All signers, Host IDs, fs descriptors and evidence are synthetic. Source-only.
"""
import base64
import os
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from zog.root_control import graphical_task_c_backend_observation as native
from zog.root_control import graphical_installation_storage_authority as storage
from zog.root_control import graphical_operation_owner_source as op
from zog.host_install import state_inspect
from zog.host_install.state_contract import canonical,StateError
from test_graphical_installation_storage_authority import selected as registered


def pub(private):
    return private.public_key().public_bytes(
        serialization.Encoding.Raw,serialization.PublicFormat.Raw)


class Context:
    def __init__(self,fd,backend):
        st=os.fstat(fd)
        dev=f"{os.major(st.st_dev)}:{os.minor(st.st_dev)}"
        self.fd=fd
        self.marker={
            "schema":2 if backend=="root-directory" else 1,
            "state_volume_id":"33333333-3333-4333-8333-333333333333",
            "filesystem_uuid":"44444444-4444-4444-8444-444444444444",
            "partition_partuuid":"55555555-5555-4555-8555-555555555555"}
        self.bundle={
            "bootstrap":{
                "registries":[{"registry_id":"selected-control","role":"control"}],
                "control_authority":{"registry_id":"selected-control"},
                "state":{
                    "storage_backend":backend,
                    "state_volume_id":self.marker["state_volume_id"],
                    "filesystem_uuid":self.marker["filesystem_uuid"],
                    "partition_partuuid":self.marker["partition_partuuid"]}},
            "marker":self.marker}
        self.mount={
            "id":"19" if backend=="root-directory" else "20",
            "device":dev,
            "backend":"root-directory" if backend=="root-directory" else None,
            "target":"/" if backend=="root-directory" else "/state",
            "state_path":"/state" if backend=="root-directory" else None}
        self.rechecks=0
    def recheck(self):self.rechecks+=1
    def __enter__(self):return self
    def __exit__(self,*_):return False


def source(monkeypatch,backend="root-directory"):
    original=registered()
    registry=original["registry"]
    key=Ed25519PrivateKey.generate()
    fd=os.open("/",os.O_RDONLY|os.O_DIRECTORY)
    context=Context(fd,backend)
    monkeypatch.setattr(state_inspect,"read_at",
                        lambda fd,name:canonical(context.marker))
    monkeypatch.setattr(state_inspect,"inspect_live",lambda:context)
    snap=native._live_snapshot(context)
    scope=storage.installation_scope(
        registry,pinned_registry_public=original["registrar"])[1]
    issued=int(time.time())
    body={
        "schema":native.SCHEMA,
        "registry_sha256":op.digest(registry),
        "installation_scope_sha256":scope,
        "host_fingerprint_sha256":registry["host_fingerprint"],
        "legacy_host_uuid":"11111111-1111-4111-8111-111111111111",
        "legacy_state_uuid":context.marker["state_volume_id"],
        "aws_instance_id":"i-0123456789abcdef0",
        "aws_region":"us-east-1",
        "iid_document_sha256":"sha256:"+"a"*64,
        "backend":backend,"observation_sha256":op.digest(snap),
        "boot_id":Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "issued_at":issued,"expires_at":issued+60}
    signed={**body,"signature_ed25519":base64.b64encode(
        key.sign(native.DOMAIN+op.canonical(body))).decode("ascii")}
    files={native.REGISTRY:registry,native.OBSERVATION:signed}
    pins={native.REGISTRY_PIN:original["registrar"],
          native.OBSERVER_PIN:pub(key)}
    monkeypatch.setattr(native,"_safe_json",lambda path:files[path])
    monkeypatch.setattr(native,"_read_root",lambda path,**kw:pins[path])
    monkeypatch.setattr(native.os,"geteuid",lambda:0)
    return SimpleNamespace(registry=registry,context=context,fd=fd,
                           witness=signed,key=key,files=files,pins=pins)


@pytest.mark.parametrize("backend",("root-directory","mounted-volume"))
def test_fresh_protected_observer_rechecks_real_descriptor_backend(
        monkeypatch,backend):
    s=source(monkeypatch,backend)
    try:
        out=native.require_live_backend_bound_identity()
        assert out["backend"]==backend
        assert out["registry_sha256"]==op.digest(s.registry)
        assert out["native_observer_sha256"]==op.digest(s.witness)
        assert s.context.rechecks>=3
        assert "native_accepted" not in out
        assert "ssm_authorized" not in out
    finally:os.close(s.fd)


@pytest.mark.parametrize("attack",(
    "missing_observer","wrong_issuer","expired","wrong_boot",
    "changed_inode","changed_mount","changed_marker","changed_backend",
    "changed_registry","changed_state_uuid","native_accepted_flag",
    "unsigned","reader_denied","standalone","wrong_iid",
    "cross_identity","bad_observation_sha",
))
def test_static_mapping_substitution_or_live_backend_change_holds(monkeypatch,attack):
    s=source(monkeypatch)
    try:
        if attack=="missing_observer":
            s.pins[native.OBSERVER_PIN]=b""
        elif attack=="wrong_issuer":
            s.pins[native.OBSERVER_PIN]=pub(Ed25519PrivateKey.generate())
        elif attack=="expired":
            s.witness["expires_at"]=0
        elif attack=="wrong_boot":
            s.witness["boot_id"]="stale-boot"
        elif attack=="changed_inode":
            s.context.fd=os.open("/tmp",os.O_RDONLY|os.O_DIRECTORY)
        elif attack=="changed_mount":
            s.context.mount["device"]="0:1"
        elif attack=="changed_marker":
            s.context.marker["state_volume_id"]="foreign"
        elif attack=="changed_backend":
            s.context.bundle["bootstrap"]["state"]["storage_backend"]="mounted-volume"
        elif attack=="changed_registry":
            s.registry["host_id"]="f"*64
        elif attack=="changed_state_uuid":
            s.context.bundle["bootstrap"]["state"]["state_volume_id"]="foreign"
        elif attack=="native_accepted_flag":
            s.witness["native_accepted"]=True
        elif attack=="unsigned":
            s.witness.pop("signature_ed25519")
        elif attack=="reader_denied":
            def deny():
                raise StateError("not-installed","no host-install native backend")
            monkeypatch.setattr(state_inspect,"inspect_live",deny)
        elif attack=="standalone":
            s.context.bundle["bootstrap"]["registries"]=[]
            s.context.bundle["bootstrap"]["control_authority"]=None
        elif attack=="wrong_iid":
            s.witness["aws_instance_id"]="i-00000000000000000"
        elif attack=="cross_identity":
            s.witness["legacy_host_uuid"]="66666666-6666-4666-8666-666666666666"
        elif attack=="bad_observation_sha":
            s.witness["observation_sha256"]="sha256:"+"e"*64
        with pytest.raises(op.OperationDenied):
            native.require_live_backend_bound_identity()
    finally:
        os.close(s.fd)
        if attack=="changed_inode":os.close(s.context.fd)


def test_protected_observer_key_must_be_separate_from_registry_issuer(monkeypatch):
    s=source(monkeypatch)
    try:
        s.pins[native.OBSERVER_PIN]=s.pins[native.REGISTRY_PIN]
        with pytest.raises(op.OperationDenied):
            native.require_live_backend_bound_identity()
    finally:os.close(s.fd)
