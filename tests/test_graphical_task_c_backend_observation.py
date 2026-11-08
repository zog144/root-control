"""Synthetic protected-native observer tests; signed mapping alone never admits.

A fake retained descriptor stands in for host-install's separately tested live
inspector. Production has no way to supply this from an RPC or a JSON flag.
"""
import base64
import copy
import os
import stat
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from zog.root_control import graphical_task_c_backend_observation as native
from zog.root_control import graphical_operation_owner_source as op
from zog.host_install import graphical_registry_identity_mapping_v2 as v2
from zog.host_install import state_inspect
from zog.host_install.state_contract import canonical, StateError
from test_graphical_registry_identity_mapping_v2 import source


def pub(key):
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


class Context:
    def __init__(self, fd, backend):
        st = os.fstat(fd)
        device = f"{os.major(st.st_dev)}:{os.minor(st.st_dev)}"
        self.fd=fd
        self.marker={
            "schema":2 if backend=="root-directory" else 1,
            "state_volume_id":"33333333-3333-4333-8333-333333333333",
            "filesystem_uuid":"44444444-4444-4444-8444-444444444444",
            "partition_partuuid":"55555555-5555-4555-8555-555555555555",
        }
        self.bundle={
            "bootstrap":{
                "registries":[{"registry_id":"selected-control","role":"control"}],
                "control_authority":{"registry_id":"selected-control"},
                "state":{
                "storage_backend":backend,
                "filesystem_uuid":self.marker["filesystem_uuid"],
                "partition_partuuid":self.marker["partition_partuuid"],
            },"installation_id":"22222222-2222-4222-8222-222222222222"},
            "installation":{"installation_id":"22222222-2222-4222-8222-222222222222"},
            "marker":self.marker,
        }
        self.mount={
            "id":"19" if backend=="root-directory" else "20",
            "device":device,
            "backend":"root-directory" if backend=="root-directory" else None,
            "target":"/" if backend=="root-directory" else "/state",
            "state_path":"/state" if backend=="root-directory" else None,
        }
        self.rechecks=0
    def recheck(self):
        self.rechecks+=1
    def __enter__(self):return self
    def __exit__(self,*_):return False


def selected(monkeypatch,tmp_path,backend="root-directory"):
    # Use a root-owned real descriptor for the synthetic source harness.
    # The test never claims this is a selected native /state observation.
    fd=os.open("/",os.O_RDONLY|os.O_DIRECTORY)
    context=Context(fd,backend)
    args,_,registrar_secret=source(backend)
    observer_secret=Ed25519PrivateKey.generate()
    now=int(time.time())
    boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    attest={
        "host_uuid":args["legacy"]["host_uuid"],
        "aws_instance_id":"i-0123456789abcdef0",
        "aws_region":"us-east-1",
        "volume_id": "vol-0123456789abcdef0" if backend=="mounted-volume" else None,
    }
    monkeypatch.setattr(state_inspect,"read_at",
                        lambda fd,name:canonical(context.marker))
    monkeypatch.setattr(state_inspect,"inspect_live",lambda:context)
    _, observation=native._context_observation(context,attest)
    args["observation"]=observation
    body=v2.prepare_unsigned(**args)["body"]
    mapping={**body,
        "signature_ed25519":base64.b64encode(
            registrar_secret.sign(v2.DOMAIN+canonical(body))).decode()}
    receipt={
        "schema":native.SCHEMA,
        "mapping_sha256":op.digest(mapping),
        "observation_sha256":op.digest(observation),
        "backend":backend,
        **attest,
        "boot_id":boot_id,
        "issued_at":now,
        "expires_at":now+60,
    }
    witness={**receipt,"signature_ed25519":base64.b64encode(
        observer_secret.sign(native.DOMAIN+op.canonical(receipt))).decode()}
    files={
        native.REGISTRY:args["registered_installation"],
        native.MAPPING:mapping,native.LEGACY:args["legacy"],
        native.OBSERVATION:witness,
    }
    pins={
        native.REGISTRY_PIN:args["pinned_registry_public"],
        native.REGISTRAR_PIN:args["pinned_registrar_public"],
        native.OBSERVATION_PIN:pub(observer_secret),
    }
    monkeypatch.setattr(native,"_safe_json",lambda path, size=8192:files[path])
    monkeypatch.setattr(native,"_read_root",lambda path,**kw:pins[path])
    monkeypatch.setattr(native.os,"geteuid",lambda:0)
    return SimpleNamespace(files=files,pins=pins,context=context,fd=fd,
                           observer=observer_secret,registrar=registrar_secret,
                           receipt=receipt,backend=backend,args=args)


@pytest.mark.parametrize("backend",("root-directory","mounted-volume"))
def test_protected_live_backend_v2_requires_real_descriptor_recheck(
        monkeypatch,tmp_path,backend):
    s=selected(monkeypatch,tmp_path,backend)
    try:
        result=native.require_live_backend_bound_identity()
        assert result["backend"]==backend
        assert result["mapping_sha256"]==op.digest(s.files[native.MAPPING])
        assert s.context.rechecks>=3
        assert not any(k in result for k in (
            "native_accepted","ssm_authorized","broker_admission"))
    finally:
        os.close(s.fd)


@pytest.mark.parametrize("attack",(
    "mapping_swap","expired","wrong_boot","changed_inode",
    "changed_mount","changed_marker","changed_backend","wrong_issuer",
    "missing_pin","changed_registry","signed_false_native_flag",
    "reader_unavailable","changed_witness_signature",
    "standalone_registry_free",
))
def test_static_signed_mapping_and_false_native_status_cannot_authorize(
        monkeypatch,tmp_path,attack):
    s=selected(monkeypatch,tmp_path)
    try:
        if attack=="mapping_swap":
            s.files[native.MAPPING]["state_marker_sha256"]="sha256:"+"f"*64
        elif attack=="expired":
            s.files[native.OBSERVATION]["expires_at"]=0
        elif attack=="wrong_boot":
            s.files[native.OBSERVATION]["boot_id"]="other-boot"
        elif attack=="changed_inode":
            s.context.fd=os.open(tmp_path,os.O_RDONLY|os.O_DIRECTORY)
        elif attack=="changed_mount":
            s.context.mount["id"]="777"
        elif attack=="changed_marker":
            s.context.marker["state_volume_id"]="foreign"
        elif attack=="changed_backend":
            s.context.bundle["bootstrap"]["state"]["storage_backend"]="mounted-volume"
        elif attack=="wrong_issuer":
            s.pins[native.OBSERVATION_PIN]=pub(Ed25519PrivateKey.generate())
        elif attack=="missing_pin":
            s.pins[native.OBSERVATION_PIN]=b""
        elif attack=="changed_registry":
            s.files[native.REGISTRY]["host_id"]="f"*64
        elif attack=="signed_false_native_flag":
            s.files[native.MAPPING]["native_accepted"]=True
        elif attack=="reader_unavailable":
            def unavailable():
                raise StateError("native-hold","no selected STATE backend")
            monkeypatch.setattr(state_inspect,"inspect_live",unavailable)
        elif attack=="changed_witness_signature":
            s.files[native.OBSERVATION]["signature_ed25519"]=base64.b64encode(b"0"*64).decode()
        elif attack=="standalone_registry_free":
            s.context.bundle["bootstrap"]["registries"]=[]
            s.context.bundle["bootstrap"]["control_authority"]=None
        with pytest.raises(op.OperationDenied):
            native.require_live_backend_bound_identity()
    finally:
        os.close(s.fd)
        if attack=="changed_inode":
            os.close(s.context.fd)


def test_unenrolled_native_observer_cannot_be_replaced_by_mapping(monkeypatch,tmp_path):
    s=selected(monkeypatch,tmp_path)
    try:
        s.pins[native.OBSERVATION_PIN]=s.pins[native.REGISTRAR_PIN]
        with pytest.raises(op.OperationDenied):
            native.require_live_backend_bound_identity()
    finally:
        os.close(s.fd)
