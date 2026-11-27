"""Exact current box-control wire compatibility at the root-control boundary."""
import copy
import os
import socket
from pathlib import Path
from threading import Thread, BoundedSemaphore

import pytest

from zog.box_control.build_protocol import INHERITED_EXECUTION_CONTRACT
from zog.box_control.runtime.root_control import RootControlSystemdTransport
from zog.root_control.daemon import BUILD_RPC_CONTRACT, RootControlDaemon
from zog.root_control.protocol import decode
from zog.box_control.errors import RuntimeOperationError
from zog.root_control.build import BuildBackend
from .test_build_backend import Systemd


RID = "b" * 32
JID = "c" * 32
PROJECT = "/project"
REG = dict(resource_id=RID, prepared_root=PROJECT+"/root",
           source_directory=PROJECT+"/source", output_directory=PROJECT+"/output",
           input_manifest_id="manifest")
JOB = dict(build_root_id=RID, source_workspace_id=RID+"-source",
           output_workspace_id=RID+"-output", command=["cc","$PATH"],
           environment={"PATH":"/bin"}, working_directory="/image-build/source",
           startup_timeout_seconds=5, execution_timeout_seconds=8,
           termination_grace_seconds=2,
           resource_limits={"thread-count-maximum":32,"memory-maximum-bytes":10000000},
           read_only_root=True, network_access=False)
CASES = [
    ("register", REG), ("prepare", dict(job_id=JID,request=JOB)),
    ("start", dict(job_id=JID,request=JOB)),
    ("observe", dict(job_id=JID,build_root_id=RID)),
    ("cleanup", dict(job_id=JID,build_root_id=RID)),
    ("cancel", dict(job_id=JID,build_root_id=RID,expected_invocation_id=None)),
    ("release", dict(build_root_id=RID)), ("forget", dict(build_root_id=RID)),
]


class StrictBackend:
    """Record real method names without requiring a privileged filesystem."""
    def __init__(self):
        self.calls = []

    def __getattr__(self, name):
        def call(**kwargs):
            self.calls.append((name, kwargs))
            assert "build_contract" not in kwargs and "operation" not in kwargs
            return {"called":name}
        return call


@pytest.mark.parametrize("peer", [(0,0),(1001,1002)])
@pytest.mark.parametrize("operation,arguments", CASES)
def test_exact_current_client_envelope_and_identity(tmp_path, monkeypatch,
                                                    peer, operation, arguments):
    daemon=RootControlDaemon(tmp_path/"unused.sock")
    daemon.build=StrictBackend()
    transport=RootControlSystemdTransport()
    original=copy.deepcopy(arguments)
    def request(name, **fields):
        assert name == "build_"+operation
        assert fields["build_contract"] == INHERITED_EXECUTION_CONTRACT == BUILD_RPC_CONTRACT
        return daemon.handle(dict(operation=name,**fields),peer=peer)["result"]
    monkeypatch.setattr(transport,"_request",request)
    assert transport.build_call(operation,project_root=PROJECT,**arguments)=={"called":operation}
    assert daemon.build.calls == [(operation,dict(project_root=PROJECT,_peer=peer,**original))]
    assert arguments == original


@pytest.mark.parametrize("operation,arguments", CASES)
@pytest.mark.parametrize("peer", [(0,0),(1001,1002)])
def test_bad_envelopes_never_reach_backend(tmp_path,operation,arguments,peer):
    daemon=RootControlDaemon(tmp_path/"unused.sock")
    daemon.build=StrictBackend()
    valid=dict(operation="build_"+operation,project_root=PROJECT,
               build_contract=BUILD_RPC_CONTRACT,**arguments)
    bad=[{k:v for k,v in valid.items() if k!="build_contract"},
         dict(valid,build_contract="zog-build-inherited-peer-v1"),
         dict(valid,build_contract=None), dict(valid,build_contract=True),
         dict(valid,build_contract=[BUILD_RPC_CONTRACT]),
         dict(valid,unknown_field="x"), dict(valid,project_root="relative"),
         dict(valid,project_root="/invalid"+chr(0)+"path")]
    bad.extend(dict(valid,**{k:0}) for k in
               ("uid","gid","_peer","peer","peer_identity","execution_user_id",
                "execution_group_id","User","Group"))
    bad.extend({k:v for k,v in valid.items() if k!=field} for field in arguments)
    for invalid in bad:
        with pytest.raises(ValueError):
            daemon.handle(invalid,peer=peer)
    assert daemon.build.calls == []


def test_status_shape_unchanged(tmp_path,monkeypatch):
    daemon=RootControlDaemon(tmp_path/"unused.sock")
    daemon.build=StrictBackend()
    transport=RootControlSystemdTransport()
    monkeypatch.setattr(transport,"_request",lambda op,**kw:
                        daemon.handle(dict(operation=op,**kw))["result"])
    assert transport.build_registration_status(project_root=PROJECT,resource_id=RID)=={
        "called":"registration_status"}
    assert daemon.build.calls==[("registration_status",dict(project_root=PROJECT,resource_id=RID))]
    with pytest.raises(ValueError):
        daemon.handle(dict(operation="build_registration_status",project_root=PROJECT,
                           resource_id=RID,build_contract=BUILD_RPC_CONTRACT))


def test_real_socket_client_registration_with_kernel_peer(tmp_path,monkeypatch):
    # Run under the existing unprivileged source runner AND its existing
    # 0:0 root CI lane. Actual socket, actual client bytes, real registration;
    # the finite-build systemd backend remains a test double.
    peer=(os.geteuid(),os.getegid())
    if peer != (0,0):
        monkeypatch.setattr(os,"chown",lambda *a,**kw:None)
    project=tmp_path/"project"
    attempt=project/"state/image-build/attempts/one"
    prepared=attempt/"root"
    (prepared/"bin").mkdir(parents=True)
    (prepared/"bin/cc").write_text("test compiler")
    (prepared/"bin/cc").chmod(0o755)
    source=attempt/"source"
    output=attempt/"output"
    source.mkdir(); output.mkdir()
    (source/"input").write_text("input")
    backend=BuildBackend(Systemd(),tmp_path/"privileged")
    backend.systemd.version=lambda:252
    path=tmp_path/"rpc.sock"
    daemon=RootControlDaemon(path)
    daemon.build=backend
    kwargs=dict(resource_id=RID,prepared_root=str(prepared),
                source_directory=str(source),output_directory=str(output),
                input_manifest_id="manifest")
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as server:
        server.bind(str(path)); server.listen(1); server.settimeout(10)
        def serve():
            for _ in range(7):
                conn,_=server.accept()
                kernel_peer=daemon._kernel_peer(conn)
                request=decode(conn)
                slot=BoundedSemaphore(1); slot.acquire()
                daemon._serve_request(conn,request,slot,peer=kernel_peer)
        thread=Thread(target=serve,daemon=True); thread.start()
        transport=RootControlSystemdTransport(path,timeout_seconds=10)
        assert transport.build_registration_status(project_root=project,resource_id=RID)=={
            "resource_id":RID,"state":"absent"}
        with pytest.raises(RuntimeOperationError,match="unsupported inherited build RPC contract"):
            transport._request("build_register",project_root=str(project),**kwargs)
        assert transport.build_registration_status(project_root=project,resource_id=RID)=={
            "resource_id":RID,"state":"absent"}
        result=transport.build_call("register",project_root=project,**kwargs)
        assert result["execution_identity"]==dict(uid=peer[0],gid=peer[1])
        assert "build_contract" not in result and "build_contract" not in result["intent"]
        assert transport.build_registration_status(project_root=project,resource_id=RID)==result
        job=copy.deepcopy(JOB)
        with pytest.raises(RuntimeOperationError,match="unsupported fields"):
            transport._request("build_prepare",project_root=str(project),
                build_contract=BUILD_RPC_CONTRACT,job_id=JID,request=dict(job,execution_user_id=0))
        assert transport.build_call("start",project_root=project,job_id=JID,request=job)["request"]==job
        thread.join(timeout=10)
        assert not thread.is_alive()
    props=backend.systemd.properties
    assert props["User"].value==str(peer[0]) and props["Group"].value==str(peer[1])
    assert props["PrivateNetwork"].value is True
    assert props["NoNewPrivileges"].value is True
    assert props["CapabilityBoundingSet"].value==0
    assert props["ExecStart"].value==[["/bin/cc",["/bin/cc","$$PATH"],False]]
