"""Review root-control's disabled cross-owner archive IPC handoff.

No import of root-control runtime or service; exact source pinned host-install
companion is examined as AST, never run as an authorized receiver.
"""
from __future__ import annotations
import ast
import json
from pathlib import Path
import pytest

ROOT=Path(__file__).resolve().parents[1]
CONTRACT=ROOT/"project/archive-provider-ipc-source-handoff-v1.json"
HOST=ROOT/"companions/host-install/src/zog/host_install/archive_provider_ipc_contract.py"
EXPECTED_HEAD="59a2e99c877c2687a01e69cd026d0966a2631afd"
EXPECTED_HOST_IDENTIFY="59dbc181f54c6ac29ee5eb1f83b6f322fb73c037"
EXPECTED_ARCHIVE="9df811cf9315efec4312e6a16738a23149d286a2"

def verify(candidate):
    if type(candidate) is not dict or set(candidate)!={
        "schema","status","host_install_source_head","host_identify_source_head",
        "archive_mirror_source_head","consumer","purpose","transport","socket_path",
        "root_sender_uid","archive_app_uid","archive_app_gid","required_peer_auth",
        "transfer","steps","revocation","ambiguous_outcome","source_consumer_adapter",
        "authentic_native_witness","native_accepted","activation_allowed",
        "issuer_cloudflare_reuse_allowed"}:
        raise ValueError("invalid IPC source handoff")
    expected={"schema":"zog-root-control-archive-provider-ipc-source-handoff-v1",
        "status":"DISABLED_SOURCE_REVIEW_ONLY",
        "host_install_source_head":EXPECTED_HEAD,
        "host_identify_source_head":EXPECTED_HOST_IDENTIFY,
        "archive_mirror_source_head":EXPECTED_ARCHIVE,
        "consumer":"archive-mirror","purpose":"archive-mirror-upstream-fetch",
        "transport":"AF_UNIX_SOCK_STREAM",
        "socket_path":"/run/zog/archive-provider-credential.sock",
        "root_sender_uid":0,"archive_app_uid":None,"archive_app_gid":None,
        "ambiguous_outcome":"INSPECT_ONLY_NEVER_REDELIVER",
        "source_consumer_adapter":"NOT_AUTHORED",
        "authentic_native_witness":None,"native_accepted":False,
        "activation_allowed":False,"issuer_cloudflare_reuse_allowed":False}
    if any(candidate[k]!=v for k,v in expected.items()):
        raise ValueError("premature archive receiver authority or source pin")
    for key, required in {
        "required_peer_auth":{"SO_PEERCRED","selected-installed-UID","selected-installed-GID",
                              "exact-mounted-STATE","selected-root-control-byte-revision"},
        "transfer":{"one-SCM_RIGHTS","anonymous-memfd","F_SEAL_WRITE","F_SEAL_GROW",
                    "F_SEAL_SHRINK","F_SEAL_SEAL","no-secret-in-metadata"},
        "steps":{"signed-approved-request-and-nonce-durable","verified-delivery-durable",
                 "installing-fence-durable","exact-once-app-FD-transfer",
                 "application-installed-byte-witness","secret-free-ack-durable"},
        "revocation":{"common-deny-durable-first","signed-purpose-bound-application-revocation",
                      "application-tombstone-witness-before-ack",
                      "never-delete-catalogue-or-pins"},
    }.items():
        if type(candidate[key]) is not list or set(candidate[key])!=required or len(candidate[key])!=len(required):
            raise ValueError("missing native IPC ownership or ordering gate: "+key)
    return "DISABLED_SOURCE_HANDOFF_ONLY"

def test_source_contract_only():
    assert verify(json.loads(CONTRACT.read_text()))=="DISABLED_SOURCE_HANDOFF_ONLY"

@pytest.mark.parametrize("key,substitute",[
    ("native_accepted",True),("activation_allowed",True),
    ("issuer_cloudflare_reuse_allowed",True),
    ("archive_app_uid",1000),("archive_app_gid",1000),
    ("root_sender_uid",1000),("purpose","issuer-cloudflare-dns01"),
    ("consumer","certify-manage"),("source_consumer_adapter","installed"),
    ("authentic_native_witness",{"result":"PASS"}),
    ("ambiguous_outcome","REDELIVER"),
    ("host_install_source_head","a"*40),
])
def test_unauthorized_promotion_rejected(key,substitute):
    value=json.loads(CONTRACT.read_text())
    value[key]=substitute
    with pytest.raises(ValueError):
        verify(value)

def test_source_companion_not_production_selected():
    parsed=ast.parse(HOST.read_text())
    constants={}
    funcs=set()
    for item in parsed.body:
        if isinstance(item,(ast.FunctionDef,ast.AsyncFunctionDef)):
            funcs.add(item.name)
        if isinstance(item,ast.Assign) and len(item.targets)==1 and isinstance(item.targets[0],ast.Name):
            if isinstance(item.value,ast.Constant):
                constants[item.targets[0].id]=item.value.value
    assert constants["SCHEMA"]=="zog-archive-provider-protected-ipc-v1"
    assert constants["PURPOSE"]=="archive-mirror-upstream-fetch"
    assert constants["CONSUMER"]=="archive-mirror"
    assert constants["LIVE_ACTIVATION"] is False
    assert {"validate_policy","peer_credentials","verify_secret_fd",
            "receive_single_fd","validate_application_ack"} <= funcs
