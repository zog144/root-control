"""Exact graphical gateway -> root owner IPC source admission (not a daemon).

This module parses the frozen Task C frame, consults an independently supplied
protected original mapping and enforces SO_PEERCRED. It cannot send SSM or
create a socket, service, signer or stored approval. A native service must
install and authenticate these inputs, then use the one-way ledger.
"""
from __future__ import annotations
import hashlib
import json
import os
import re
import socket
import struct
from . import graphical_operation_owner_source as owner

SCHEMA="zog-graphical-owner-ipc-v1"
FIELDS={"schema","action","request_id","operation_id","original_request_sha256",
        "origin_repository","origin_issue_number","origin_trigger_actor",
        "stage","ordinal","binding_sha256","remote_request_sha256","nonce"}
HEX32=re.compile(r"[0-9a-f]{32}\Z")
HEX64=re.compile(r"[0-9a-f]{64}\Z")
NONCE=re.compile(r"[0-9a-f]{48}\Z")
ACTOR=re.compile(r"[A-Za-z0-9-]{1,100}\Z")
MAX_FRAME=8192

def deny():
    owner.deny()

def parse(raw):
    if type(raw) is not bytes or len(raw)>MAX_FRAME or not raw or b"\n" in raw:
        deny()
    def unique(pairs):
        result={}
        for k,v in pairs:
            if k in result:deny()
            result[k]=v
        return result
    try:
        message=json.loads(raw,object_pairs_hook=unique,
                           parse_constant=lambda _:deny())
    except (ValueError,TypeError,UnicodeError,OverflowError):
        deny()
    if type(message) is not dict or set(message)!=FIELDS or owner.canonical(message)!=raw:
        deny()
    if (message["schema"]!=SCHEMA
            or message["action"] not in ("submit-original","preflight-original")
            or message["origin_repository"]!="zog144/host-deploy"
            or type(message["origin_issue_number"]) is not int
            or not 1<=message["origin_issue_number"]<2**31
            or type(message["origin_trigger_actor"]) is not str
            or not ACTOR.fullmatch(message["origin_trigger_actor"])
            or message["stage"] not in ("capabilities","snapshot","submit","inspect")
            or type(message["ordinal"]) is not int
            or not 0<=message["ordinal"]<64):
        deny()
    for key,pattern in (("request_id",HEX32),("operation_id",HEX32),
                        ("original_request_sha256",HEX64),
                        ("binding_sha256",HEX64),("remote_request_sha256",HEX64),
                        ("nonce",NONCE)):
        if type(message[key]) is not str or not pattern.fullmatch(message[key]):
            deny()
    return message

def authenticated_peer(sock, *, installed_gateway_uid, installed_gateway_gid):
    if (sock.family!=socket.AF_UNIX or (sock.type & 0xf)!=socket.SOCK_STREAM
            or type(installed_gateway_uid) is not int or installed_gateway_uid<=0
            or type(installed_gateway_gid) is not int or installed_gateway_gid<=0):
        deny()
    try:
        pid,uid,gid=struct.unpack("3i",sock.getsockopt(socket.SOL_SOCKET,
                               socket.SO_PEERCRED,struct.calcsize("3i")))
    except (OSError,ValueError,struct.error):
        deny()
    if pid<=0 or (uid,gid)!=(installed_gateway_uid,installed_gateway_gid):deny()
    return (pid,uid,gid)

def original_identity(frame):
    """Only the original frozen GitHub source, not an authorization grant."""
    return {k:frame[k] for k in ("request_id","original_request_sha256",
        "origin_repository","origin_issue_number","origin_trigger_actor",
        "operation_id","stage","ordinal","binding_sha256",
        "remote_request_sha256","action")}

def selected_original_operation(frame, *, protected_original_map,
                                protected_owner_request):
    """The protected installation preselects *both* preflight and stage sends."""
    request=owner.validate_request(protected_owner_request)
    if type(protected_original_map) is not dict or set(protected_original_map)!={
            "schema","selected","approved_request_sha256","selected_original","host_installation_state_sha256"}:
        deny()
    if protected_original_map["schema"]!="zog-graphical-owner-original-github-map-v1":
        deny()
    if protected_original_map["selected"] is not True:deny()
    if protected_original_map["selected_original"]!=original_identity(frame):deny()
    if protected_original_map["approved_request_sha256"]!=owner.digest(request):deny()
    if (type(protected_original_map["host_installation_state_sha256"]) is not str
            or not owner.SHA.fullmatch(protected_original_map["host_installation_state_sha256"])):
        deny()
    # Both IDs are separately preapproved in the independent owner ledger;
    # never accept the gateway's locally derived preflight ID as sufficient.
    if (frame["operation_id"]!=request["operation_id"]
            or frame["request_id"]!=request["request_id"]
            or frame["stage"]!=request["stage"]
            or frame["ordinal"]!=request["ordinal"]
            or frame["remote_request_sha256"]!=request["remote_request_sha256"][7:]):
        deny()
    return request

def admit_source_only(raw, sock, *, installed_gateway_uid, installed_gateway_gid,
                      protected_original_map, protected_owner_request):
    """No send and no positive preflight; caller must not use as a send ticket."""
    frame=parse(raw)
    authenticated_peer(sock,installed_gateway_uid=installed_gateway_uid,
                       installed_gateway_gid=installed_gateway_gid)
    selected_original_operation(frame,protected_original_map=protected_original_map,
                                protected_owner_request=protected_owner_request)
    return {"status":"ORIGINAL_IPC_SOURCE_MATCH_ONLY",
            "ssm_send_authorized":False,"native_preflight_authenticated":False,
            "nonce":frame["nonce"]}
