"""Protected Task C IPC admission for selected graphical original operations.

This adapter intentionally speaks the *new* gateway's 2026-11-04 original
GitHub identity protocol, not the retired seqpacket owner protocol. It does
NOT enable native SSM. Independent installed operator-signed original mapping
is required before the owner can consider either stage or preflight.

A root peer and an unsigned matching nonce are NOT send authority or proof of
preflight readiness. Positive IPC responses require a separately reviewed
signed native observation protocol; the gateway's current v1 client does not
accept that and therefore must continue to fail closed.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import socket
import struct

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import graphical_operation_owner_source as owner

IPC_SCHEMA = "zog-graphical-owner-ipc-v1"
MAPPING_SCHEMA = "zog-graphical-task-c-original-operation-mapping-v1"
MAPPING_DOMAIN = b"zog-graphical-task-c-original-operation-mapping-v1\0"
FRAME_MAX = 8192
ORIGINAL_KEYS = frozenset((
    "request_id", "original_request_sha256", "origin_repository",
    "origin_issue_number", "origin_trigger_actor", "operation_id",
    "stage", "ordinal", "binding_sha256", "remote_request_sha256"))
FRAME_KEYS = ORIGINAL_KEYS | {"schema", "action", "nonce"}
ASCII_ACTOR = re.compile(r"[A-Za-z0-9-]{1,100}\Z")
# Read-only observation uses the same original bound identity, never a fresh claim.
TASK_C_ACTIONS = frozenset(("preflight-original", "submit-original", "observe-original"))


def deny():
    owner.deny()


def preflight_id(request_id, original_stage_operation_id):
    if (not owner.match(request_id, owner.H32) or
            not owner.match(original_stage_operation_id, owner.H32)):
        deny()
    return hashlib.sha256(
        ("zog-graphical-original-preflight-v1:" + request_id + ":" +
         original_stage_operation_id).encode("ascii")).hexdigest()[:32]


def canonical(row):
    return owner.canonical(row)


def _unique(pairs):
    row = {}
    for key, value in pairs:
        if key in row:
            deny()
        row[key] = value
    return row


def parse_frame(raw):
    """Strict one-frame canonical JSON-lines, no trailing command or FD."""
    if (type(raw) is not bytes or not 2 <= len(raw) <= FRAME_MAX or
            not raw.endswith(b"\n") or raw.count(b"\n") != 1):
        deny()
    try:
        frame = json.loads(raw[:-1], object_pairs_hook=_unique,
                           parse_constant=lambda _: deny())
        if (type(frame) is not dict or set(frame) != FRAME_KEYS or
                canonical(frame) != raw[:-1]):
            deny()
    except (ValueError, TypeError, UnicodeError, OverflowError):
        deny()
    if (frame["schema"] != IPC_SCHEMA or
            frame["action"] not in TASK_C_ACTIONS or
            not owner.match(frame["nonce"], owner.NONCE) or
            any(not owner.match(frame[key], owner.H32) for key in
                ("request_id", "operation_id")) or
            any(not owner.match(frame[key], owner.H64) for key in (
                "original_request_sha256", "binding_sha256",
                "remote_request_sha256")) or
            frame["origin_repository"] != "zog144/host-deploy" or
            type(frame["origin_issue_number"]) is not int or
            not 1 <= frame["origin_issue_number"] <= 2147483647 or
            not owner.match(frame["origin_trigger_actor"], ASCII_ACTOR) or
            frame["stage"] not in owner.STAGES or
            type(frame["ordinal"]) is not int or
            not 0 <= frame["ordinal"] < 64):
        deny()
    return frame


def original(frame):
    return {key: frame[key] for key in ORIGINAL_KEYS}


def _mapping_body(row):
    if (type(row) is not dict or
            set(row) != {"schema", "original", "stage_operation_id",
                         "owner_request_sha256", "approval_sha256",
                         "signature_ed25519"} or
            row["schema"] != MAPPING_SCHEMA or
            type(row["original"]) is not dict or
            set(row["original"]) != ORIGINAL_KEYS or
            not owner.match(row["stage_operation_id"], owner.H32) or
            not owner.match(row["owner_request_sha256"], owner.SHA) or
            not owner.match(row["approval_sha256"], owner.SHA)):
        deny()
    row_frame = {"schema": IPC_SCHEMA, "nonce": "0" * 48,
                 "action": ("submit-original" if
                            row["original"]["operation_id"] ==
                            row["stage_operation_id"] else
                            "preflight-original"),
                 **row["original"]}
    parse_frame(canonical(row_frame) + b"\n")
    if (row_frame["action"] == "preflight-original" and
            row["original"]["operation_id"] != preflight_id(
                row["original"]["request_id"], row["stage_operation_id"])):
        deny()
    return {key: value for key, value in row.items()
            if key != "signature_ed25519"}


class ProtectedOriginalRegistry:
    """Installer-frozen mapping, independently signed by operator key.

    Installed mapping must also be independently tied to the *actual* GitHub
    authorization and current Host/installation/STATE, not just a valid
    standalone operator signature. Never accept registry data over the socket.
    """
    def __init__(self, installed_records, *, pinned_operator_public_key):
        if (type(installed_records) is not dict or not installed_records or
                type(pinned_operator_public_key) is not bytes or
                len(pinned_operator_public_key) != 32):
            deny()
        self.entries = {}
        self.key = pinned_operator_public_key
        for op, entry in installed_records.items():
            if (not owner.match(op, owner.H32) or
                    type(entry) is not dict or
                    set(entry) != {"mapping", "owner_request",
                                   "original_operator_approval"}):
                deny()
            mapping = entry["mapping"]
            body = _mapping_body(mapping)
            req = owner.validate_request(entry["owner_request"])
            approval = entry["original_operator_approval"]
            if (mapping["original"]["operation_id"] != op or
                    req["operation_id"] != op or
                    req["request_id"] != mapping["original"]["request_id"] or
                    req["stage"] != mapping["original"]["stage"] or
                    req["ordinal"] != mapping["original"]["ordinal"] or
                    owner.digest(req) != mapping["owner_request_sha256"] or
                    owner.digest(approval) != mapping["approval_sha256"]):
                deny()
            try:
                sig = base64.b64decode(mapping["signature_ed25519"],
                                       validate=True)
                if len(sig) != 64:
                    deny()
                Ed25519PublicKey.from_public_bytes(self.key).verify(
                    sig, MAPPING_DOMAIN + canonical(body))
            except (ValueError, TypeError, InvalidSignature):
                deny()
            self.entries[op] = {
                "original": dict(mapping["original"]),
                "owner_request": req,
                "approval": json.loads(canonical(approval)),
                "stage_operation_id": mapping["stage_operation_id"],
            }

    def select(self, frame):
        if (type(frame) is not dict or set(frame) != FRAME_KEYS):
            deny()
        item = self.entries.get(frame["operation_id"])
        if item is None or item["original"] != original(frame):
            deny()
        stage_id = item["stage_operation_id"]
        if (frame["action"] in ("preflight-original", "observe-original") and
                stage_id != frame["operation_id"]):
            if (preflight_id(frame["request_id"], stage_id) !=
                    frame["operation_id"] or stage_id not in self.entries):
                deny()
            stage = self.entries[stage_id]
            # Verify distinct original preflight and stage IDs match one
            # immutable GitHub origin/remote/binding; never reuse a stage
            # claim as a preflight claim.
            comparable = ORIGINAL_KEYS - {"operation_id"}
            if (any(item["original"][k] != stage["original"][k]
                    for k in comparable) or
                    stage_id == frame["operation_id"]):
                deny()
        elif (frame["action"] == "preflight-original" or
              (frame["action"] == "submit-original" and stage_id != frame["operation_id"])):
            deny()
        return item


def read_stream_frame(connection):
    if (connection.family != socket.AF_UNIX or
            (connection.type & 0xf) != socket.SOCK_STREAM):
        deny()
    buf = bytearray()
    while len(buf) <= FRAME_MAX:
        data = connection.recv(min(4096, FRAME_MAX + 1 - len(buf)))
        if not data:
            break
        buf.extend(data)
        if b"\n" in data:
            break
    return parse_frame(bytes(buf))


def verify_peer(connection, *, gateway_uid, gateway_gid):
    if (connection.family != socket.AF_UNIX or
            (connection.type & 0xf) != socket.SOCK_STREAM):
        deny()
    try:
        pid, uid, gid = struct.unpack(
            "3i", connection.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
    except (OSError, struct.error):
        deny()
    if (pid <= 0 or type(gateway_uid) is not int or
            type(gateway_gid) is not int or
            uid != gateway_uid or gid != gateway_gid):
        deny()
    # Exact executable/source, PID-starttime, cgroup, invocation and boot
    # still require a native installed peer witness, not SO_PEERCRED alone.
    return pid


def inspect_one(connection, *, registry, gateway_uid, gateway_gid):
    """Source-only preadmission: NO mutation or positive send acknowledgement."""
    verify_peer(connection, gateway_uid=gateway_uid, gateway_gid=gateway_gid)
    frame = read_stream_frame(connection)
    item = registry.select(frame)
    # Return data only to source callers. Never claim authenticated preflight
    # or send on this path without separate monotonic native send admission.
    return {
        "operation_id": frame["operation_id"],
        "action": frame["action"],
        "selected_request_sha256": owner.digest(item["owner_request"]),
        "status": "selected-source-only-native-held",
        "native_ssm_sent": False,
    }
