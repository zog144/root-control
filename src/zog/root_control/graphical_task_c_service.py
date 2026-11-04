"""Disabled native Task C owner service selector (source-only).

This executable intentionally does not accept a live graphical send until an
independent monotonic CAS/authority issuer, installed peer process binding,
signed observation protocol and separate SSM principal have native acceptance.
It is the only prospective Task C *stream* service; the older seqpacket owner
is a separate held draft and is NOT a second installable sender.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import socket
import stat
import sys
import time

from . import graphical_operation_owner_source as owner
from . import graphical_task_c_owner as taskc
from .graphical_owner_service import _read_root

SOCKET = "/run/zog/graphical-operation-owner.sock"
CONFIG = Path("/etc/zog/graphical-owner/task-c-originals.json")
INSTALL_SCHEMA = "zog-protected-task-c-original-operations-installation-v1"
# Nonrollbackable highwater and effective AWS IAM denial cannot be asserted
# from a caller-supplied config or root-protected local JSON. A separate,
# independently reviewed native provider must implement admission first.
NATIVE_TASK_C_SEND_ADMISSION_IMPLEMENTED = False


def denied():
    owner.deny()


def selected_original_registry():
    """Inspect root-installed, owner-signed exact Task C mapping, no send."""
    if os.geteuid() != 0:
        denied()
    config = json.loads(_read_root(CONFIG, max_bytes=32768),
                        object_pairs_hook=taskc._unique,
                        parse_constant=lambda _:denied())
    if (type(config) is not dict or
            set(config) != {"schema", "boot_id", "host_id",
                            "installation_id", "state_volume_id",
                            "gateway_uid", "gateway_gid", "operator_key_b64",
                            "originals"} or
            config["schema"] != INSTALL_SCHEMA or
            any(not owner.match(config[k], owner.H64)
                for k in ("host_id", "installation_id", "state_volume_id")) or
            type(config["boot_id"]) is not str or
            config["boot_id"] != Path(
                "/proc/sys/kernel/random/boot_id").read_text().strip() or
            type(config["gateway_uid"]) is not int or
            config["gateway_uid"] < 1000 or
            type(config["gateway_gid"]) is not int or
            config["gateway_gid"] <= 0):
        denied()
    try:
        pub = base64.b64decode(config["operator_key_b64"], validate=True)
        if len(pub) != 32:
            denied()
    except (ValueError, TypeError):
        denied()
    registry = taskc.ProtectedOriginalRegistry(
        config["originals"], pinned_operator_public_key=pub)
    for entry in registry.entries.values():
        request = entry["owner_request"]
        if (request["host_id"] != config["host_id"] or
                request["installation_id"] != config["installation_id"] or
                request["state_volume_id"] != config["state_volume_id"]):
            denied()
    return registry, config["gateway_uid"], config["gateway_gid"]


def _socket_from_systemd():
    if (os.environ.get("LISTEN_PID") != str(os.getpid()) or
            os.environ.get("LISTEN_FDS") != "1"):
        denied()
    sock = socket.fromfd(3, socket.AF_UNIX, socket.SOCK_STREAM)
    if (sock.getsockname() != SOCKET or
            (sock.type & 0xf) != socket.SOCK_STREAM or
            sock.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1):
        denied()
    st = os.lstat(SOCKET)
    if (not stat.S_ISSOCK(st.st_mode) or st.st_uid != 0 or
            stat.S_IMODE(st.st_mode) != 0o660):
        denied()
    return sock


def serve_selected_connection(connection, executor, policy, *, now):
    """Strict native stream entry; source tests use disposable socketpairs.

    The caller must have independently installed the exact executor and policy.
    Nothing in the incoming frame can choose signer, target or AWS credentials.
    """
    from .graphical_task_c_native import installed_peer
    pid = taskc.verify_peer(
        connection, gateway_uid=policy["gateway_uid"],
        gateway_gid=policy["gateway_gid"])
    installed_peer(pid, policy)
    frame = taskc.read_stream_frame(connection)
    result = executor.handle(frame, now=now)
    wire = taskc.canonical(result) + b"\n"
    if len(wire) > taskc.FRAME_MAX:
        denied()
    connection.sendall(wire)
    return result


def main():
    if len(sys.argv) != 1 or os.geteuid() != 0:
        denied()
    if not NATIVE_TASK_C_SEND_ADMISSION_IMPLEMENTED:
        # No native service is activated merely by installing these bytes;
        # no test fixture or signed status can flip the send gate.
        denied()
    # The native constructor selects externally pinned S3 genesis/history,
    # distinct owner-only checkpoint/SSM role sessions, original approvals,
    # and fixed send/readback. No caller can select these through IPC.
    from .graphical_task_c_native import installed_runtime
    executor, policy = installed_runtime()
    sock = _socket_from_systemd()
    while True:
        connection, _ = sock.accept()
        with connection:
            connection.settimeout(5)
            try:
                serve_selected_connection(
                    connection, executor, policy, now=int(time.time()))
            except (OSError, ValueError, owner.OperationDenied):
                # Denials never imply original operation acceptance.
                try:
                    connection.sendall(b'{"error":"owner-denied"}\n')
                except OSError:
                    pass


if __name__ == "__main__":
    main()
