"""Read-only, separately attributable X11 and RFB Workspace observations.

Never returns X11 cookies, socket paths, RFB bytes, cgroups, UIDs or capabilities.
A probe is evidence only for the selected desktop/runtime/boot/incarnation, not
an authority to launch or to supply a browser access grant. No state writes.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import struct
import time

from zog.box_control.boot import current_boot_id
from zog.box_control.runtime.reference import RuntimeReferenceStore
from zog.box_control.model import ApplicationRuntimeState

from .workspace import host_namespace_stat, peer_cgroups, peer_namespace_stat

SCHEMA = "zog-workspace-stage-readiness-v1"
MAX_MECHANISM = 8192
TIMEOUT = 1.0


class _Untrusted(Exception):
    pass


def _bounded_file(path, limit=MAX_MECHANISM):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size < 1 or info.st_size > limit:
            raise _Untrusted()
        value = os.read(fd, limit + 1)
        if len(value) != info.st_size:
            raise _Untrusted()
        return value
    finally:
        os.close(fd)


def _endpoint_info(path):
    info = path.lstat()
    if not stat.S_ISSOCK(info.st_mode):
        raise _Untrusted()
    return (info.st_dev, info.st_ino)


def _context(backend, project_root, binding):
    if type(binding) is not dict or binding.get("role") != "client":
        raise _Untrusted()
    project, base = backend.location(project_root, binding)
    if binding.get("boot_id") != current_boot_id():
        raise _Untrusted()
    mechanism = _bounded_file(base / "mechanism.json")
    raw = json.loads(mechanism)
    if (type(raw) is not dict or type(raw.get("resolved")) is not dict
            or type(raw.get("binding")) is not dict
            or raw["binding"].get("workspace_id") != binding.get("workspace_id")
            or raw["binding"].get("incarnation") != binding.get("incarnation")
            or raw["binding"].get("boot_id") != binding.get("boot_id")
            or any(binding.get(k) != v for k, v in raw["resolved"].items())
            or type(raw.get("uid")) is not int
            or type(raw.get("cookie_hex")) is not str
            or type(raw.get("authority_hex")) is not str):
        raise _Untrusted()
    cookie = bytes.fromhex(raw["cookie_hex"])
    authority = bytes.fromhex(raw["authority_hex"])
    if len(cookie) != 16 or not authority or len(authority) > 4096:
        raise _Untrusted()
    namespace = host_namespace_stat()
    if ((namespace.st_dev, namespace.st_ino) !=
            (binding.get("namespace_device"), binding.get("namespace_inode"))):
        raise _Untrusted()
    runtime_base = Path(raw["resolved"]["access_directory"]).parent
    if (runtime_base.resolve() != runtime_base.absolute()
            or any(not d.is_dir() or d.is_symlink() for d in
                   (runtime_base, runtime_base / "run", runtime_base / "x11"))):
        raise _Untrusted()
    auth_path = runtime_base / "run" / "Xauthority"
    if _bounded_file(auth_path, 4096) != authority:
        raise _Untrusted()
    refs = RuntimeReferenceStore(project.runtime_reference_file).load()
    selected = refs.get(binding.get("desktop_runtime_id"))
    if (selected is None or selected.state != ApplicationRuntimeState.RUNNING
            or selected.boot_id != binding["boot_id"]
            or not selected.programs
            or any((selected.workspace_binding or {}).get(k) != binding.get(k)
                   for k in ("workspace_id", "incarnation", "boot_id"))):
        raise _Untrusted()
    groups = []
    for member in selected.programs:
        unit = backend.systemd.observe(project_root=project.path, unit_name=member.unit_name)
        if (not unit.get("exists") or unit.get("active_state") != "active"
                or unit.get("invocation_id") != member.invocation_id
                or not unit.get("control_group")):
            raise _Untrusted()
        groups.append(unit["control_group"])
    x11 = runtime_base / "x11" / ("X" + str(binding["number"]))
    rfb = runtime_base / "run" / "vnc.sock"
    # The source paths are controller-owned; neither is returned to the caller.
    endpoints = (_endpoint_info(x11), _endpoint_info(rfb))
    return (project, mechanism, authority, cookie, raw["uid"], namespace,
            tuple(groups), x11, rfb, endpoints, selected)


def _probe(path, *, uid, namespace, groups, x11, cookie):
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(TIMEOUT)
            client.connect(str(path))
            pid, peer_uid, _ = struct.unpack(
                "3i", client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            observed_cgroups = peer_cgroups(pid)
            net = peer_namespace_stat(pid)
            if (peer_uid != uid or
                    (net.st_dev, net.st_ino) != (namespace.st_dev, namespace.st_ino)
                    or not any(line.startswith("0::") and any(
                        group and (line[3:] == group or
                                   line[3:].startswith(group + "/"))
                        for group in groups) for line in observed_cgroups)):
                return {"status": "failed", "code": "endpoint-identity"}
            if x11:
                name = b"MIT-MAGIC-COOKIE-1"
                client.sendall(struct.pack("<BBHHHHH", ord("l"), 0, 11, 0,
                            len(name), len(cookie), 0) + name +
                            b"\0" * (-len(name) % 4) + cookie)
                response = b""
                while len(response) < 8:
                    fragment = client.recv(8 - len(response))
                    if not fragment:
                        break
                    response += fragment
                if len(response) != 8 or response[0] != 1:
                    return {"status": "failed", "code": "x11-rejected"}
            else:
                banner = b""
                while len(banner) < 12:
                    fragment = client.recv(12 - len(banner))
                    if not fragment:
                        break
                    banner += fragment
                if (len(banner) != 12 or banner[:4] != b"RFB " or
                        banner[7:8] != b"." or banner[11:12] != b"\n" or
                        not banner[4:7].isdigit() or not banner[8:11].isdigit()):
                    return {"status": "failed", "code": "rfb-invalid"}
            return {"status": "confirmed", "code": "ok"}
    except (OSError, ValueError, struct.error):
        return {"status": "unknown", "code": "probe-unavailable"}


def inspect(backend, *, project_root, binding):
    """Bounded read-only inspection. A changed snapshot cancels BOTH stages."""
    observed_at = time.time()
    base = dict(schema=SCHEMA, workspace_id=binding.get("workspace_id"),
                desktop_runtime_id=binding.get("desktop_runtime_id"),
                boot_id=binding.get("boot_id"), incarnation=binding.get("incarnation"),
                observed_at=observed_at, endpoint_identity=None)
    missing = {"status": "unknown", "code": "binding-unavailable"}
    try:
        initial = _context(backend, project_root, binding)
        project, mechanism, authority, cookie, uid, ns, groups, x11, rfb, endpoints, selected = initial
        result_x11 = _probe(x11, uid=uid, namespace=ns, groups=groups, x11=True, cookie=cookie)
        result_rfb = _probe(rfb, uid=uid, namespace=ns, groups=groups, x11=False, cookie=cookie)
        # Re-evaluate all authority and runtime evidence after both live probes.
        final = _context(backend, project_root, binding)
        if (final[1] != mechanism or final[2] != authority or
                final[9] != endpoints or final[10] != selected or
                current_boot_id() != binding["boot_id"]):
            raise _Untrusted()
        opaque = hashlib.sha256(json.dumps({
            "workspace_id": binding["workspace_id"],
            "desktop_runtime_id": binding["desktop_runtime_id"],
            "boot_id": binding["boot_id"],
            "incarnation": binding["incarnation"],
            "endpoints": endpoints,
        }, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        return dict(base, endpoint_identity=opaque,
                    x11=result_x11, rfb=result_rfb)
    except Exception:
        return dict(base, x11=dict(missing), rfb=dict(missing))
