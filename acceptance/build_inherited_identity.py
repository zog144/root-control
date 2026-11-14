"""Opt-in native systemd identity probe for the finite-build execution model.

Run only on an explicitly authorized disposable systemd Host. Unlike source
property tests, this reads the actual *running child* credentials from /proc.
This is a diagnostic transient unit, not a compiler submission or a replacement
for an end-to-end RootDirectory build-job acceptance.
"""
import argparse
import asyncio
import json
import os
from pathlib import Path
import sys
import uuid

from dbus_next import BusType, Message, MessageType, Variant
from dbus_next.aio import MessageBus

SYSTEMD = "org.freedesktop.systemd1"
MANAGER = "/org/freedesktop/systemd1"
MANAGER_IFACE = "org.freedesktop.systemd1.Manager"
UNIT_IFACE = "org.freedesktop.systemd1.Unit"
SERVICE_IFACE = "org.freedesktop.systemd1.Service"


def kernel_identity(pid):
    if type(pid) is not int or pid <= 1:
        raise ValueError("expected existing process PID greater than 1")
    status = (Path("/proc") / str(pid) / "status").read_text()
    values = {}
    for line in status.splitlines():
        if line.startswith(("Uid:", "Gid:")):
            key, numbers = line.split(":", 1)
            parts = [int(p) for p in numbers.split()]
            if len(parts) != 4:
                raise RuntimeError("kernel credential format changed")
            values[key.lower()] = {
                "real": parts[0], "effective": parts[1], "saved": parts[2], "filesystem": parts[3],
            }
    if set(values) != {"uid", "gid"}:
        raise RuntimeError("kernel process credentials unavailable")
    return values


async def probe(controller_pid):
    # A new unit is deliberately unique: no existing compiler or Zog unit is
    # targeted, replaced or modified.
    name = "zog-build-identity-probe-" + uuid.uuid4().hex + ".service"
    command = [sys.executable, "-I", "-c", "import time; time.sleep(20)"]
    properties = [
        ["Description", Variant("s", "Zog diagnostic finite-build identity probe")],
        ["Type", Variant("s", "exec")],
        ["ExitType", Variant("s", "cgroup")],
        ["Restart", Variant("s", "no")],
        ["KillMode", Variant("s", "control-group")],
        ["AddRef", Variant("b", True)],
        ["NoNewPrivileges", Variant("b", True)],
        ["CapabilityBoundingSet", Variant("t", 0)],
        ["PrivateNetwork", Variant("b", True)],
        ["TasksMax", Variant("t", 32)],
        ["MemoryMax", Variant("t", 128 * 1024 * 1024)],
        ["RuntimeMaxUSec", Variant("t", 22 * 1000000)],
        ["StandardOutput", Variant("s", "null")],
        ["StandardError", Variant("s", "null")],
        ["ExecStartEx", Variant("a(sasas)", [[command[0], command, ["no-env-expand"]]])],
    ]
    assert not {"User", "Group"} & {key for key, _ in properties}
    parent_before = kernel_identity(controller_pid)
    bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
    started = False
    cleanup_errors = []

    async def call(path, iface, member, signature, body):
        reply = await asyncio.wait_for(bus.call(Message(
            destination=SYSTEMD, path=path, interface=iface,
            member=member, signature=signature, body=body,
        )), timeout=10)
        if reply.message_type == MessageType.ERROR:
            raise RuntimeError(f"{member}: {reply.error_name}")
        return reply.body

    async def manager(method, signature, body):
        return await call(MANAGER, MANAGER_IFACE, method, signature, body)

    async def property_value(path, iface, key):
        raw = await call(path, "org.freedesktop.DBus.Properties", "Get",
                         "ss", [iface, key])
        return raw[0].value

    try:
        # The real system manager (rather than a mocked Backend) performs the
        # fork/exec and controls the default Unix identity.
        await manager("StartTransientUnit", "ssa(sv)a(sa(sv))",
                      [name, "fail", properties, []])
        started = True
        path = (await manager("GetUnit", "s", [name]))[0]
        deadline = asyncio.get_running_loop().time() + 10
        pid = 0
        while pid <= 1:
            pid = await property_value(path, SERVICE_IFACE, "MainPID")
            if asyncio.get_running_loop().time() > deadline:
                raise RuntimeError("diagnostic systemd child never became active")
            if pid <= 1:
                await asyncio.sleep(.05)
        child = kernel_identity(pid)
        parent_after = kernel_identity(controller_pid)
        if parent_before != parent_after:
            raise RuntimeError("controller process identity changed during inspection")
        # Verify kernel-reported effective and filesystem credentials. This
        # includes root (0), without an admission filter or identity switch.
        matches = all(
            child[k]["effective"] == parent_before[k]["effective"]
            and child[k]["filesystem"] == parent_before[k]["filesystem"]
            for k in ("uid", "gid")
        )
        result = {
            "schema": "root-control-real-child-identity-v1",
            "diagnostic_only": True,
            "unit": name,
            "controller_pid": controller_pid,
            "child_pid": pid,
            "controller_identity": parent_before,
            "child_identity": child,
            "systemd_user": await property_value(path, SERVICE_IFACE, "User"),
            "systemd_group": await property_value(path, SERVICE_IFACE, "Group"),
            "user_group_override_submitted": False,
            "credentials_match": matches,
            "uid_zero_case": parent_before["uid"]["effective"] == 0,
        }
        if not matches:
            raise RuntimeError("systemd child credentials do not match running controller")
        return result
    finally:
        if started:
            for method, signature, body in (
                ("StopUnit", "ss", [name, "replace"]),
                ("ResetFailedUnit", "s", [name]),
                ("UnrefUnit", "s", [name]),
            ):
                try:
                    await manager(method, signature, body)
                except Exception as exc:
                    cleanup_errors.append(f"{method}: {exc}")
        bus.disconnect()
        if cleanup_errors:
            raise RuntimeError("diagnostic unit cleanup failed: " + "; ".join(cleanup_errors))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--disposable-host", action="store_true", required=True)
    parser.add_argument("--controller-pid", type=int, required=True,
                        help="Actual installed root-control service MainPID, not a configured user ID")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not Path("/run/systemd/system").is_dir():
        parser.error("requires the native systemd system manager")
    # Do NOT impose a nonroot-only (or root-only) identity admission rule.
    result = asyncio.run(probe(args.controller_pid))
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"credentials_match": result["credentials_match"],
                      "uid_zero_case": result["uid_zero_case"],
                      "child_pid": result["child_pid"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
