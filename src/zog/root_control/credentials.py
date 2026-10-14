"""Read-only kernel credential evidence for persisted application runtimes.

Never accept PIDs, units, or expected numeric IDs from callers. They are
derived from the durable runtime reference and rechecked against the systemd
transient invocation and cgroup on both sides of each /proc inspection.
"""
from __future__ import annotations

import os
import time
from pathlib import Path

from zog.box_control.boot import current_boot_id
from zog.box_control.errors import RuntimeOperationError
from zog.box_control.project import Project
from zog.box_control.runtime.reference import RuntimeReferenceStore

from .processes import (
    BusctlSystemdBackend, IdentityChanged, _member, _read, _scan, _stat, _unit,
)

SCHEMA = "zog-runtime-credential-observation-v1"
_MAX_PROGRAMS = 32
_MAX_PROCESSES = 64
_MAX_DURATION = 5.0


class ChangedDuringRead(Exception):
    pass


def _status_credentials(content):
    """Linux /proc/<pid>/status records 4 IDs: real/effective/saved/filesystem."""
    values = {}
    for line in content.splitlines():
        if line.startswith((b"Uid:", b"Gid:")):
            name, payload = line.split(b":", 1)
            items = payload.split()
            if name.decode() in values or len(items) != 4:
                raise ValueError("invalid process credential fields")
            numbers = tuple(int(item) for item in items)
            if any(i < 0 or i >= 2**32 for i in numbers):
                raise ValueError("invalid credential value")
            values[name.decode()] = numbers
        elif line.startswith(b"Groups:"):
            if "Groups" in values:
                raise ValueError("duplicate supplementary groups")
            members = tuple(int(i) for i in line.split(b":", 1)[1].split())
            if len(members) > 128 or any(i < 0 or i >= 2**32 for i in members):
                raise ValueError("unsupported supplementary group list")
            values["Groups"] = members
    if set(values) != {"Uid", "Gid", "Groups"}:
        raise ValueError("incomplete process credential fields")
    return values


def _credential(pid, started, group, proc_root):
    """Reject any PID reuse, cgroup escape or credential transition mid-read."""
    try:
        directory = os.open(
            proc_root / str(pid), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        )
    except (FileNotFoundError, ProcessLookupError) as exc:
        raise ChangedDuringRead("process disappeared") from exc
    try:
        stat_before, truncated = _read(directory, "stat")
        group_before, cgroup_truncated = _read(directory, "cgroup")
        if (truncated or cgroup_truncated or _stat(stat_before)[2] != started
                or not _member(group_before, group)):
            raise ChangedDuringRead("process identity changed before credential read")
        status_before, truncated = _read(directory, "status")
        if truncated:
            raise ValueError("oversized process status")
        credentials = _status_credentials(status_before)
        status_after, truncated = _read(directory, "status")
        stat_after, stat_truncated = _read(directory, "stat")
        group_after, group_truncated = _read(directory, "cgroup")
        if (truncated or stat_truncated or group_truncated
                or _stat(stat_after)[2] != started
                or not _member(group_after, group)
                or _status_credentials(status_after) != credentials):
            raise ChangedDuringRead("process identity or credentials changed during read")
        return {
            "pid": pid,
            "start_time_ticks": started,
            "uid": list(credentials["Uid"]),
            "gid": list(credentials["Gid"]),
            "supplementary_groups": sorted(set(credentials["Groups"])),
        }
    finally:
        os.close(directory)


def _bound_expected(reference, member, project):
    binding = reference.execution_binding
    if binding is None:
        return None
    if not isinstance(binding, dict):
        raise IdentityChanged("saved execution grant is malformed")
    uid, gid = binding.get("uid"), binding.get("gid")
    grant_id = binding.get("grant_id")
    if (binding.get("schema") != "zog-execution-identity-v1"
            or binding.get("project") != str(project.path)
            or binding.get("application") != reference.application
            or type(binding.get("version")) is not int
            or binding["version"] != 1
            or not isinstance(grant_id, str)
            or len(grant_id) != 32
            or any(c not in "0123456789abcdef" for c in grant_id)
            or type(uid) is not int or type(gid) is not int
            or not (1000 <= uid < 2**31 - 1 and 1000 <= gid < 2**31 - 1)):
        raise IdentityChanged("saved execution grant scope or IDs differ")
    effective = dict(member.expected_properties)
    if effective.get("User") != str(uid) or effective.get("Group") != str(gid):
        raise IdentityChanged("saved systemd user/group differ from the prepared grant")
    return {"grant_id": binding.get("grant_id"), "uid": uid, "gid": gid}


def _compare_credentials(entry, expected):
    if expected is None:
        return "unbound"
    uid, gid = expected["uid"], expected["gid"]
    if (any(value != uid for value in entry["uid"])
            or any(value != gid for value in entry["gid"])
            or any(group != gid for group in entry["supplementary_groups"])):
        return "mismatch"
    return "match"


def _program(reference, member, project, deadline, budget, *, backend, proc_root, cgroup_root):
    expected = _bound_expected(reference, member, project)
    result = dict(
        program=member.program, unit_name=member.unit_name,
        recorded_invocation_id=member.invocation_id,
        expected_execution_identity=expected,
        basis="kernel-proc-status",
        status="identity-unavailable",
        control_group=None, processes=[], truncated=False,
        skipped_processes=0,
    )
    if not member.invocation_id or not member.unit_name:
        return result
    before = _unit(backend, project, member.unit_name)
    if before is None:
        return {**result, "status": "absent"}
    if before[0] != member.invocation_id:
        return {**result, "status": "integrity-fault"}
    group = before[1]
    if not group:
        return result
    result["control_group"] = group
    snapshot = _scan(
        group, budget, deadline, cgroup_root=cgroup_root, proc_root=proc_root
    )
    rows = []
    skipped = snapshot["skipped_processes"]
    changed = False
    for process in snapshot["processes"]:
        if time.monotonic() >= deadline:
            changed = True
            break
        try:
            item = _credential(
                process["pid"], process["start_time_ticks"], group, proc_root
            )
            item["comparison"] = _compare_credentials(item, expected)
            rows.append(item)
        except (ChangedDuringRead, OSError, ValueError, KeyError, IndexError):
            skipped += 1
            changed = True
    after = _unit(backend, project, member.unit_name)
    if after != before:
        return {**result, "status": "changed-during-read"}
    result.update(processes=rows, skipped_processes=skipped,
                  truncated=bool(snapshot["truncated"] or changed))
    if any(item["comparison"] == "mismatch" for item in rows):
        result["status"] = "credential-mismatch"
    elif result["truncated"] or skipped:
        result["status"] = "partial"
    elif rows:
        result["status"] = "observed" if expected is not None else "legacy-unbound"
    else:
        result["status"] = "absent"
    return result


def inspect_runtime_credentials(
    *, project_root, runtime_id, limit=50,
    proc_root=Path("/proc"), cgroup_root=Path("/sys/fs/cgroup"),
    backend=None,
):
    if type(limit) is not int or not 1 <= limit <= _MAX_PROCESSES:
        raise ValueError("credential process limit must be 1 through 64")
    project = Project(Path(project_root))
    reference = RuntimeReferenceStore(project.runtime_reference_file).load().get(runtime_id)
    if reference is None:
        raise ValueError("unknown or pruned application runtime identity")
    result = dict(
        schema=SCHEMA, runtime_id=runtime_id,
        application=reference.application, observed_at=time.time(),
        snapshot="non-atomic", basis="kernel-proc-status",
        recorded_boot_id=reference.boot_id,
        recorded_execution_identity=reference.execution_binding,
        status="identity-unavailable", programs=[], truncated=False,
    )
    if not reference.boot_id:
        return result
    try:
        if reference.boot_id != current_boot_id():
            return {**result, "status": "previous-boot"}
    except RuntimeOperationError:
        return {**result, "status": "unavailable"}
    if not reference.programs:
        return result  # A no-program record is not evidence of an empty cgroup.
    if len(reference.programs) > _MAX_PROGRAMS:
        return {**result, "status": "partial", "truncated": True}
    backend = backend or BusctlSystemdBackend()
    deadline = time.monotonic() + _MAX_DURATION
    backend.deadline = deadline
    remaining = limit
    for member in reference.programs:
        if remaining <= 0 or time.monotonic() >= deadline:
            result["truncated"] = True
            break
        try:
            item = _program(
                reference, member, project, deadline, remaining,
                backend=backend, proc_root=proc_root, cgroup_root=cgroup_root,
            )
        except IdentityChanged:
            item = dict(program=member.program, unit_name=member.unit_name,
                        recorded_invocation_id=member.invocation_id,
                        status="integrity-fault", processes=[], truncated=False)
        except (OSError, ValueError, RuntimeError, RuntimeOperationError, TimeoutError):
            item = dict(program=member.program, unit_name=member.unit_name,
                        recorded_invocation_id=member.invocation_id,
                        status="unavailable", processes=[], truncated=False)
        result["programs"].append(item)
        remaining -= len(item.get("processes", ()))
        result["truncated"] |= item.get("truncated", False)
    statuses = {p["status"] for p in result["programs"]}
    if "integrity-fault" in statuses:
        result["status"] = "integrity-fault"
    elif "credential-mismatch" in statuses:
        result["status"] = "credential-mismatch"
    elif "changed-during-read" in statuses:
        result["status"] = "changed-during-read"
    elif result["truncated"] or "partial" in statuses or len(result["programs"]) < len(reference.programs):
        result["status"] = "partial"
    elif statuses == {"observed"}:
        result["status"] = "observed"
    elif statuses == {"legacy-unbound"}:
        result["status"] = "legacy-unbound"
    elif statuses == {"absent"}:
        result["status"] = "absent"
    else:
        result["status"] = "partial" if statuses else "absent"
    return result
