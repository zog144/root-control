"""Bounded kernel mount-namespace observations for recorded application runtimes."""
from __future__ import annotations

import os
import re
import time
from pathlib import Path, PurePosixPath

from zog.box_control.boot import current_boot_id
from zog.box_control.errors import RuntimeOperationError
from zog.box_control.project import Project
from zog.box_control.runtime.reference import RuntimeReferenceStore

from .processes import _member, _read, _stat, _unit
from .systemd import BusctlSystemdBackend

SCHEMA = "zog-runtime-mount-observation-v1"
_MAX_PROGRAMS = 32
_MAX_PROCESSES = 64
_MAX_CGROUP_DIRECTORIES = 256
_MAX_MOUNTINFO_BYTES = 1024 * 1024
_MAX_MOUNTINFO_ENTRIES = 4096
_MAX_EXPECTED_MOUNTS = 128
_MAX_NAMESPACES = 8
_NAMESPACE = re.compile(r"mnt:\[[0-9]+\]")


class ChangedDuringRead(ValueError):
    pass


def _safe_destination(value):
    if not isinstance(value, str) or not value.startswith("/") or "\x00" in value:
        raise ValueError("invalid expected mount destination")
    path = PurePosixPath(value)
    if ".." in path.parts or len(value.encode("utf-8")) > 4096:
        raise ValueError("invalid expected mount destination")
    return value


def _expected_mounts(member):
    if member.mount_inventory is None:
        return None
    properties = dict(member.expected_properties)
    root = properties.get("RootDirectory")
    if not isinstance(root, str) or not root.startswith("/"):
        return None
    inventory = {
        item.get("destination"): item
        for item in member.mount_inventory.get("mounts", ())
        if isinstance(item, dict) and isinstance(item.get("destination"), str)
    }
    expected = []

    def add(source, destination, access, kind):
        destination = _safe_destination(destination)
        if not isinstance(source, str) or not source.startswith("/") or "\x00" in source:
            raise ValueError("invalid recorded mount source")
        if len(source.encode("utf-8")) > 8192:
            raise ValueError("recorded mount source is too long")
        if any(item["destination"] == destination for item in expected):
            raise ValueError("duplicate recorded mount destination")
        expected.append(
            dict(source=source, destination=destination,
                 expected_access=access, kind=kind)
        )

    add(root, "/", "read-only" if properties.get("ProtectSystem") == "strict" else "unknown",
        "runtime-root")
    for source, destination in properties.get("BindReadOnlyPaths", ()):
        item = inventory.get(destination, {})
        kind = item.get("kind")
        if not isinstance(kind, str):
            if destination.startswith("/applications/.store/"):
                kind = "application-software-artifact"
            elif destination.startswith("/applications/"):
                kind = "application-software-view"
            else:
                kind = "rootfs"
        add(str(source), str(destination), "read-only", kind)
    for source, destination in properties.get("BindPaths", ()):
        item = inventory.get(destination, {})
        kind = item.get("kind") if isinstance(item.get("kind"), str) else "application-data"
        add(str(source), str(destination), "read-write", kind)
    if len(expected) > _MAX_EXPECTED_MOUNTS:
        raise ValueError("recorded mount inventory exceeds supported bound")
    return expected


def _decode_mountinfo_field(raw):
    if not isinstance(raw, bytes) or len(raw) > 8192:
        raise ValueError("invalid mountinfo field")
    output = bytearray()
    index = 0
    while index < len(raw):
        value = raw[index]
        if value == 92:  # backslash
            if index + 3 >= len(raw):
                raise ValueError("malformed mountinfo escape")
            digits = raw[index + 1:index + 4]
            if any(byte < 48 or byte > 55 for byte in digits):
                raise ValueError("malformed mountinfo escape")
            output.append(int(digits.decode("ascii"), 8))
            index += 4
            continue
        if value in (0, 10, 13):
            raise ValueError("unsafe mountinfo field")
        output.append(value)
        index += 1
    try:
        text = output.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("mountinfo path is not UTF-8") from exc
    return _safe_destination(text)


def _parse_mountinfo(data, *, truncated=False):
    records = {}
    lines = data.splitlines()
    if truncated and data and not data.endswith(b"\n"):
        lines = lines[:-1]
    if len(lines) > _MAX_MOUNTINFO_ENTRIES:
        lines = lines[:_MAX_MOUNTINFO_ENTRIES]
        truncated = True
    for line in lines:
        fields = line.split(b" ")
        try:
            separator = fields.index(b"-")
        except ValueError as exc:
            raise ValueError("malformed mountinfo record") from exc
        if separator < 6 or len(fields) < separator + 4:
            raise ValueError("malformed mountinfo record")
        mount_point = _decode_mountinfo_field(fields[4])
        try:
            options = fields[5].decode("ascii").split(",")
        except UnicodeDecodeError as exc:
            raise ValueError("malformed mountinfo options") from exc
        if "ro" in options and "rw" not in options:
            access = "read-only"
        elif "rw" in options and "ro" not in options:
            access = "read-write"
        else:
            access = "unknown"
        records.setdefault(mount_point, []).append(access)
    return records, truncated


def _namespace(directory):
    try:
        value = os.readlink("ns/mnt", dir_fd=directory)
    except OSError as exc:
        raise ChangedDuringRead("mount namespace became unavailable") from exc
    if not _NAMESPACE.fullmatch(value):
        raise ValueError("invalid mount namespace identity")
    return value


def _identity(pid, group, proc_root):
    try:
        descriptor = os.open(
            proc_root / str(pid),
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
    except FileNotFoundError as exc:
        raise ChangedDuringRead("process disappeared during inspection") from exc
    try:
        stat, cut = _read(descriptor, "stat")
        if cut:
            raise ValueError("oversized process stat")
        _state, _parent, started = _stat(stat)
        membership, cut = _read(descriptor, "cgroup")
        if cut or not _member(membership, group):
            raise ChangedDuringRead("process cgroup membership changed")
        return dict(
            pid=int(pid),
            start_time_ticks=started,
            mount_namespace=_namespace(descriptor),
        )
    finally:
        os.close(descriptor)


def _cgroup_pids(group, deadline, *, cgroup_root=Path("/sys/fs/cgroup")):
    if (
        not isinstance(group, str)
        or not group.startswith("/")
        or group == "/"
        or any(part in (".", "..") for part in group.split("/"))
    ):
        raise ValueError("invalid service cgroup")
    root = cgroup_root.resolve()
    target = cgroup_root / group.lstrip("/")
    if not target.resolve().is_relative_to(root):
        raise ValueError("cgroup escapes hierarchy")
    stack = [target]
    pids = set()
    visited = 0
    truncated = False
    while stack:
        if time.monotonic() >= deadline or visited >= _MAX_CGROUP_DIRECTORIES:
            truncated = True
            break
        directory = stack.pop()
        visited += 1
        try:
            with (directory / "cgroup.procs").open(encoding="ascii") as stream:
                for line in stream:
                    if time.monotonic() >= deadline:
                        truncated = True
                        break
                    try:
                        pid = int(line)
                    except ValueError as exc:
                        raise ValueError("malformed cgroup process identity") from exc
                    if pid <= 0:
                        raise ValueError("malformed cgroup process identity")
                    pids.add(pid)
                    if len(pids) > _MAX_PROCESSES:
                        truncated = True
                        pids = set(sorted(pids)[:_MAX_PROCESSES])
                        break
            if truncated:
                break
            with os.scandir(directory) as entries:
                for entry in entries:
                    if entry.is_dir(follow_symlinks=False):
                        stack.append(Path(entry.path))
                        if len(stack) + visited >= _MAX_CGROUP_DIRECTORIES:
                            truncated = True
                            break
        except FileNotFoundError as exc:
            raise ChangedDuringRead("service cgroup changed during inspection") from exc
    return tuple(sorted(pids)), truncated


def _target_stat(directory, destination):
    relative = "root" if destination == "/" else "root/" + destination.lstrip("/")
    try:
        return os.stat(relative, dir_fd=directory, follow_symlinks=True)
    except (FileNotFoundError, PermissionError, OSError):
        return None


def _source_stat(path):
    try:
        return os.stat(path, follow_symlinks=True)
    except (FileNotFoundError, PermissionError, OSError):
        return None


def _compare_expected(expected, records, directory, *, truncated):
    mounts = []
    integrity_fault = False
    inconclusive = False
    for item in expected:
        destination = item["destination"]
        matches = records.get(destination, ())
        if len(matches) > 1:
            presence = "inconsistent"
            access = "unknown"
            backing = "inconclusive"
            inconclusive = True
            integrity_fault = True
        elif len(matches) == 1:
            presence = "present"
            access = matches[0]
            source_stat = _source_stat(item["source"])
            target_stat = _target_stat(directory, destination)
            if source_stat is None or target_stat is None:
                backing = "inconclusive"
                inconclusive = True
            elif (
                source_stat.st_dev == target_stat.st_dev
                and source_stat.st_ino == target_stat.st_ino
            ):
                backing = "verified"
            else:
                backing = "mismatch"
                integrity_fault = True
            if (
                item["expected_access"] in {"read-only", "read-write"}
                and access != item["expected_access"]
            ):
                integrity_fault = True
        else:
            presence = "unknown" if truncated else "missing"
            access = "unknown"
            backing = "inconclusive"
            inconclusive = True
            if not truncated:
                integrity_fault = True
        mounts.append(
            {
                "destination": destination,
                "kind": item["kind"],
                "expected_access": item["expected_access"],
                "observed_presence": presence,
                "observed_access": access,
                "backing_identity": backing,
            }
        )
    return mounts, integrity_fault, inconclusive


def _observe_namespace(identity, group, expected, deadline, *, proc_root=Path("/proc")):
    pid = identity["pid"]
    try:
        directory = os.open(
            proc_root / str(pid),
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
    except FileNotFoundError as exc:
        raise ChangedDuringRead("process disappeared during inspection") from exc
    try:
        before_stat, cut = _read(directory, "stat")
        if cut:
            raise ValueError("oversized process stat")
        _state, _parent, started = _stat(before_stat)
        membership, cut = _read(directory, "cgroup")
        if (
            cut
            or started != identity["start_time_ticks"]
            or not _member(membership, group)
            or _namespace(directory) != identity["mount_namespace"]
        ):
            raise ChangedDuringRead("process identity changed before mount read")
        data, truncated = _read(directory, "mountinfo", _MAX_MOUNTINFO_BYTES)
        if time.monotonic() >= deadline:
            raise TimeoutError("mount observation deadline exceeded")
        records, truncated = _parse_mountinfo(data, truncated=truncated)
        mounts, integrity_fault, inconclusive = _compare_expected(
            expected, records, directory, truncated=truncated
        )
        after_stat, cut = _read(directory, "stat")
        after_membership, group_cut = _read(directory, "cgroup")
        if (
            cut
            or group_cut
            or _stat(after_stat)[2] != started
            or not _member(after_membership, group)
            or _namespace(directory) != identity["mount_namespace"]
        ):
            raise ChangedDuringRead("process identity changed during mount read")
        return dict(
            mount_namespace=identity["mount_namespace"],
            representative_process={
                "pid": pid,
                "start_time_ticks": started,
            },
            mounts=mounts,
            truncated=bool(truncated),
            integrity_fault=integrity_fault,
            inconclusive=inconclusive,
        )
    finally:
        os.close(directory)


def _program_result(reference, member, project, deadline, *, proc_root=Path("/proc"),
                    cgroup_root=Path("/sys/fs/cgroup"), backend=None):
    result = {
        "program": member.program,
        "unit_name": member.unit_name,
        "recorded_invocation_id": member.invocation_id,
        "status": "unavailable",
        "mount_namespace": None,
        "mount_namespaces": [],
        "multiple_mount_namespaces": False,
        "mounts": [],
        "truncated": False,
    }
    try:
        expected = _expected_mounts(member)
    except (TypeError, ValueError, KeyError, IndexError):
        return {**result, "status": "integrity-fault"}
    if expected is None:
        return {**result, "status": "legacy-unrecorded"}
    if not reference.boot_id or not member.invocation_id or not member.unit_name:
        return {**result, "status": "identity-unavailable"}
    try:
        if reference.boot_id != current_boot_id():
            return {**result, "status": "previous-boot"}
    except RuntimeOperationError:
        return {**result, "status": "unavailable"}
    backend = backend or BusctlSystemdBackend()
    backend.deadline = deadline
    try:
        before = _unit(backend, project, member.unit_name)
        if before is None:
            return {**result, "status": "absent"}
        if before[0] != member.invocation_id:
            return {**result, "status": "integrity-fault"}
        group = before[1]
        if not group:
            return {**result, "status": "identity-unavailable"}
        pids, process_truncated = _cgroup_pids(
            group, deadline, cgroup_root=cgroup_root
        )
        if not pids:
            return {**result, "status": "absent", "truncated": process_truncated}
        identities = [
            _identity(pid, group, proc_root)
            for pid in pids
        ]
        namespaces = {}
        for identity in identities:
            namespaces.setdefault(identity["mount_namespace"], []).append(identity)
        observations = []
        integrity_fault = False
        inconclusive = False
        namespace_truncated = process_truncated
        selected_namespaces = sorted(namespaces)
        if len(selected_namespaces) > _MAX_NAMESPACES:
            selected_namespaces = selected_namespaces[:_MAX_NAMESPACES]
            namespace_truncated = True
        for namespace in selected_namespaces:
            representative = sorted(
                namespaces[namespace], key=lambda item: item["pid"]
            )[0]
            observed = _observe_namespace(
                representative, group, expected, deadline, proc_root=proc_root
            )
            observed["processes"] = [
                {
                    "pid": item["pid"],
                    "start_time_ticks": item["start_time_ticks"],
                }
                for item in sorted(
                    namespaces[namespace], key=lambda item: item["pid"]
                )
            ]
            observations.append(observed)
            integrity_fault = integrity_fault or observed.pop("integrity_fault")
            inconclusive = inconclusive or observed.pop("inconclusive")
            namespace_truncated = namespace_truncated or observed["truncated"]
        # Recheck every process identity; never silently replace a representative.
        for identity in identities:
            if _identity(identity["pid"], group, proc_root) != identity:
                raise ChangedDuringRead("process identity changed during observation")
        after_pids, after_truncated = _cgroup_pids(
            group, deadline, cgroup_root=cgroup_root
        )
        if not process_truncated and not after_truncated and after_pids != pids:
            raise ChangedDuringRead("service process membership changed during observation")
        namespace_truncated = namespace_truncated or after_truncated
        after = _unit(backend, project, member.unit_name)
        if after != before:
            raise ChangedDuringRead("systemd unit identity changed during observation")
        if len(observations) == 1:
            result["mount_namespace"] = observations[0]["mount_namespace"]
            result["mounts"] = observations[0]["mounts"]
        result["mount_namespaces"] = observations
        result["multiple_mount_namespaces"] = len(observations) > 1
        result["truncated"] = bool(namespace_truncated)
        if integrity_fault:
            result["status"] = "integrity-fault"
        elif namespace_truncated or inconclusive:
            result["status"] = "partial"
        else:
            result["status"] = "observed"
        return result
    except ChangedDuringRead:
        return {**result, "status": "changed-during-read"}
    except TimeoutError:
        return {**result, "status": "partial", "truncated": True}
    except (OSError, ValueError, RuntimeError):
        return {**result, "status": "unavailable"}


def _aggregate_status(programs):
    statuses = [item["status"] for item in programs]
    if not statuses:
        return "legacy-unrecorded"
    if "integrity-fault" in statuses:
        return "integrity-fault"
    if "changed-during-read" in statuses:
        return "changed-during-read"
    if all(status == "observed" for status in statuses):
        return "observed"
    if len(set(statuses)) == 1:
        return statuses[0]
    return "partial"


def inspect_runtime_mounts(
    *, project_root, runtime_id,
    _proc_root=Path("/proc"), _cgroup_root=Path("/sys/fs/cgroup"),
    _backend=None,
):
    """Inspect only a persisted runtime identity; accepts no caller PID or unit.

    Underscore-prefixed dependency arguments are test seams only and are never
    accepted by the root-control wire protocol.
    """
    project = Project(Path(project_root))
    references = RuntimeReferenceStore(project.runtime_reference_file).load()
    reference = references.get(runtime_id)
    if reference is None:
        raise ValueError("unknown or pruned runtime identity")
    observed_at = time.time()
    result = {
        "schema": SCHEMA,
        "runtime_id": runtime_id,
        "basis": "kernel-mount-namespace",
        "snapshot": "non-atomic",
        "observed_at": observed_at,
        "recorded_boot_id": reference.boot_id,
        "status": "unavailable",
        "programs": [],
        "truncated": False,
    }
    if len(reference.programs) > _MAX_PROGRAMS:
        members = reference.programs[:_MAX_PROGRAMS]
        result["truncated"] = True
    else:
        members = reference.programs
    deadline = time.monotonic() + 5.0
    backend = _backend or BusctlSystemdBackend()
    backend.deadline = deadline
    programs = []
    for member in members:
        if time.monotonic() >= deadline:
            programs.append(
                {
                    "program": member.program,
                    "unit_name": member.unit_name,
                    "recorded_invocation_id": member.invocation_id,
                    "status": "partial",
                    "mount_namespace": None,
                    "mount_namespaces": [],
                    "multiple_mount_namespaces": False,
                    "mounts": [],
                    "truncated": True,
                }
            )
            result["truncated"] = True
            continue
        item = _program_result(
            reference, member, project, deadline,
            proc_root=_proc_root, cgroup_root=_cgroup_root, backend=backend,
        )
        result["truncated"] = result["truncated"] or item["truncated"]
        programs.append(item)
    result["programs"] = programs
    result["status"] = _aggregate_status(programs)
    if result["truncated"] and result["status"] == "observed":
        result["status"] = "partial"
    return result
