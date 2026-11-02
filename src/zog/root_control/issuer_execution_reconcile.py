"""Root-only selected issuer PID1 cancellation/reboot reconciliation.

This is not a new untrusted RPC. All unit identities come from the saved
controller operation and from the durable epoch ledger, never caller input.
An uncertain launch with no bound InvocationID remains blocked rather than
stopping an unrelated service. Terminal status requires independent PID1 unit
absence after bounded StopUnit/UnrefUnit plus a trusted cleanup witness.
"""
from __future__ import annotations

from .issuer_execution_fence import IssuerFenceDenied, current_boot_id, installed_fence

PROGRAMS = frozenset({"renew", "inspect", "stage"})


def _deny():
    raise IssuerFenceDenied("issuer execution reconciliation unavailable") from None


def _authoritative_unit(project_root, request_id):
    from zog.box_control.operations import OperationStore
    from zog.box_control.project import Project
    project = Project(project_root)
    matches = [entry for entry in OperationStore(project).records()
               if entry.get("request_id") == request_id
               and entry.get("operation") == "launch"
               and entry.get("application", {}).get("name") == "certify-manage"]
    if len(matches) != 1:
        _deny()
    record = matches[0]
    program = record.get("selected_program")
    runtime = record.get("new_runtime_id")
    units = record.get("attempted_units")
    snapshot = record["application"]
    if (program not in PROGRAMS
            or type(runtime) is not str
            or not 1 <= len(runtime) <= 40
            or not runtime.replace("-", "").isalnum()
            or type(units) is not list or len(units) != 1
            or type(units[0]) is not str
            or not units[0].endswith(".service")
            or len(snapshot.get("programs", ())) != 1
            or snapshot["programs"][0].get("name") != program):
        _deny()
    return units[0], runtime, program


def reconcile_selected_issuer(backend, *, project_root, request_id,
                              trusted_cleanup_witness):
    """Reconcile one original operation under protected root epoch lock.

    Witness must be the root controller's independently trusted mount/FD,
    cgroup and cleanup observer, NOT a caller callback passed through RPC.
    A missing or stale unit never authorizes cleanup merely by its absence.
    """
    if (type(request_id) is not str or not 1 <= len(request_id) <= 40
            or not request_id.replace("-", "").isalnum()
            or not callable(trusted_cleanup_witness)):
        _deny()
    unit, runtime, program = _authoritative_unit(project_root, request_id)
    backend._validate_unit(project_root, unit)
    with installed_fence(for_revocation=True) as (fence, committed):
        fence.reboot(new_boot_id=current_boot_id())
        def stop_and_verify(*, request_id, original_boot_id,
                            runtime_id, invocation_id, epoch):
            # An uncertain launch can race a later PID1 admission. No
            # InvocationID -> no authority to kill or report terminal.
            if (runtime_id != runtime or type(invocation_id) is not str
                    or len(invocation_id) != 32
                    or any(c not in "0123456789abcdef" for c in invocation_id)):
                return False
            before = backend.observe(project_root=project_root, unit_name=unit)
            if before.get("exists") is True:
                if (before.get("unit_name") != unit
                        or before.get("transient") is not True
                        or before.get("invocation_id") != invocation_id):
                    return False  # never terminate a substituted unit
                backend.stop(project_root=project_root, unit_name=unit)
                # Release only our already-observed transient unit.
                backend.release(project_root=project_root, unit_name=unit)
            elif before.get("exists") is not False:
                return False
            after = backend.observe(project_root=project_root, unit_name=unit)
            if after.get("exists") is not False:
                return False  # stop request alone is NOT completed cleanup
            return trusted_cleanup_witness(
                project_root=project_root, request_id=request_id,
                runtime_id=runtime, unit_name=unit,
                invocation_id=invocation_id, original_boot_id=original_boot_id,
                epoch=epoch) is True
        # reconcile durably records cancel-pending before invoking stop and
        # leaves it on exceptions, uncertain PID1 observations, or failed
        # independently authenticated cleanup.
        return fence.reconcile(request_id=request_id,
                               verify_stopped_and_clean=stop_and_verify,
                               expected_program=program)
