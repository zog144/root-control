# Build-only exact-Project root-control sidecar

**Date:** 2026-10-25  
**Owner:** root-control Regular / box-control controller-contract reviewer  
**Tracking:** [root-control #11](https://github.com/zog144/root-control/issues/11) · [host-deploy #5](https://github.com/zog144/host-deploy/issues/5) · [host-deploy draft PR #2](https://github.com/zog144/host-deploy/pull/2)  
**Source executable and regression tests:** `root-control@19d423cdf16531474de5680117867e12b5bb0620`  
**Exact currently reviewed controller companion:** `box-control@b7934882cfacd2fbfd60c7964713ed3dde7f9460`  
**Disposition:** source change made; native host installation and new compilation **NOT** authorized by this source receipt.

## Exact startup-only authority

A separate root-owned host supervisor may invoke the audited `zog.root_control` executable with the following **host-owned protected environment** (the illustrative UID/GID values require an independent real-host allocation and are NOT granted by this file):

```text
ROOT_CONTROL_SOCKET=/run/zog/root-control-fresh-cross-bootstrap-oct25.sock
ROOT_CONTROL_SOCKET_GID=<actual newly approved controller primary GID>
ROOT_CONTROL_CONTROLLER_UID=<actual newly approved controller UID>
ROOT_CONTROL_ROLE=build-only-project-v1
ROOT_CONTROL_AUTHORIZED_PROJECT=/home/zog-cross-owner/fresh-cross-bootstrap-oct25
```

These are root-owned service properties, never caller-supplied protocol fields. The exact executor and immutable source bytes must be pinned and attested by the host installer; this source component does **not** manufacture a host grant or check its own Git commit.

Startup rejects unsupported/missing role combinations, absent UID or primary GID, a noncanonical Project, and anything other than a dedicated `/run/zog/root-control-<slug>.sock`. A compiler-named listener cannot silently start in the ordinary full-authority mode. Before socket binding, root-control verifies that the service is root, that the Project lies strictly beneath the authorized passwd home, and that every Project directory has the exact authorized UID/primary GID and is not writable by group/others. It also verifies that the socket GID matches the actual passwd primary GID. Parent socket directories remain root-owned and non-writable by other principals. An existing dedicated socket is refused, **not unlinked or replaced**; stale-listener cleanup requires a separate, reviewed host-owner operation after independently proving the former sidecar is inactive.

Linux `SO_PEERCRED` checks the connection's exact controller UID **before frame reception**. Neither a root SSM connection, another account sharing the group, nor the build principal gains RPC authority from the socket's `0660` permissions.

## Permitted RPCs and immutability

| Class | Allowed operations |
| --- | --- |
| Compiler lifecycle | `build_register`, `build_prepare`, `build_start`, `build_observe`, `build_cleanup`, `build_cancel`, `build_release`, `build_forget` |
| Compiler inspection | `build_registration_status`, `build_job_logs`, `build_job_processes` |
| Health | `ping`, `systemd_version`, without extra Project selectors |

**All other operations are denied**, including `systemd_stop/reset_failed/start_service`, other `systemd_*`, `application_*`, `issuer_*`, `workspace_*`, `execution_identity_resolve`, storage, generic mount and unknown `build_*` extensions. Every permitted `build_*` RPC must provide `project_root` **byte-for-byte equal** to the protected startup Project. Each request independently revalidates the passwd Project ownership and pathname against the immutable role binding, so group drift, foreign Project, symlinks or an altered Project fail before privileged method dispatch.

Only this new role is restricted. The existing shared daemon, whose service has **no** `ROOT_CONTROL_ROLE` or `ROOT_CONTROL_AUTHORIZED_PROJECT`, retains its original supported full interface and original `/run/zog/root-control.sock` path, exactly as required by its existing station/Certbot consumers. No original unit properties, historical job, rootfs or source binding are changed.

## Verified source regression versus native acceptance

The dedicated required `.github/workflows/privileged-socket-regression.yml` now runs the new `tests/test_build_only_project_role.py` against exactly `box-control@b7934882...` and checks that named role, wrong-Project, exact-peer and forbidden-operation regression cases were collected; test failures or skips fail the job. Normal public Python 3.12/3.13 source/wheel checks run separately. **No source CI proves a live Linux socket, systemd StartTransientUnit installation, process UID/groups, cgroup/mount policy, boot reactivation or budget guard.**

Native host-deploy/host-install Work must first:
1. Recheck historical protected request/job/fragment hash baseline, original shared daemon PID/InvocationID, old bad-setting unit and current station/Certbot workloads **read only**. Avoid any `daemon-reload`, `reset-failed`, stopping or repinning old source.
2. Allocate and verify actual new locked controller/build NSS accounts, Project and source owners. Require nonoverlapping new Project, newly admitted immutable seed, source/companion file-byte attestations and zero supplementary groups for the build principal.
3. Install a **new dedicated host-owned supervisor** by a separately reviewed fixed installer using a uniquely named **transient service** through systemd `StartTransientUnit`, with portable `ExecStart`, exact protected environment and pinned executable, without a shared PID1 `daemon-reload`. This is privileged host control-plane service management, not permission for the caller to manipulate arbitrary Zog program units. A transient service alone is not a boot-start solution: a separately reviewed host-owned durable reactivation strategy remains mandatory.
4. Verify actual new root:primary-GID socket mode `0660`, protected traversable ancestry, exact peer UID, rejected root/wrong same-group/build peers, rejected all unrelated systemd/issuer/storage calls and foreign Projects; positive registration/read-only inspector only on the bound new Project. Inspect old shared PID/InvocationID and bad-setting fragment/hash again.
5. Ensure the new box-control instance is constructed with `RootControlSystemdTransport(Path(<dedicated socket>))` through image-build's protected `configured_runner` `socket_path`; default box-control socket construction is **not acceptable** for the new lane.
6. Verify the host-owned *aggregate* persisted **6-hour wall-clock** / **32 GiB additional disk** cap across all compiler subprocesses (not just per-command timeouts), live resource capacity fencing, guard crashes/reboots/cancel uncertainty and no side effects on old/Certbot/station workloads.
7. Only after complete Stage A source+native+budget acceptance may host-deploy/image-build Work durably submit **one fresh** typed `toolchain.submit(cross-bootstrap)`. Recover/inspect the same new request; never resubmit, restore or clean the historic original.

Source tests and this document **do not authorize** a host account creation, privileged socket installation, supervisor start, compiler execution, old job modification, EC2 creation or later bootstrap phase.
