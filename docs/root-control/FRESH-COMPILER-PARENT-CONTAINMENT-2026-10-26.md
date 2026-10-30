# Fresh compiler worker containment — root-control source correction

**Date:** 2026-10-26  
**Owner:** root-control / box-control Regular  
**Verified executable source:** `97481da26ae1294c9bf474f93f2ed90b4512b9b1` on `unstable`  
**Companion:** `box-control@b7934882cfacd2fbfd60c7964713ed3dde7f9460` (unchanged)  
**Producer:** `image-build@53ad8c2166e6b73dffbc722c2e47ccf3593612ec` (must pass own installed-byte admission)  
**Integration baseline:** `host-deploy@af9a7363c60dc1550abac4a8f3e9cb2e684d36c9` draft PR #2  
**Scope:** source correction for the exact new compiler lane only. **NO native controller deployment or new compiler submission.**

## Evidence and failure

[Host-deploy Work October 26 report](https://github.com/zog144/know-file/blob/43f9eb8cab1149f3f8323b3d699b370837d74811/host-deploy/verification/fresh-native-corrections-2026-10-26/README.md) verified five local fixture corrections but identified a structural containment violation in the prior root-control source: `BuildBackend.prepare()` created `zog-fresh-cross-bootstrap-oct25-build<job>.slice` independently of the protected host-deploy cancellation target `zogfreshcrossbootstrapoct25.slice`. The worker's explicit `Slice` property prevented reliance on the controller service's own placement. This was source-level proof of **missing guaranteed parentage**, not an observation that an actual live worker escaped.

## New frozen containment contract

Only the protected `build-only-project-v1` sidecar receives `BuildBackend(parent_slice="zogfreshcrossbootstrapoct25.slice", authorized_project_root="<canonical fresh-cross-bootstrap-oct25 Project>")`. The parent value is a **root-control source constant**, not a caller RPC argument or mutable job option. Its sole accepted Project basename is `fresh-cross-bootstrap-oct25`. The already reviewed sidecar role authenticates the exact controller UID/GID/Project and denies general systemd management; no new `systemd_*` or generic parent RPC was added.

For every new build root registration:
- Persist `parent_slice="zogfreshcrossbootstrapoct25.slice"` inside the immutable privileged registration intent before any execution.
- On preparation, reject registration mismatch or an existing job with an old/different parent/child slice. Bind the child slice `zogfreshcrossbootstrapoct25-build<32-character job ID>.slice` and durable `parent_slice` to the exact saved job. The finite service remains `zog-fresh-cross-bootstrap-oct25-build<job>.service`, explicitly started with `Slice=<bound child>`.
- PID1's hierarchical slice naming makes `zogfreshcrossbootstrapoct25-build<job>.slice` a child of `zogfreshcrossbootstrapoct25.slice`. The only systemd unit validator exception is the exact fresh Project and `build[0-9a-f]{32}.slice` child pattern; the parent itself, wrong Project, arbitrary other slice/service and the historical unit remain outside that exception.
- **Before setting durable `start_attempted`**, use the privileged adapter's read-only exact parent unit object to confirm `LoadState=loaded`, `ActiveState=active` and `ControlGroup=/zogfreshcrossbootstrapoct25.slice`. Fail closed if parent missing, bad-setting, inactive, relocated, or D-Bus readback fails. Never silently create a different budget parent.
- During worker observation, require systemd `Slice` readback to equal the durably bound child. A live service must have the exact `ControlGroup=/zogfreshcrossbootstrapoct25.slice/zogfreshcrossbootstrapoct25-build<job>.slice/zog-fresh-cross-bootstrap-oct25-build<job>.service`; any missing or divergent active group blocks observation. A terminal inactive/failed service may no longer have a cgroup; terminal evidence and cleanup remain independently required.
- Cleanup of the saved worker service and child slice checks the exact corresponding cgroup path before stopping/unrefing them; a wrongly placed active worker blocks cleanup. The **shared parent is never stopped, reset or released by the build backend**.
- Ordinary shared-controller jobs have no parent slice in their registration or job and retain the historical `zog-<Project>-build<job>.slice` behavior. No existing historical records are rewritten or migrated.

## Code and source acceptance

The narrow implementation modifies:
- `src/zog/root_control/build.py` — fixed source parent, persistent registration/job binding, pre-start parent observation, service Slice and cgroup validation, fail-closed cleanup/status/release.
- `src/zog/root_control/systemd.py` — narrowly defined alternate fresh-only child slice name validation; no general slice permissions.
- `src/zog/root_control/daemon.py` — pass the fixed parent and protected Project into the new build-only role only.
- `tests/test_build_worker_containment.py` — durable binding, missing/bad-setting/relocated parent, no start marker on refusal, real expected Slice property, exact active service cgroup, foreign/altered worker observations, escaped cleanup, wrong Project/malformed child rejection, legacy absence of new fields.
- `.github/workflows/privileged-socket-regression.yml` — new tests required on PR, explicit selected JUnit cases and zero security skips or failures.

[Privileged source security run 40404621130](https://github.com/zog144/root-control/actions/runs/40404621130): **357 passed, zero skipped/deselected**.  
[Public source run 40404621110](https://github.com/zog144/root-control/actions/runs/40404621110): Python 3.12 and 3.13 each **433 passed, 1 unrelated native-only skip**; wheel/source distribution checks PASS.

No box-control executable changes were needed. The existing typed calls `build_register`, `build_prepare`, `build_start`, `build_observe` preserve their wire schema; the root-owned role binds parentage internally.

## Mandatory native Work acceptance (disposable, no new EC2)

**The source CI cannot prove a live process's Linux cgroup placement.** Before submitting any compiler job, host-deploy Regular must adopt this exact root-control executable pin **only in the fresh v3 lane** and finish its separate aggregate, durable 21,600-second total clock and +34,359,738,368-byte disk accounting, including host-owned ledger/state, journal/log backing files, metadata/slack and failure recovery. Current 55 fixture passes do NOT prove those ceilings.

Host-deploy Work then requires a separately reviewed disposable Linux systemd test boundary **within the previously authorized existing resources**; do not create another EC2 instance, reboot the retained old-compiler host or reload shared PID1 just to test. In an isolated live PID1:
1. Verify exact root-owned `zogfreshcrossbootstrapoct25.slice` has loaded/active state and the expected `ControlGroup`, and that the user-approved overall guard actually owns/cancels that slice.
2. Verify exact fresh protected Project, new source/companion module hashes, UID/GID, socket SO_PEERCRED and `build-only-project-v1` role.
3. Register/prepare one harmless finite fixture and inspect the **persisted** `parent_slice` and `slice_name`. Require that PID1 displays the exact service `Slice` and that `systemctl show --property=ControlGroup`, `/proc/<every worker PID>/cgroup` and `cgroup.procs` place **all descendants** beneath the approved parent at each observation. A controller/supervisor process merely being in the parent is insufficient.
4. Intentionally reject wrong Project, absent/bad-setting parent and wrong or missing service cgroup, without creating `start_attempted`, mutating the old Project or dispatching arbitrary syscalls. Test the new parent's cancellation kills **only** its descendants and leaves existing shared controller, Certbot and historical `bad-setting` unit intact.
5. Repeat after controller restart/disconnect, daemon reload **only within disposable test PID1**, job exit, cancellation, cleanup and budget exhaustion. Assert no cgroup escapes and no replacement submission; reconcile protected receipts.
6. Rehash historical gateway request `371da99f...`, old controller job `7dfa7c6e...`, InvocationID `6d8efd9e...`, original fragment and shared PID1 controller identity before and after.

**NO-GO for fresh cross-bootstrap submission until actual cgroup placement, exclusive cancellation, aggregate time/disk enforcement, protected installed bytes, seed import and crash/reboot acceptance are independently verified.** This source correction performs no host-side writes, new AWS activity or original compiler action.
