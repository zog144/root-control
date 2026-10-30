# GitHub-triggered image-build — privileged execution compatibility

**2026-10-19 — root-control Regular security review**  
**Reviewed runtime source:** `root-control/unstable@e6ff84448ec7103af141905749f504b7e5704fc1`  
**Controller companion tested:** `box-control@542e6f8a5c0a485170c1c8a29d6d1effaced67e1`  
**Source PR CI:** [privileged-socket-regression 39255526688](https://github.com/zog144/root-control/actions/runs/39255526688), **261 passed**.  
**Native host execution:** NOT RUN; no production host, mount, IAM role, socket or systemd unit modified.

## Authority model and decisions

GitHub, SQS, SSM and host-deploy are **request/transmission authorities only**, not root-control identities. An approved gateway invokes the exact reviewed image-build producer checkout, which binds pipeline/attempt/recipe snapshot and creates local controller command requests. The trusted local nonroot box-control project owner alone may use the exact privileged root-control socket. Root-control enforces kernel peer UID; no direct GitHub, host-deploy or ordinary build UID access is approved. The daemon exposes typed build operations, not host shell/argv, raw filesystem/mount operations or arbitrary systemd commands to network inputs. **A gateway that allows an issue field to become arbitrary command/argv would be a separate upstream authorization fault, not something that GitHub OIDC could cure.**

Build execution is the typed `build_register` → `build_prepare` → `build_start` → `build_observe` → `build_cancel`/`build_cleanup` → `build_release`/`build_forget` API. The build request is a canonical immutable JSON input bound to registered root, two exclusive source/output workspaces, UID/GID, resolved guest executable, argv/environment, timeouts and resource limits. Root-control does not resolve commands using the host Python/PATH and never falls back to subprocess, Docker or Podman.

A registration's build identity must be a separate explicit **positive numeric UID AND GID**; both must be less than 2^31, and **neither may equal the controller project's owner UID/GID**. The previous check considered only the UID; this pass closes the GID overlap and rechecks the separation immediately before privileged preparation, so changing project ownership after registration cannot turn an original build grant into a controller-owner grant. The root import is owned by root and immutable; only exactly the registered source/output workspaces are writable to the build identity. Real NSS, supplementary groups, ACL and mount inspection remains a native gate.

A build start sets `start_attempted` and persists it **before** starting its slice and `StartTransientUnit`. A lost or timed-out job reply is ambiguous, never permission to retry the same start. Root-control refuses to start an attempted job again, even if the caller reconnects under the same ID. Systemd uses `Type=exec`, `ExitType=cgroup`, `Restart=no`, `PrivateNetwork`, `PrivateDevices`, `ProtectSystem=strict`, `NoNewPrivileges`, zero capabilities, exact UID/GID, explicit cgroup memory/task/CPU limits where selected, startup/runtime/stop timeouts, journald-only logging, and the approved bind set. No root-owned persistent build state is offered as a writeable guest mount.

The root daemon serializes **privileged control-plane mutations** in one bounded executor; distinct prepared build-root lanes execute simultaneously as independent transient systemd services after admission. The same registered root admits only one unfinished writer. This is not a promise of parallel root-mutating registration imports or a shared unbounded worker pool. Cross-project/lane resource budgeting remains the gateway/operator's responsibility.

Observation compares expected launched service properties, exact systemd invocation, cgroup state and terminal evidence. The journal-barrier exit hook may preserve authoritative terminal information when the unit has already unloaded; missing/mismatched evidence causes an unknown/fault outcome. Cleanup is explicitly proven before the root/import is released. Lost cleanup replies retain the protected controller/root record and require observation/reconciliation, not a replacement systemd invocation. A caller disconnect alone never cancels compilation.

## Source coverage and bounded changes

1. Reject root-control build registrations whose GID equals the owner group's ID, even with a different build UID; reject booleans, zero and >=2^31 numeric IDs.
2. Before preparing an existing registered root, recheck its persisted build UID/GID against *current* controller project ownership.
3. Added source regression cases for the above, including changes to project ownership after registration. Existing root-control tests for exact systemd properties, immutable root, workspace ownership, wrong command resolution, registered-writer exclusion, cancellation, cleanup and resource reclaim remain included in source CI.
4. The source CI's exact box-control companion SHA is verified before running tests. Historical public `zog` image-build is a compatibility fixture **not** the deployed/current image-build revision.

The source gate is **PASS**, but no live systemd, actual filesystem UID/GID, host SSM, journald retention or crash/reboot test is represented as a PASS.

## Disposable-host native acceptance — Work owner

Run this only on an independently authorized isolated host after source/provenance pins and host-install identities are approved:

1. Record actual nonroot controller owner UID/GID, build UID/GID, supplementary groups, protected root-control socket peer UID, root-owned registration/controller state and host project directories. Verify that neither build UID nor its groups can modify controller state or root registry.
2. Admit one immutable producer request through reviewed host-deploy transport. Verify signed original gateway operation, immutable image-build repo/revision, selected recipe snapshot, exact application of build policy, registered input hash/manifest identity and one durable controller request/job identity before the systemd launch.
3. Launch a bounded long-running compilation and disconnect/terminate the GitHub runner/SSM response channel. Reconnect through the same producer operation ID and controller request; prove exactly **one** transient unit/InvocationID and no duplicate start.
4. Repeat with a lost `StartTransientUnit` acknowledgment, root-control daemon restart and a fast-exiting program. Preserve unknown evidence if the unit and exit-hook proof are both unavailable; never reallocate the job on ambiguity.
5. Simultaneously run two reviewed **different** build-resource lanes; observe both systemd cgroups active. Confirm same-root overlapping submissions are denied, while privileged mutation calls remain serialized.
6. Inspect service `User`/`Group`, NNP/capabilities, network/devices, rootfs view, exact writable binds, working directory, resolved executable, argv/environment, memory/task/runtime/stop limits and systemd transient properties. A mismatched altered unit must fault, not be adopted.
7. Cancel a live job with a preserved request ID, inspect SIGTERM/timeout/KILL evidence and ensure no orphan cgroup survives. Attempt repeated cancel, interrupted cleanup, lost release reply, restart/reboot and eventual explicit release without deleting image-build's retained source/output/evidence prematurely.
8. Verify exit 0, nonzero, signal, timeout and missing journal/InvocationID each produce the expected durable classification and the same machine-readable controller IDs/exit evidence after gateway reconnect. Logs remain independently retained by journald, not fabricated by controller success.
9. Demonstrate 48-hour idempotency/retention boundaries without a clock hack on production: use an isolated clock-controlled acceptance fixture or preapproved disposable time environment. Retired request IDs cannot allocate new execution after pruning.
10. Run negative input cases (root/group alias, wrong manifest binding, changed command/env, unexpected mount, symlink/device import, host executable fallback, raw RPC, direct GitHub/host-deploy root-control access, wrong socket UID, policy drift). Fail closed before additional privileged work.

**Production deployment and broad GitHub compilation:** NO-GO until the Work/native and producer/gateway-specific gates are actually accepted. This review does not authorize a new trust path or general raw argv API.
