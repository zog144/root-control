# Non-root compiler controller Project and privileged socket — identity review

Date: 2026-10-21  
Owner: box-control/root-control Regular  
Related: [box-control #10](https://github.com/zog144/box-control/issues/10), [root-control #8](https://github.com/zog144/root-control/issues/8), [host-deploy draft PR #2](https://github.com/zog144/host-deploy/pull/2)  
Exact host-deploy source reviewed: `12819ad8d06e772afbfbb0fb1b71142cbe7833eb`  
Exact controller companion: `zog144/box-control@644170fc441863307092f329bf7e23cb64eb33e2`  
**Reviewed patched root-control:** `zog144/root-control/unstable@e4f25110c854c000bdde5ec564c8119370da9a52`

## Disposition

**Source compatibility: PASS after a narrow root-control hardening change. Native socket/UID/Project/SSM acceptance: NOT RUN and NO-GO.** No real host, systemd manager, socket, privileged group or IAM role was changed by this source pass.

The original root-control `62dca363...` did *not* match the proposed root-owned group socket: its `_protect_socket` changed the listener inode owner to the nonroot controller UID even in group mode. This contradicted host-deploy's exact `st_uid=0`, `st_gid=controller_gid`, mode `0660` kernel-DAC preflight. It must not be used to enable that launcher.

Root-control now:
1. With both `ROOT_CONTROL_CONTROLLER_UID` and `ROOT_CONTROL_SOCKET_GID`, resolve the exact UID's passwd record, require its **primary GID** to match the reviewed socket GID, and set the listener to **root:controller-primary-group 0660**. Reject unknown accounts or mismatched primary group before changing access. Legacy root-only 0600 and nonroot-owner-only 0600 socket modes remain separate and are **not** a fallback for the new compiler lane.
2. Authenticate every connection using kernel Linux `SO_PEERCRED` *before* accepting any request frame, allowing only exact `controller_uid`. Linux root SSM (UID 0), a different group member, the build process UID, station-access and host-welcome are not accepted. DAC membership alone is not privileged RPC authorization; supplementary groups are unnecessary.
3. For **every `build_*` RPC**, including registration, prepare, start, observe, cancel, cleanup, release, forget, journal/status/process reads, require the claimed Project path to be an unredirected canonical directory **strictly beneath the real passwd home of the configured controller UID**. Verify home and each subdirectory are owned by the exact controller UID and **primary GID** and are not group-/world-writable; fail closed before invoking any privileged build backend. The root-only legacy transport retains its separate policy.
4. Continue requiring registered build UID/GID to be positive integers, disjoint from the controller Project's UID/GID; recheck disjointness at privileged preparation after any Project ownership drift. The build identity is not granted `/run/zog/root-control.sock`, root-owned imported filesystem or controller state. Existing build start_attempted, single-writer lane, systemd `User/Group`, journal and cleanup/recovery contracts remain unchanged.

The trusted host-deploy launcher **already** uses `pwd.getpwuid(controller_uid)`, exact home, canonical Project under home, root-owned source/companion checkout roots, exact fixed interpreter, nonroot kernel user/group transition and `extra_groups=()`, sealed memfd for request data and protected root-only SSM receipts. BoxControl `Project.require_state_allowed()` gates local mutation to `Path.home()`; with host-deploy's fixed unspoofed `HOME=passwd.pw_dir` that resolves to the same root-control-checked project. The controller's own home check is *not* independent authentication of arbitrary user-supplied `HOME`; the protected launcher, kernel peer and root-control Project checks are all required.

**host-deploy Regular follow-up:** update `_trusted_identity` to reject home/Project `st_gid != controller_gid` (root-control now enforces that requirement), and confirm that the installed source/companion **contents and all descendants** are root-owned, readable but never writable by controller or build identity—not just the top-level checkout directory. Do not silently repin an existing operation; issue a new source/revision binding on the new authorized lane after review. This follow-up is not authority to execute a compiler job.

## Tested evidence

- [Privileged-socket security regression, exact root-control commit](https://github.com/zog144/root-control/actions/runs/39641720410): **264 passed**, no skipped/deselected test in the required security gate.
- [Public source verification](https://github.com/zog144/root-control/actions/runs/39641720309): PASS (synthetic Python suite reports 360 passed, 1 skipped across its broader selection).
- Root CI fetched exact box-control `644170fc441863307092f329bf7e23cb64eb33e2` (formerly an older `542e6f...` fixture), so this was actually tested as the host-deploy pinned companion.
- New regressions: root-owned primary-group socket mode and passwd GID mismatch; UID 0 and unrelated UID rejected by `SO_PEERCRED`; Project wrong home, symlink/canonicalization, wrong owner UID/GID, group-writable ancestry, missing Project; build status, logs and process reads may not select another owner's Project.
- Existing build backend tests cover distinct UID/GID at registration and preparation, immutable request/operation, no repeated privileged start on ambiguous replies, cancellation and cleanup.
- Nothing in these fixtures validates actual passwd/NSS entries, ACLs, systemd/D-Bus startup or socket inode on a real host.

## Required disposable host acceptance before enabling compiler work

1. Host-install/operator authoritatively choose and record **real** controller UID/GID, build UID/GID, passwd home, exact Project, group membership and login restrictions; none may be inferred from the GitHub issue, station-access UID, `HOME`, wrapper defaults or an example. Check `getent passwd`, `getent group`, kernel process UID/GID/groups and no supplemental groups; confirm controller != root and build identities distinct.
2. Verify `namei`/stat of passwd home, Project, root-owned source and exact pinned checkout subtrees, root-owned protected task/request/results, and source/output workspaces. Require no symlink substitutions, unsafe ACLs or writable root-owned code and records; Project ancestors inside home are non-writable to other principals. Verify build process cannot traverse/modify Project control state.
3. Start exact patched root-control using reviewed environment `ROOT_CONTROL_CONTROLLER_UID=<actual controller UID>`, `ROOT_CONTROL_SOCKET_GID=<actual primary GID>`, fixed `ROOT_CONTROL_SOCKET=/run/zog/root-control.sock`. Inspect socket inode `root:controller_gid 0660`, protected root-owned parent `/run/zog`; no insecure supplemental membership or group-only authority.
4. From root SSM (UID 0), build UID, wrong same-GID account, and wrong controller UID, try the socket: deny **before** privileged RPC. From exact reviewed controller UID with only the primary GID, connect and perform a **read-only** `ping`/status against the exact authorized Project. Check kernel `SO_PEERCRED` at the daemon and remote caller's actual `/proc` credentials; no spoofing.
5. With a disposable synthetic Project, test wrong home, wrong directory UID/GID, symlink replacement, group-writable ancestors and cross-Project read-only/mutation requests. All must fail before registration or systemd invocation. Observe real software and task SHA/source pins and sealed memfd request reader.
6. Resume the *same* protected seed/lane operation after a deliberate connection loss and restart. Verify immutable original Project/UID/GID, controller request ID, registered build resource, unit/InvocationID and retained uncertainty. A new systemd unit must not appear from a repeated submission. Check different-lane isolation, cancel/cleanup and ledger retention separately if a compiler execution has its own approval.

**Explicit hold:** The preceding read-only native preflight can be accepted without permitting `toolchain.submit`. Production IAM/SQS enablement, first compiler submission, rootfs/toolchain publication, host-wide group changes, clearing prior ambiguous markers and adoption of historical root-only lanes remain **NO-GO** pending separate Work evidence and authorization.
