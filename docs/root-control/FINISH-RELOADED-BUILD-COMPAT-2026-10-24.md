# Finite build transient unit reload compatibility and original compiler recovery

**Date:** 2026-10-24  
**Owner:** root-control Regular with box-control review  
**Origin:** [original compiler live readback](https://github.com/zog144/know-file/blob/c41b661098809b97fa48d95db6a4817584ed9431/image-build/verification/original-compiler-recovery-2026-10-24/README.md)  
**Disposition:** **future-unit source correction implemented and source CI accepted; native systemd 252 reload acceptance NOT RUN; original historical job remains BLOCKED.** This document creates no authorization for host changes, direct systemd mutation, new commands, or producer resume.

## Frozen original, DO NOT REPIN OR RELAUNCH

| Entity | Original identity |
| --- | --- |
| GitHub gateway request | `371da99f23764180aad37d8e4e83595b` |
| Phase operation | `c148d718f9c93d16238e71945e8f4784` |
| Image-build source | `31e6121cdf9fd05336286529666e2c35cdbe0831` |
| Box-control companion | `644170fc441863307092f329bf7e23cb64eb33e2` |
| Installed root-control executable | `e4f25110c854c000bdde5ec564c8119370da9a52` |
| Compiler seed-check pipeline | `a19de7a39f474e8da0604b848cd94d60` |
| Retained attempt | `image-19e25953716f4f78b774f4b23e66cc3d` |
| Resource | `9e511cb845234b2dac838c21a445baad` |
| Configure job | `7dfa7c6e3f556e4cd8673771035c1280` |
| Systemd InvocationID | `6d8efd9e612c4e94a9e6117fe41e685b` |
| Boot | `0c2c1834-fca6-46c1-8a0f-9813799533f3` |

This historical systemd 252.23-12.amzn2023 job used the D-Bus `ExecStartEx` extended property with `no-env-expand` and no `journal_barrier_token`. Its transient on-disk file serialized two `ExecStartEx=` lines. The prior configure did execute and produce a Makefile, with PID1 `Result=success`, `ExecMainCode=1`, `ExecMainStatus=0` and nonzero exit timestamp, same InvocationID. After an unrelated daemon reload (Oct 24 12:43:04 UTC), PID1 rejected `ExecStartEx` as an unknown **unit-file directive**, leaving `LoadState=bad-setting`, no executable properties, empty cgroup. That lost property coverage correctly causes the existing `build_observe` to reject rather than silently accept. **Do not treat its saved `running` snapshot as current running proof.**

## New finite-job source correction

Reviewed source on `root-control/unstable` at `5f8b132010f5ff7d220e9a289b062a4b362a8d5e` changes *future* selected finite build launches to use the portable D-Bus `ExecStart` signature `a(sasb)` and the same portable `ExecStopPost` signature for the optional journal hook, with explicit true ignore-failure for that hook. It no longer writes `ExecStartEx`/`ExecStopPostEx` that the observed systemd 252 unit-file parser cannot reload.

The original immutable request command is **not rewritten**. Serialization escapes literal dollar signs and percent specifiers as `$$` and `%%` in the D-Bus argv to prevent systemd's own variable/specifier substitution from changing executable arguments. The controller's expected-property comparison now checks the encoded exact argv; it does not ignore `ExecStart` or authorize arbitrary other properties. NULs, unsupported executable names, mutated resource or changed command are refused. This encoding is validated by source tests only: **systemd 252 native tests must independently compare the command's actual process argv against the frozen request, before and after reload.** Do not deploy before that proof.

The reload-safe command is locally prevalidated *before* writing the irreversible `start_attempted` marker. It remains persisted before any systemd start call. Existing `start_attempted` idempotency, finite `Type=exec`/`ExitType=cgroup`, no restart, protected UID/GID, immutable root, writable workspace allowlist, cgroup budget, AddRef, journal attribution and failure blocking remain intact.

**Source CI:** [root privileged regression 40116326408](https://github.com/zog144/root-control/actions/runs/40116326408) **290 passed**, zero security skips/deselections; [public source 40116326379](https://github.com/zog144/root-control/actions/runs/40116326379) PASS (Python 3.12/3.13, wheel audit). Synthetic tests cover portable property signatures, exact dollar/percent escaping, refusal of command NUL, no duplicate launch, portable barrier hook and fail-closed historic missing executable properties. **These do not constitute a native reload test.**

## Two separate acceptance procedures — NEVER CONFLATE

### A. Future-job serialization acceptance (disposable systemd 252 host)

- Stage a new isolated disposable Project with exact reviewed current source and authentic nonzero separate controller/build identities, root-owned socket and fixed source pin. Do not install this candidate on the shared compiler for this test.
- Register/start ONE finite test command through actual box-control/root-control. Include arguments with `$HOME`, `${FOO}`, `$$`, `%i`, `%%`, spaces, semicolons and quotes; compare **real executed argv bytes** to frozen source request. Verify literal shell expansions occur only inside the chosen shell, not in systemd.
- Inspect `StartTransientUnit` D-Bus properties, actual unit fragment, `systemctl show`, exact `_BOOT_ID` / `_SYSTEMD_INVOCATION_ID`, process UID/GID and limits. Require stable `ExecStart=`, not `ExecStartEx=`, and independently verify `ExecStopPost=` if barrier enabled.
- Run `systemctl daemon-reload` while job is still active and again after a successful termination **only** on that isolated host. Require `LoadState=loaded`, unchanged `ExecStart` semantic argv and selected policy, retained same InvocationID, no duplicate execution, and normal `build_observe`, finalization and cleanup. Include negative tampered fragment/property cases and timeout/cancellation. Reject all missing/mismatched properties. Preserve journal evidence and test native journal hook fallback separately.
- Repeat on exact target Amazon Linux `252.23-12.amzn2023`; any deployment to the retained shared controller requires independently approved source/companion successor binding.

### B. Historical already-successful InvocationID recovery (retained shared compiler)

**Read-only evidence first. No work to change the original unit before a one-time reviewed recovery contract is approved.**

1. Snapshot hashes/inodes of original protected root-control job, controller request/job/resource record, producer checkpoint, selected recipe/pin, and gateway owner operation. Confirm one immutable accepted request/attempt/command/job. Require original saved `start_attempted=true`, original command, rootfs/workspaces, build UID/GID and earlier captured matching invocation; forbid replacement IDs.
2. Record `_BOOT_ID`, `_SYSTEMD_INVOCATION_ID`, unit name, `LoadState`, `LoadError`, `Transient`, `FragmentPath`, `ExecMainCode/Status/ExitTimestampMonotonic`, PID/cgroup emptiness and `Result` from PID1, and snapshot the exact root-owned transient unit fragment with SHA256. Independently compare every recoverable fragment property and the exact escaped serialized argv to original prepared job/expected systemd policy. Preserve the existing evidence SHA values.
3. Bound a **complete, size-limited** journal read by saved boot, invocation and unit. Validate PID1/service messages and actual configure logs against original command and worker UID, and ensure no second execution. Ordinary journal stdout and a newly calculated fragment digest alone are not authoritative terminal evidence. Specifically, this old job has **no** authenticated journal-barrier token.
4. Fail closed if the loaded unit has an active cgroup, PID1 terminal fields are inconsistent/absent, the boot or InvocationID changed, the fragment was overwritten, expected policy cannot be reconstructed, or the journal is incomplete/ambiguous. Do not infer success from Makefile existence, SSM response 0, or `LoadState=bad-setting` alone.
5. Produce a **review-only original-invocation evidence receipt** containing exact job/request/resource/boot/InvocationID, all independently captured evidence SHA256 digests, observed exit facts, and an explicit reviewer decision. A separately reviewed protected one-time controller reconciliation operation (not implemented or authorized in this source pass) would have to durably bind the one exact receipt, prohibit generic `bad-setting` acceptance, preserve historical request identity, record a successful terminal outcome **only** if an independent authorized review confirms it, and then perform verified cleanup in its own recovery phase. Existing mutating `build.refresh`, reset-failed, process release and producer resume must remain blocked until that contract is explicitly accepted.

**If the original command's runtime identity or terminal status cannot be independently proven, retain the blocked original forever until supported abandonment is designed; do not force a success result or relaunch.**

## Next owners

- **root-control Regular:** source correction above and acceptance protocol owned; seek separate review of any one-time historical recovery operation before implementing mutable finalization.
- **box-control Regular:** review the saved request/job state and ensure no existing public status endpoint misreports stale `running` as observed; any terminal reconciliation must be durable, idempotent and exact-request bound, not a direct state-file edit.
- **host-deploy/image-build Work:** preserve original SSM/producer/gateway records and current controller while testing serialization on an **independent disposable host**. Do not run `daemon-reload`, `reset-failed`, `stop`, `StartTransientUnit`, cleanup or new `toolchain.resume` on the shared compiler until separately authorized.
- **host-deploy Regular:** review source transition pin from old installed `e4f25110...` to candidate future source; do not substitute the new candidate under the old v2 protected grant or historical task without an explicit binding successor.

**No first compiler replay, next build phase, modified historical source or production release is authorized.**
