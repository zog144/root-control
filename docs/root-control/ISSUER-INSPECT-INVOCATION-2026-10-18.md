# Exact-invocation issuer inspection — privileged boundary review

**2026-10-18 | source implementation completed, native Gate B NOT RUN**

The selected finite `certify-manage/inspect` is a managed transient Zog runtime, **not** a static or long-lived inspector daemon. The new root-control `issuer_inspect_result` operation is read-only and accepts exactly `project_root` and the saved `request_id`. It runs in the existing bounded observation lane.

The privileged reader [issuer_inspection_result.py](../../src/zog/root_control/issuer_inspection_result.py) reconstructs a single satisfied selected inspect from durable controller request+operation records, exact saved runtime/boot/InvocationID, protected issuer grant and policy capability. It also requires completed runtime cleanup, successful program status, and matching immutable software view, command, expected systemd properties and mount inventory. No request may choose a journal stream, PID, UID, unit, path, policy or program.

The reader uses systemd's *saved* `_BOOT_ID` and `_SYSTEMD_INVOCATION_ID` journal match and validates `_SYSTEMD_UNIT`, `_TRANSPORT=stdout`, issuer `_UID`, exactly one `ZOG_CERTIFY_INSPECT_RESULT_V1` line, issuer policy SHA, approved hostnames, validity, fingerprint, temporal provenance and a journal timestamp within 120 seconds of the inspection. The inspection must be newer than 15 minutes to remain actionable. It reads a fully bounded stream (256 KiB; 5-second budget), never a truncated page that could hide duplicates. Missing/overlarge/malformed/stale/foreign records fail closed. An exit code 0 alone cannot create issuer-verified evidence.

The returned `zog-trusted-issuer-inspection-v1` is a **local issuer X.509 observation**: `verified` or `unverified`, with `tls_ready=false` unconditionally. It does not attest nginx, public CA/SNI, renewal delivery, or a matching *separate* renewal request; host-deploy must independently correlate the existing authenticated issuer renewal observer.

Root-control's original `issuer_observe` request-journal interface is unchanged. The role-broker implementation in box-control only exposes selected renew/inspect/stage and accepts exact request IDs. The host-deploy client requires an independently pinned controller UID for inspection, verified by SO_PEERCRED before request transmission.

**Source regression:** [root-control run 39128163435](https://github.com/zog144/root-control/actions/runs/39128163435) **230 passed**; [box-control run 39128166197](https://github.com/zog144/box-control/actions/runs/39128166197) **525 passed**, all security test selections without skips/deselections. The tests use synthetic journal rows and mocked protected identities; they do not establish real journald attribution/retention, a native systemd invocation, real ACME state, installed immutable code, UID/GID mounts or reboot recovery.

**Gate B requirements:** an approved isolated host after image-build native Gate A accepts the actual view, original selected prepare/inspect request IDs, saved InvocationID and systemd properties, real issuer UID and protected policy/storage binds, journal stdout transport metadata, negative duplicate and missing logs, crash/reboot, request history and pruning, headless recovery and no network mutation. Staging CA, Cloudflare token transfer, nginx reload and production issuance remain NO-GO.
