# Security audit response: PR CI, privileged socket, bounded ingress

Date: 2026-10-16. Owners: box-control and root-control Regular.
Baseline: box-control unstable 03c847ec6adc55fd5e2268534d47b500d9f52ab9 and root-control unstable 43b04826af8fdcb9dfb8e50fc130aa7d0988a1fb.

## Source implemented; acceptance not established

The root-control daemon now authenticates exact numeric controller UID via Linux SO_PEERCRED before decoding a framed request. Without the configured ROOT_CONTROL_CONTROLLER_UID, privileged access defaults to root-only DAC 0600. With the approved nonroot controller UID, socket ownership uses that UID and mode 0600. An optional ROOT_CONTROL_SOCKET_GID must accompany the UID and gives 0660 DAC, but does NOT authorize additional peer UIDs. UID/GID authority must come from host-install protected numeric grant records, never a caller-supplied name or JSON field.

The socket parent chain must be root-owned, non-symlinked and not group/world-writable. A suspicious preexisting path is not removed. Station-access, host-deploy, the certificate issuer, host-welcome, ordinary apps and delegated observers must use their existing narrowly authenticated brokers, not the general privileged socket. No production ACL, user, grant, group, mount or installed service was modified.

## Raw mount/unmount audit

Reviewed controller transport: box-control/src/zog/box_control/runtime/root_control.py sends typed systemd_*, build_*, workspace, issuer and inspection requests. It contains NO method sending the raw mount/unmount RPC. In root-control/src/zog/root_control/daemon.py the legacy branches directly forwarded client-chosen source, target, filesystem, flags and data to privileged.py's libc mount/umount2 wrapper. They are now unconditionally rejected, retaining typed runtime systemd BindPaths and independently validated managed storage/build mechanisms. This is intentionally a fail-closed compatibility change. Any undiscovered historical external mount RPC consumer now fails and requires a reviewed typed project/runtime-bound substitute. A wider source inventory attempt exceeded the repository connector request limit; do not claim an exhaustive external-caller audit.

## Admission contract and compatibility

A four-slot pre-dispatch ingress pool authenticates peers before frame parsing and enforces a 10-second absolute monotonic deadline from accept. Request size remains max 1 MiB; empty frames, duplicate JSON keys, invalid UTF-8, non-object JSON and invalid operation names are rejected. Excess ingress connections receive a generic immediate "root-control admission busy" response, without waiting in an unbounded queue. Invalid requests receive only "root-control request rejected" or close on peer denial. Handler error responses use "root-control operation rejected", retaining validated structured codes and the storage_failure bit instead of reflecting potentially sensitive system paths.

The existing serialized single-thread mutation lane (8 total queued/admitted slots) and the separate two-worker read/inspection lane are retained. Ping is handled in the read lane. Execution order is the order of fully admitted mutation requests, not the arrival order of incomplete frames. A disconnect after mutation submission preserves uncertainty: box-control RootControlReplyTimeout and durable request identity semantics are unchanged and clients must not replay non-idempotent operations by guessing failure. Normal lane saturation still reports "root-control lane busy; retry later". Reader and mutation executors are closed on daemon exit; slots are released on failure and completion.

## Required CI gates

box-control/.github/workflows/controller-security-regression.yml defines the stable check name controller-security-regression. It triggers on all pull requests targeting main/unstable without path filters, uses exact pinned root-control, verifies its checkout SHA, imports the current installed namespace components and an explicitly historical public image-build fixture, and runs symbolic execution identity, storage/grants, issuer, durability/reboot and privileged-socket tests without deselection. A report gate requires all four symbolic parameterized cases and reports test totals/skips/errors. The historical aggregate lane in box-control/.github/workflows/ci.yml is renamed public-aggregate-compatibility; its known four excluded cases are not silently counted as security passes.

root-control/.github/workflows/privileged-socket-regression.yml defines privileged-socket-regression against an exact reviewed public box-control checkout. Both source workflows have read-only contents permissions, no pull_request_target or live privileged mutations. GitHub-hosted tests do not constitute native socket DAC, real mount, SELinux, installed UID/GID, systemd identity or reboot acceptance. Current public image-build is not approved by the audit; the historical Zog image-build module used solely as a compatibility fixture is labeled accordingly.

## Pending acceptance and exact owner handoffs

- Obtain actual green example pull-request runs and a deliberately failing scratch-PR regression, record their run links and exact source SHA/tests/skipped counts. No workflow-result links are asserted here.
- Repository administrator configures branch protection with required status names controller-security-regression and privileged-socket-regression. Existing direct publishing does not automatically become protected by adding workflow YAML.
- host-install: independently verify deployed numeric controller UID/GID and supplementary memberships, root-control socket ownership/modes/ancestors, unit and environment integrity, wrong station/host-deploy/observer UID denial, applicable LSM, and current root-only behavior before enabling nonroot controller use.
- Disposable-host Work: native multi-client fairness, real kernel socket credentials, mount namespace and exact runtime grant, interruption/reboot safety. No production server restart, mount change, privilege grant, certificate issuance, or greetd login approval is authorized by these source changes.

Disposition: SOURCE COMMITTED; CI TEST RESULTS AND NATIVE ACCEPTANCE PENDING.

## Verified GitHub Actions evidence (2026-10-16)

Successful ordinary documentation-only draft PRs (subsequently **closed, not merged**):

- box-control PR #1: https://github.com/zog144/box-control/pull/1
- Box candidate check controller-security-regression: https://github.com/zog144/box-control/actions/runs/38970885412 — **success: 468 passed, 0 skipped, 0 deselected, 0 failed**; report step explicitly verified all four symbolic identity cases, including both caller-credential parameterizations. Historical public-aggregate compatibility job also succeeded separately.
- root-control PR #1: https://github.com/zog144/root-control/pull/1
- Root candidate check privileged-socket-regression: https://github.com/zog144/root-control/actions/runs/38970889747 — **success: 195 passed, 0 skipped, 0 deselected, 0 failed**. Historical Public source verification also succeeded separately.

Negative-control draft PR #2: https://github.com/zog144/box-control/pull/2 (subsequently **closed, not merged**). The deliberately failing test was appended to an included security-suite module **only on its scratch branch**. https://github.com/zog144/box-control/actions/runs/38971013118 returned **failure: 1 failed, 468 passed**. Its verification/report step also failed as required. The failing fixture never entered unstable. This proves the security CI **runs and rejects one synthetic failing test on an ordinary PR**; it does not prove branch-protection rules are installed or that the native host is safe.

Exact candidate source pins in successful runs:

- box-control workflow candidate checkout: the PR head b26701a38651678bca2f5d2108a629094efcc83f, exact root-control companion ba7d0e4afc18493a34d2fd9a05a661b2ca5ad8cd and historical Zog d47d86b363824c718d9c165124cb55bbed12e0f9.
- root-control workflow candidate checkout: the PR head 0d2a563cd397ee2c4eb6801f73031ce31710ab33, exact box-control companion 03c847ec6adc55fd5e2268534d47b500d9f52ab9 and historical Zog d47d86b363824c718d9c165124cb55bbed12e0f9.
- Both PRs targeted unstable. The candidate check names recommended for required branch status are **controller-security-regression** and **privileged-socket-regression** respectively.

Native host-install socket/GID/SELinux, mount and reboot acceptance still pending; no production identity, privilege or kernel mount was altered.
