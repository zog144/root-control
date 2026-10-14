# Optional build-job journal synchronization

Status: opt-in implementation; disposable-host systemd acceptance passed.
Compiler-host deployment must preserve existing resource-limit and workspace
cleanup contracts and validate a new job before resuming compilation.

This covers finite build jobs only, not application services. Journald remains
the only log store and boot/invocation matching is unchanged. A barrier result
is evidence of synchronization, not a guarantee that journald retained every
message (rate limits, storage failures and retention remain independent).

## Deployment requirements

Linux with SO_PEERPIDFD (introduced in 6.5), systemd supporting the existing build
API, a trusted host Python installation and `/usr/bin/busctl`, `journalctl` and
`readelf`. Enablement probes peer-pidfd support and rejects a dynamic helper.
The helper source is included as `src/zog/root_control/native/journal-wait.c` in Python
package data. Compile on the target architecture with a static C toolchain:

```sh
cc -static -O2 -Wall -Wextra -Werror \
  box-control/src/zog/box_control/src/zog/root_control/native/journal-wait.c -o /tmp/journal-wait
install -d -m 0755 /usr/libexec/zog
install -o root -g root -m 0755 /tmp/journal-wait /usr/libexec/zog/journal-wait
```

These commands assume a reviewed source checkout and trusted build toolchain.
Do not compile build-provided source as the installed helper. Never set setuid
bits or file capabilities. Executable and parent directories must be root-owned,
not symlinks, and not group/world writable. No compiled binary is stored in Git.

Set `ROOT_CONTROL_JOURNAL_BARRIER=1` in the **host root-control service** and
restart it before submitting new jobs. This is deployment configuration, not a
caller-controlled build option. Leave unset for existing behavior. The daemon
starts the dedicated broker before its management listener. An unavailable helper,
unsupported kernel, untrusted deployment path or second active broker blocks
startup. Minimum build termination grace when enabled: three seconds.

## Boundary and protocol

The build service retains its non-root UID/GID, no capabilities, NoNewPrivileges,
private network, read-only root and writable-workspace restrictions. Its exit hook
is mounted read-only at `/run/zog-journal/wait`. It runs with `no-env-expand` and
`ignore-failure`; **no privileged or no-setuid flag** is used. It is static so
build libraries, LD_PRELOAD and Python settings cannot select its dependencies.
It requests synchronization over `/run/zog-journal/socket`, then exits within a
two-second alarm deadline. It refuses to run as root and writes no log messages.

The socket is a dedicated endpoint, not the root-control management socket. Its
fixed request is exactly a 64-character hexadecimal registration token plus LF;
the one-byte reply is `1` for synchronized, `0` for unconfirmed. The token is a
lookup identity, not authentication. Extra data cannot invoke a second operation.
The broker checks kernel peer UID and SO_PEERPIDFD liveness against systemd's
current ControlPID, unit identity, transient flag, stop-post state, boot and
invocation identity. A disclosed token or another process under the same UID is
insufficient. No command, environment or filesystem path is accepted over this
endpoint. Missing/unreadable systemd evidence fails closed.

A maximum of two requests can be in service, with a bounded backlog and a 0.2s
request-read timeout. Excess requests close without success. The host command is
fixed `/usr/bin/journalctl --sync`, with a fixed environment, cwd `/`, no input,
and a 0.8s execution timeout. Systemd queries have individual 0.3s bounds.
Concurrent load can therefore produce unconfirmed barriers rather than extend
job shutdown indefinitely. This is intentional; no completeness claim is made.

## Durable results and lifecycle

Root-owned registration files live under `/var/lib/zog/journal-barriers`.
Registration is saved before service start; invocation binding and `attempted`
are saved before synchronization. `synchronized` is saved before a positive
reply. Failed synchronization records `unconfirmed`. A crash after `attempted`
does not cause an automatic retry; repeated authenticated requests cannot repeat
the operation. File-write failures never receive a positive acknowledgment.

Build inspection exposes the additive `journal_barrier` field:

```json
{"status":"synchronized","boot_id":"32 lowercase hex","invocation_id":"32 lowercase hex"}
```

An unconfirmed broker result can also contain a bounded `reason` code.
Statuses are `not-enabled`, `pending`, `attempted`, `synchronized`, and
`unconfirmed`. Pending/attempted records observed after the service disappears
or terminates are presented as unconfirmed. The disabled status contains only
`status`. A status is separate from `outcome`, `exit_code`, `signal` and
`service_result`; synchronization failure does not fabricate compilation failure.

The socket's parent directory is bound read-only, allowing a restarted broker's
new socket inode to be visible to existing jobs. Management and broker requests
use separate worker pools, avoiding a StopUnit/wait-for-hook deadlock. Existing
unit identities are never relaunched to repair logs. Across reboot, missing or
incomplete barriers remain unconfirmed. Required durable state corruption still
blocks normal inspection/recovery; it is not treated as successful synchronization.

Broker records are removed when the associated privileged build resource is
forgotten. An interruption between registration and saving the token can leave an
orphan registration; automatic orphan reclamation is deferred. Do not delete
pending records while diagnosing uncertainty. Default-disabled jobs are unchanged.

## Acceptance gate

`acceptance/journal_barrier_live.py` is a disposable-host harness. Eleven cases
passed on Amazon Linux 2023, systemd 252 and kernel 6.18: delayed journald,
short success/nonzero/child/signal output, timeout, cancellation, hostile
LD_PRELOAD and rootfs substitutions, disclosed-token impersonation, broker restart,
broker loss, durable exit recovery and concurrent jobs. It briefly suspends host journald with an
independent resume process. It provisions an unprivileged fixture account and
needs a static compiler and the installed helper. Do not run on a shared host.

## Durable exit evidence

The authenticated stop hook records PID1's main-process exit code/status, service
result, boot/invocation and bounded launch-property snapshot before attempting
journal synchronization. No exit information is accepted from the build process.
This record is independent of the root-control D-Bus connection's AddRef lifetime.
A synchronization timeout does not erase an already saved process result.

After systemd confirms the unit is absent, root-control can return that evidence
only when job/unit/UID, current boot, invocation and immutable launch properties
match. Box-control persists the recovered outcome before cleanup and reports
`exit_evidence_source: "exit-hook"`. It never starts another process to recover
logs or an exit code. Live conflicting units and mismatched evidence remain faults.
A unit disappearing during a multi-property query requires an independent absence
check before this fallback is permitted.

If the broker is unavailable at exit, its write fails, or the host reboots before
an exit record is saved, the original outcome can remain unknown. Old-boot hook
records are not adopted as current-boot process evidence. Explicit cancellation
can drain/release an absent unknown job without relabeling it successful. The
feature still requires opt-in; default-disabled jobs keep their existing behavior.

The disposable-host harness no longer holds independent unit references. It tests
SIGKILL of root-control before exit, SIGKILL after exit but before result collection,
and broker absence through exit. Reboot, production rollout and long-duration
load testing remain separate gates.

## Compiler-host compatibility

The optional positive `stack-maximum-bytes` request limit sets both systemd
`LimitSTACK` and `LimitSTACKSoft`; unknown limits remain rejected. On resource
release, stopped source/output workspace directories return to the project owner.
File content, ownership and modes are preserved. Active registrations, overlapping
workspace registrations, symlinks and mounts block directory reclamation.
