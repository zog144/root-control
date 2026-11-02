# Independent selected certificate broker execution-fence source security review

2026-11-02 · source-only, no installed Host changes.

**Exact reviewed original heads:** root-control PR #23
`32ec525903834d3a707e5aace408cf4dbee32d83`;
box-control PR #15 `baca7f815974dbf685950c0c7e78f693dd0a96e2`;
host-install PR #15 `437b4448b7af7de5f4237cdf56fac924c833d279`.
The proposed **additional** root-only lock correction is deliberately on a
separate review branch, not silently installed or selected by host-install's
source/RECORD trust digest.

## Independent review outcomes

**Selected admission:** box-control rechecks committed projection and pending
or final tombstone before mutation; protected root-control
`BusctlSystemdBackend.start_service` independently selects renew/inspect/stage
and persists a commit-bound `admission-uncertain` epoch record before PID1.
There is no unfenced alternative for selected `issue`, `renew`, `inspect`
or `stage`. It observes the same invocation under its protected flock.

**Cancellation race:** box-control's `cancel_launch` holds the actual ProjectLock
and cannot falsely cancel a launch with saved operation evidence; it returns
`pending` or `uncertain` rather than erasing the selected operation.
Root-control's `reconcile_selected_issuer` does not infer a stopped process
from cancellation or StopUnit acknowledgement. It requires the original
controller unit and matching InvocationID before stop/release and independently
authenticated cleanup evidence before terminal status. Missing InvocationID
remains a blocking `cancel-pending` record, never a guessed kill.

**Revocation interleaving:** a public broker RPC may see the old projection
between the durable private `revoked=true` epoch update and final/pending
tombstone creation. This is an advisory stale-read interval, **not** an
execution admission escape: root-control refuses any selected StartTransientUnit
after private revocation and preserves all outstanding cancel-pending operations.
The three-owner synthetic test demonstrates that exact interval. Once any
pending marker exists, the broker denies even a malformed partial marker.
On publication loss the private ledger never clears the revoked bit or
restarts an operation; an identical authorized marker can be retried.

**Reboot and lost PID1 acknowledgement:** admission-uncertain is written before
dispatch; a lost response prevents duplicate request execution and a new
request while uncertainty remains. A subsequent boot records a new boot ID
and turns nonterminal operations into cancel-pending, preserving their
original identity. Stopped/clean evidence remains an independent native gate.

## Source correction found

Original root-control `IssuerExecutionFence._ensure_lock` could silently
re-create `selected-issuer-execution.lock` if its file disappeared while the
durable `selected-issuer-execution.json` survived. This changes the lock
inode for a new fence object and risks dividing protected writers between
the old and new lock identities. The isolated correction:
- refuses first-use lock creation if any durable ledger entry already exists
  (including an invalid or symlinked state entry);
- pins the stable lock inode to the lifetime of each fence instance;
- rejects replacement while held instead of using a second writer lock;
- adds tests for intact, already-revoked and substituted-inode situations.

No ledger, caller-supplied directory, recovered state or lock is reset by
this correction. A malicious privileged actor capable of rewriting the
entire trusted root installation remains outside this *source-only*
guarantee, and independent installed provenance/native reboot acceptance
remain necessary.

## Source evidence and native stop condition

Existing original source CI: root-control selected fence, public source and
privileged socket tests PASS at the original PR #23 head; box-control
certificate controller integration PASS at exact PR #15 head; host-install
protected recovery source PASS at exact PR #15 head. The review's own
Python 3.12/3.13 CI checks out box-control/host-install immutable companion
heads and runs real source code, while only unrelated historical Zog support
packages are overlaid. Tests never create a real systemd service, certificate,
STATE or protected broker.

The original source pins remain unchanged. Candidate review correction must
be independently accepted and re-pinned before protected native installation;
*review CI green is not an authorization to repin*.

**Remaining native NO-GO:** actual root-owned lock and RECORD evidence,
native PID1/InvocationID/StopUnit/cgroup cleanup, cold boot with an incomplete
tombstone, missing-provenance recovery-only authorization, authentic issuer
signature/UID/STATE provenance, and real certificate lifecycle acceptance.
