# Task C — selected graphical operation owner source reconciliation (2026-11-04)

Input: [host-deploy exact Task C handoff](https://github.com/zog144/host-deploy/blob/c3e597f09965680587c97dbe6f7b5ee18d52e9a9/docs/host-deploy/GRAPHICAL-TASK-C-SOURCE-NATIVE-HANDOFF-2026-11-04.md) at `c3e597f09965680587c97dbe6f7b5ee18d52e9a9`. Root-control baseline draft PR #33 `6cf1e3064f77a6aefe17bf75f50c4b8d83a15762`.

**Critical incompatibility:** the Task C gateway selects `/run/zog/graphical-operation-owner.sock`, AF_UNIX `SOCK_STREAM`, canonical newline frames and original GitHub provenance, with independent domain-separated preflight ID; PR #33's initial native executable selected `/run/zog/graphical-owner.sock`, `SOCK_SEQPACKET`, and a different original request plus approval RPC. These are NOT interoperable. Do not install both as independent authority endpoints or silently accept the v1 unsigned response.

## Newly implemented source

- Strict bounded `zog-graphical-owner-ipc-v1` Task C frame parser (original Github issue, trigger actor, repository, canonical original request hash, immutable original stage/ordinal/remote+binding hashes, nonce; no script, AWS credentials, caller-supplied peer or sender).
- Independently operator-signed, fixed original-operation mapping from each IPC identity to its selected root-control PR #30 request SHA and **distinct** original operator approval. Preflight ID must be SHA256 of `zog-graphical-original-preflight-v1:<request-id>:<stage-id>` truncated to 32 hex and match its separately selected stage sibling.
- Kernel peer `SO_PEERCRED` UID/GID with strict stream framing (source preadmission only); no positive original send, preflight authenticated=true or reusable ticket. Real installed peer must additionally authenticate exact binary/process/cgroup/boot and source/RECORD/current authority.
- Fixed root-owner ledger and checkpoint `flock` now use freshly opened independent file descriptions for each critical section, while permanently retaining the original lock inode as a substitution witness. `dup` of one retained FD did not provide in-process mutual exclusion. Tests assert actual competing-thread lock exclusion on both domains.

## Explicitly still NOT implemented / native NO-GO

1. A single accepted root service that implements this stream IPC and returns a fresh independently signed current-authority/SSM result proof; the existing current root executable remains hard-disabled and cannot send SSM. The Task C v1 client currently rejects all signed-v2 responses and preflight always denies. Until protocol convergence and external highwater source are integrated, no positive execution is safe.
2. Independent, nonrollbackable current highwater/CAS beyond separate durable files; origin approvals must be installed and authenticated against the actual GitHub issue and current Host/installation/STATE, not just the gateway's claimed values.
3. Owner-only AWS STS credentials under service principal; actual gateway IAM/STS/IMDS denial; exact source and protected mount/protected signer installation. File/source tests are not native permission evidence.
4. Protected preflight claim, *actual* original SSM preflight result readback, signed current owner observation, and stage send under the same revocation lock. No source mock may authorize a live stage.
5. Native Work needs direct-send denial as deployed gateway UID, distinct owner one-send proof, concurrent/ACK/cancel/revoke/rollback/reboot acceptance.

The draft defines source contracts, never creates or activates a systemd socket, role, AWS credentials, operator key, canonical STATE, nonrollbackable authority or graphical build. Unmerged; production pins unchanged.
