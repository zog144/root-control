# Boot A restrictive immutable-root import: merged source and exact installed-byte adoption

Date: 2026-10-28. Owners: root-control maintainer (source), host-deploy native installer owner (if applicable), **image-build Work** (retained installed verification/retry).

## Reviewed and integrated source

- [root-control PR #15](https://github.com/zog144/root-control/pull/15) **MERGED into unstable**.
- Exact merge commit: `9e1d9043083a213dd819c2e7ce9583c8d28234ac`.
- Exact reviewed PR head: `25b455f911dfa4370d518c2cf3de1af2b84a4e0d`.
- Exact `src/zog/root_control/build.py` Git blob identity: `1dc93adad7f1d2905095b1ee9ca1a52e4733d5dc`. A Git blob SHA-1 is not an installed SHA-256; calculate and compare SHA-256 and wheel RECORD on the Host during admission.
- Updated immutable importer `BuildBackend._tree(immutable=True)` applies only `mode & ~0o222`; no mandatory world read/search bits. Preserve root:root 0000 `/state` and `/applications`, 0700→0500 private directories, 0600→0400 private files.
- Privileged regression uses *real* root `chown`/directory `fsync`/copy and `register`, checks source unmodified, durable registration, idempotence and read-only transient unit property construction; does not start PID1.
- Merge-head exact CI: [privileged 40772915988](https://github.com/zog144/root-control/actions/runs/40772915988) **PASS**; [public 40772915997](https://github.com/zog144/root-control/actions/runs/40772915997) **PASS**.

## Mandatory exact installed-byte gate BEFORE Boot A retry

1. Native controller owner independently read back the current Host identity, protected installation, actual root-control process/cgroup/socket, installed Python interpreter, installed Python module and wheel/`RECORD` hash. Reject stale/mismatched source or unexpected symlink/ownership/execution origin. **No claim is made that merge == installed.**
2. Independently build/install the exact reviewed root-control commit in the existing protected installation pathway (do not overwrite an immutable generation or replace the host's global source). Read back `zog.root_control.build.__file__`, stat/hash the installed file bytes and compare to the exact checkout module bytes from the merged commit, including Git blob/sha256 comparison, and validate the corresponding `RECORD` entry. Confirm installed process imports *those* bytes and source `permissions &= ~0o222`.
3. Host-deploy's separate fresh compiler binding currently still contains `FRESH_ROOT_CONTROL_REVISION=4a6ef2252c06a92cbab2550c4fec24a48438a4ba` at `regular/toolchain-gateway-20261019` (inspected 2026-10-28), **not** the newly merged `9e1d9043...`. That pin requires a separate exact consumer/CI/installed readback review if this lane is the actual Host issuer. Do not silently rebind historical jobs or conflate the fresh compiler and image-build Boot A lanes; check the actual controller owner's binding first.
4. Capture all previously failed attempt IDs, source pins, package outputs, execution receipts, and frozen inputs unchanged. A source change is a **new successor operation identity**, not permission to mutate/relaunch an old request. Check failure/recovery semantics before initiating the next supported operation.
5. Before a worker executes, inspect the **actual imported** immutable root tree: `/state` and `/applications` have uid:gid 0:0, mode 0000, are empty, are not symlinks or writable bind overrides, and are located on the exact bounded resource root; inspect private directory/file modes and executable. Verify the registered root's path/inode identity, owned source/output mounts and a root:root durable `registration.json`. Abort if old 0555 mode import recurs.
6. Independently verify selected read-only transient worker properties and native PID1/mount identity. Do not infer a worker can run just because source CI generated correct D-Bus properties. Any root-control/host-deploy worker containment/aggregate budget gates still open under [root-control #11](https://github.com/zog144/root-control/issues/11) and [host-deploy #5](https://github.com/zog144/host-deploy/issues/5) remain **separate hard holds** for the fresh compiler lane.

## Image-build Work: narrow new Boot A retry (not executed by Regular)

- Image-build source: `unstable@ce4b1d754d21bfe629eca8df23af3ddc184525f4` as last observed, or an independently reviewed newer exact successor. Do not assume source has changed from historical failed operations.
- Retain the exact parent `45a81ec3ea473bfa397e546b5c0ec1ae306bf00cb864eaa9a86d94c13c623f2e`; no full rebuild, silent overlay change, or original parent mutation.
- Retry only through the supported, fresh, source-corrected image-build operation (not an old idempotency key), retaining accepted upstream package/EFI evidence. Rebuild accepted build inputs only if supported artifact re-import is unavailable; do not fabricate release/cache provenance.
- Verify the *actual* installed-verification code path through durable `prepared.json` and `verification.json`, output directory durability and inventory, with resident mountpoint modes 0000 throughout registration/import and verification output, and record exact Python invocation/systemd identity.
- Return canonical Boot A verification PASS/MISSING, exact accepted `systemd-bootx64.efi` hash/provenance, source and installed-controller hashes, archival/build-record and successor immutable generation only if actually published. Keep the foreign AL2023 kernel/initramfs/modules acceptance separate.
- No UEFI disposable boot, EC2 creation, image activation, global PID1 reload, shared host replacement, new compiler bootstrap or unapproved native deployment is authorized by this source merge.

**Disposition:** PR merged and source verified. Native installed-byte adoption and Boot A retry are still pending image-build Work / protected installer owner, and must be recorded with native receipts—not inferred from this document.
