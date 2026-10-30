# Fresh compiler mount/worker-write recovery — exact PID1 successor

**Date:** 2026-10-27  
**Owner:** box-control/root-control Regular  
**Tracked:** [root-control #11](https://github.com/zog144/root-control/issues/11), [host-deploy #5](https://github.com/zog144/host-deploy/issues/5), [host-deploy draft PR #2](https://github.com/zog144/host-deploy/pull/2)  
**Source candidate:** root-control executable+regressions `984b564907f88dccb91a5b2ea3f8a7f8e8151bd8` (successfully tested); required security-workflow successor `75697aa93efb3f31495d226a25bc8ad5d85b8d6e`.  
**Disposition:** source-only correction; **native PID1, complete worker writes, aggregate +32 GiB and six-hour acceptance remain NO-GO**. No new compiler or retained-host operation.

## Recovery from interrupted session

An earlier interrupted root-control implementation already committed worker containment changes through `67510401bcc456e449913b385bcebc9a3f52ff55`: fresh-only `PrivateTmp=False`, root-owned worker-image scratch parents, typed `PrivateMounts/ProtectControlGroups/RestrictNamespaces/LimitCORE`, full child slice under `zogfreshcrossbootstrapoct25.slice`, fixed journal namespace, saved exact worker policy, and a constrained descendant-process inspector. The original shared controller and historical `bad-setting` compiler were not changed.

A subsequent cross-source review found **two actual integration inconsistencies**, corrected here:

### 1. Exact installation bind sources and targets

The current [host-deploy 2026-10-27 protected installer source](https://github.com/zog144/host-deploy/blob/4129ec067a5c25125b0bebb2cb4ba392ccd0671d/docs/host-deploy/FRESH-V3-HOST-WRITE-BOUNDARY-2026-10-27.md) uses:

| Purpose | Actual host-owned source | Active target | Budget |
| --- | --- | --- | --- |
| Project working state | `<Project>/work/state` | `<Project>/state` (host bind) | 30-GiB ext4 |
| Privileged imported build root + registration | `<Project>/work/controller-build-resources` | `/var/lib/zog/build-resources` **only in fresh root-control sidecar mount namespace** | 30-GiB ext4 |
| Fresh guest scratch | `<Project>/work/.zog-runtime/<job>/{tmp,vartmp,run}` | worker guest `/tmp`, `/var/tmp`, `/run` | 30-GiB ext4 |
| Fresh namespace journals and external owner state | independently attested external pool | exact protected persistent/volatile journal binds and owner paths | 2-GiB ext4 |

The original interrupted root-control verifier mistakenly demanded a distinct `attempts` mount and put the copied imported rootfs into the **2-GiB** external pool. That could both reject legitimate hosts and consume log space. The corrected fresh-only `BuildBackend` requires **both** new mount targets in its actual `/proc/self/mountinfo`, compares source/target `st_dev` **and** `st_ino` within the sidecar's mount namespace, requires protected root-owned mount roots and resource directory, rechecks registered input/source/output paths, and rejects unexpected nested mounts. It does not weaken the shared-role behaviour or its storage paths. Fresh registration no longer chmods its root-only directory to 0755.

### 2. PID1 resolves worker-unit paths in the host namespace

A further defect remained after fixing the sidecar bind. The controller copies its immutable prepared rootfs into the sidecar-private `/var/lib/zog/build-resources/<project-digest>/<resource-id>/root`. **PID 1 does not inherit the fresh sidecar's `BindPaths`**. Passing that private spelling as a worker service's `RootDirectory` could accidentally select historical/unbounded host data at the same pathname, or simply fail.

Fresh-only root-control now translates the saved registration suffix to the **PID1-visible, bounded source path**:

```text
/work/controller-build-resources/<project-digest>/<resource-id>/root
```

where `/work` is the absolute protected `/home/zog-cross-owner/fresh-cross-bootstrap-oct25/work` 30-GiB loop-backed mount. The optional private `/dev/null` bind source is similarly translated. A supplied path outside the exact sidecar registration root cannot be translated. Before writing irreversible `start_attempted`, root-control requires that the imported root directory visible through both spellings has identical device **and inode**, is a directory, not a symlink, and belongs to the 30-GiB worker image. Worker `RootDirectory` PID1 readback uses **the exact host-visible path**, not the sidecar alias. This prevents source-only validation of a root which PID1 would execute from an unrelated host filesystem. A later inspection also revalidates the rootfs inode mapping.

## Remaining source/native boundary

The fresh-only unit policy retains `PrivateTmp=False`, explicit quota-backed guest `/tmp`, `/var/tmp`, `/run`, source and output `BindPaths`, `RootDirectory` on the bounded 30-GiB image, `ProtectSystem=strict`, `PrivateMounts=True`, `ProtectControlGroups=True`, `Delegate=False`, `RestrictNamespaces=0`, `LimitCORE=0`, `NoNewPrivileges=True`, `PrivateNetwork=True`, `ExitType=cgroup` and `KillMode=control-group`. The constrained `build_job_processes` reader checks actual fresh parent/service cgroup and invocation identity, but a source/snapshot check is not proof of every descendant process or write on the native kernel.

**Work must still prove, in a disposable Linux/systemd 252 environment using already-authorized resources:**

1. The host-owned installer really mounted the 30-GiB and 2-GiB quota ext4 filesystems and the **exact** Project/state + *sidecar-private* resource binds *before* source import and StartTransientUnit. Inspect PID1 service `RootDirectory` and actual inode/device equivalence in **both** PID1 host and sidecar mount namespaces. Reject fake same-device/different-inode, symlink, foreign nested mount and absent bind.
2. Run a harmless finite worker, inspect each `/proc/<pid>/mountinfo`, `/proc/<pid>/root`, `/proc/<pid>/cgroup`, cgroup subtree, `cgroup.procs` and descendants. Include forks/exec, attempted namespace unshare, foreign cgroup joins, worker UID/GID, protected parent-slice `cgroup.kill`, and cancellation of **only the fresh unit**.
3. Exercise actual writes and ENOSPC in `/tmp`, `/var/tmp`, `/run`, source/output, working directory and all possible caches; verify read-only imported root `/etc`, `/var`, `/home` and other guest paths remain unwritable except reviewed binds. Inspect `/dev/shm`, tmpfs/swap and kernel-generated/core-dump paths for any spillover. `LimitCORE=0` is not an observed core-dump write bound until natively tested.
4. Preserve complete journald@ namespace backing and all related controller/PID1/watchdog/cron/SSM/default journal bytes inside **the total +32-GiB allowance**. Child slice placement and `LogNamespace` alone do not bound those host writers. The independent PID1 hard deadline and cancellation after simultaneous monitor loss/disk-full and reboot must pass; do not silently increase quota, create EBS, relocate the shared journal, or infer available headroom from `du`.
5. Compare old shared daemon PID/InvocationID and the original `bad-setting` fragment/request/record hashes before and after; never reset, stop, replay, repin or cleanup original request `371da99f...`.

**Source CI:** [successful root-control security suite](https://github.com/zog144/root-control/actions/runs/40550176043) and [public Python/wheel suite](https://github.com/zog144/root-control/actions/runs/40550176010) validated the executable implementation at `984b564...`. The updated required-case workflow is at `75697aa...`; review its own checks before declaring final CI accepted.

**Next owner:** host-deploy Regular should adopt the exact **final validated** root-control source pin for fresh v3 only and preserve protected immutable source/UID/Project/host and budget bindings. Work runs disposable PID1/mount/cgroup/ENOSPC/cancellation acceptance, while host-deploy Regular continues the independently unresolved *total* host-write cap. **Stage B cross-bootstrap submission remains NO-GO**.
