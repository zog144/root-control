# Fresh compiler: exact worker-write, namespace and descendant containment — source correction

> **Successor correction (2026-10-27):** Host-deploy's newer `prepare-work` binds `<work>/state` at **`<Project>/state`**, not at `<Project>/state/image-build/attempts`. Its new transient sidecar binds **`<work>/controller-build-resources`** to `/var/lib/zog/build-resources` within the new sidecar's own mount namespace, **not** to the 2-GiB external accounting pool. Root-control corrected both source bindings at `7619a10db64d80b47cb02bdc035bd5631ce5b9bc`, verifies exact mountinfo targets and **matching `st_dev` + `st_ino`**, and retains root-only resource permissions. Previous path/table instructions below describe the pre-host-deploy-4129ec proposal and are superseded by [the exact mount correction](./FRESH-COMPILER-MOUNT-BINDING-SUCCESSOR-2026-10-27.md). Historical jobs stay unchanged. Actual native proof and total 32-GiB host-write enforcement remain NO-GO.

**Date:** 2026-10-27  
**Owner:** root-control Regular / box-control controller-contract reviewer  
**Tracking:** [root-control #11](https://github.com/zog144/root-control/issues/11), [host-deploy #5](https://github.com/zog144/host-deploy/issues/5), [host-deploy draft PR #2](https://github.com/zog144/host-deploy/pull/2)  
**Root-control executable/test source:** `01b2d0031d1830ed5734e2e8c788dde7005f34d4`  
**Companion:** `box-control@b7934882cfacd2fbfd60c7964713ed3dde7f9460` unchanged  
**Disposition:** fresh-only source correction **CI PASS**; **native containment/aggregate host budget remain NO-GO** until independent Work acceptance. This is not permission to install or submit.

## 1. Confirmed escapes in previous root-control source

- `BuildBackend` persisted imported build root, registration JSON, job records, device/profile inode and cleanup metadata by default under `/var/lib/zog/build-resources`, **outside** either bound image. Copying the root could allocate arbitrarily on the host.
- Registration accepted any paths lexically under `<Project>/state/image-build/attempts`. The worker image's `work` mount was *not* an authoritative binding of that path; independently writable source/output could still be host-backed.
- `PrivateTmp=yes` uses host-backed private `/tmp` and `/var/tmp` on the target systemd version. These writes are not constrained by the worker cgroup or the 30-GiB image. Writable `/run` and indirect paths also required proof.
- The prior name-bound `Slice` and `ControlGroup` checks did not themselves prevent the unprivileged child from attempting to create or join new namespaces or write cgroupfs, nor did the read-only `build_job_processes` endpoint explicitly validate the fresh child hierarchy.
- Moving scratch binding sources under the **worker-owned output** was rejected during this pass: the build UID could rename the parent after validation. The implementation therefore uses a root-owned scratch parent on the fixed 30-GiB image.

These are actual source-policy gaps, not evidence that a historic/production worker escaped. The already published journald source correction remains separate; PID1/default journals, cron/SSM and host-owner writes are **not** automatically covered by worker isolation.

## 2. Reviewed source contract

**Protected fixed mount topology.** The fresh `build-only-project-v1` backend uses only these compiled constants; no RPC changes or arbitrary caller-controlled paths:

| Role | Fixed host path | Required backing |
| --- | --- | --- |
| 30-GiB worker image mount | `/home/zog-cross-owner/fresh-cross-bootstrap-oct25/work` | Independently attested, fully allocated 30-GiB loop-backed ext4 |
| Attempts source/output bind target | `/home/zog-cross-owner/fresh-cross-bootstrap-oct25/state/image-build/attempts` | **Exact kernel mountinfo entry** bind-mounted from the worker image; st_dev matches the 30-GiB mount |
| 2-GiB owner/journald image mount | `/var/lib/zog/host-deploy/fresh-cross-bootstrap-oct25/external` | Independently attested, fully allocated 2-GiB ext4 |
| Privileged build registration and imported root | `<external>/artifacts/build-resources` | Pre-existing directory on **that same** bounded 2-GiB image |
| Fresh transient guest scratch sources | `<work>/.zog-runtime/<32hex-job>/{tmp,vartmp,run}` | Actual directories on 30-GiB image, trusted root-owned and non-group/world-writable ancestors, only leaf directories worker-owned |

Before **registration**, the privileged backend checks two actual mountpoints, root:root protected mount-root modes, exact attempts mountinfo entry (not `os.path.ismount()`, which cannot reliably detect a same-device bind), matching mounted filesystem device numbers, non-symlink and canonical source/output/root paths, and the absence of unexpected nested mounts under registered writable inputs. It does not silently allocate the registration root on the old host filesystem. Each `area()` and `load()` access, including inspection, cleanup, cancellation, release, reclaim and forget, rechecks backing and the exact saved inputs. Removing any verified mount therefore fails closed rather than falling back to an unbounded host path.

**Fresh guest writable paths.** `PrivateTmp=False` **only for the fresh compiler** and fixed typed `BindPaths` map quota-backed scratch leaves into guest `/tmp`, `/var/tmp` and `/run`. Source/output remain explicit bound mounts. `ProtectSystem=strict` stays in place. The imported root must provide safe ordinary bind destinations (not symlinks), including `/var/tmp`; a conflicting rootfs needs corrected source, not a weakened mount check. Scratch parent/job directories must be verified root-owned before any child creation; leaves are nonroot worker-owned with mode 0700 and cannot be renamed by the worker through the protected parents. `PrivateDevices=True` / API VFS are retained; native inspection must confirm they introduce no unbudgeted persistent backing or swap spill.

**Fresh descendant/namespace protection.** The finite service retains the exact source-bound parent `zogfreshcrossbootstrapoct25.slice`, child `zogfreshcrossbootstrapoct25-build<job>.slice`, service `Slice`/full `ControlGroup`, `Type=exec`, `ExitType=cgroup`, `KillMode=control-group`, `Restart=no`, `NoNewPrivileges`, `CapabilityBoundingSet=0` and separate worker UID/GID. Added fresh-only typed PID1 properties **`PrivateMounts=True`, `ProtectControlGroups=True`, `Delegate=False`, `ProtectKernelTunables=True`, `RestrictNamespaces=0` (deny new namespaces) and `LimitCORE=0`**; `build_observe` requires exact PID1 readbacks. These settings aim to prevent worker-created namespace mounts, cgroup delegation/migration and host core-dump writes. Unsupported properties, kernel enforcement failures and mismatches must block native admission.

The authorized `build_job_processes` reader now enforces the exact protected **parent/child/service ControlGroup** and saved InvocationID before cgroup-v2 process traversal. A moved or substituted worker results in an integrity fault and no foreign process disclosure. The reader is explicitly a bounded **non-atomic snapshot**, not proof of every PID's lifetime or mount namespace.

**Legacy** shared `root-control`, ordinary non-fresh builds, original `ExecStartEx` bad-setting compiler and all historical records/source bindings remain untouched. No general root-control mount/cgroup operation has been added to the RPC surface.

## 3. Required host-deploy Regular integration changes

1. Adopt `root-control@01b2d0031d1830ed5734e2e8c788dde7005f34d4` **in fresh v3 only**, after independent source/installed-byte review. Keep PR #2 draft and historic pins frozen.
2. Host-install/host-deploy's existing protected root owner must create and attest the **exact bind mount** of a directory on the 30-GiB image to `<Project>/state/image-build/attempts` before the controller can register, and precreate `<external>/artifacts/build-resources` as root-owned inside 2 GiB. These are hard startup/registration prerequisites; a pathname or `st_dev` comparison alone does not establish the image's loop-back file provenance.
3. Provision and attest root-owned `<work>/.zog-runtime`; do not allow the build UID to rename the scratch root. Audit `/var/tmp` bind target from the exact prepared image and all parent/inode modes. Bind mounts must survive across authorized sidecar start and be reattached to **the same** backing after reboot; no foreign host mounts or automatic fallback.
4. Keep the **total 32-GiB** guard including the 30+2-GiB preallocations, journal namespace persistent/volatile files, root-control resource imports, controller and watchdog logs, host PID1/default journal, SSM, cron, transient unit state, artifact metadata, inodes and volume metadata. The source does NOT prove those other components are bounded; missing evidence is an explicit NO-GO.
5. Retain the existing six-hour overall UTC/monotonic deadline, crash-safe exact-new-request cancellation and no-new-EC2 conditions. No automatic reboot continuation, second submission or original compiler recovery is authorized.

## 4. Work: mandatory native disposable Linux proof

Use the existing permitted disposable host/systemd environment and **do not** run a shared production PID1 daemon reload. Collect before/after original request/job/unit/fragment hashes and shared controller PID/InvocationID; no modification to the old `bad-setting` unit.

- Verify exact installed root-control binary/modules and box-control source, authenticated dedicated socket, Project/passwd UID/GID and parent PID1 source. Check both actual loop-backed ext4 backing files with `losetup`, `findmnt`, `statvfs`, `st_dev`, inode and mountinfo; validate bind mount at the *exact attempts path* and imported root/registration on external. Negative: no bind, wrong device, nonroot/writable fixed mount root, nested foreign mount, symlink source/output, missing external image and reboot reattach all deny registration without a host write.
- Start **only a harmless disposable finite worker** in the exact child slice and check **all** inherited `/proc/<pid>/cgroup` paths and `cgroup.procs`, recursively, with start-time identity/InvocationID. Inspect actual PID1 `PrivateMounts`, `ProtectControlGroups`, `Delegate`, `RestrictNamespaces`, `LimitCORE` and actual children after fork; test attempts at `unshare`, mount, writable cgroupfs and cgroup migration. Do not infer complete descendant placement from the controller service's own cgroup or from source tests.
- Inspect **the worker process's mount namespace** `/proc/<pid>/mountinfo`, `/proc/<pid>/root`, and `/proc/<pid>/mounts`: expected `RootDirectory` on 2-GiB external, `/image-build/source` and `/image-build/output` on 30 GiB, `/tmp`, `/var/tmp` and `/run` bound from root-owned scratch tree on 30 GiB; file and inode/disk-growth probes must show these writes never change unrelated host devices. Include `/dev/shm`, `/dev`, proc/sys/API VFS, tmpfs/swap, `$HOME`, `/var`, user-created symlinks/hardlinks, huge stdout/stderr, core dumps, fork/exec and systemd native logging.
- Test loss of each loop image/bind mount, path/symlink substitution and wrong PID1 property; demonstrate fail-closed inspect/cancel/cleanup/reclaim without touching old/foreign services or host storage. Demonstrate hard 32-GiB aggregate exhaustion and forced 21,600-second expiry under cron/watchdog/sidecar failure, plus only-new-parent `cgroup.kill` and exact historical evidence preservation.
- Repeat bounded fixtures for cancelled, failed, terminal and reboot-recovered states; verify no autonomous replay and no unsupported journal-barrier evidence claims.

**Disposition:** source correction **PASS**, **native Stage A/Stage B compiler admission NO-GO**. Only after ALL separate host-deploy, controller and Work gates are accepted may the previously user-authorized **one** fresh `toolchain.submit(cross-bootstrap)` be issued. This report does not install a unit, mount a volume, create AWS resources or execute the compiler.
