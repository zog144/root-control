# Task C November 11 trusted-Host execution — root-control source disposition

**Architecture approved 2026-11-11; source-only. No native SSM, IAM, AWS, S3 or systemd activation.**

The trusted `host-registry` root filesystem, administrator and installed service identities are inside the current trust boundary. Whole-Host rollback, malicious local filesystem alteration and independently forged local installation receipts are not in this Task C threat model.

## Selected executable submission path

- **Host-deploy PR #30** owns the runnable SSM gateway code. Its `generic_pipeline.advance` validates the admitted, frozen image-build task, compiler lane and target, exact operation and source, and generated remote script. It uses the ordinary Host instance AWS role and **one** `Host.submit_command` (`AWS-RunShellScript`, SDK `total_max_attempts=1`).
- The gateway's **existing** `graphics_operation_send_intent` is the selected local authority. It fsyncs a write-once operation ID, target/request/source binding and local intent before the single SSM call. A reply supplies a command ID recorded separately with fsync; lost acknowledgement, crash, invalid/missing local evidence and duplicate requests cannot automatically resend. No S3 storage, signer, independent anchor, separate SSM principal or second owner/trust daemon.
- **Host-install PR #35** stages only the existing direct `host-deploy-gateway` entry point in one root-run `zog-task-c-gateway.service` unit, disabled by default. Its `StateDirectory=host-deploy-gateway` on the existing root filesystem is the intended root-owned local journal. There is no second SSM service or trust service to start.

The older `graphical_task_c_native`, `graphical_s3_installation_checkpoint`, signed v3/v4 source validators, broker and installer/signer constructs on this PR branch are **not selected for the new Task C execution path**. Do not install them, require their S3/signer/mount gates, or accept an existing v3/v4 signed receipt as the new direct gateway admission. These remain historical draft source only; no production pin changes are implied.

## Focused root-control source work

`zog.root_control.task_c_trusted_host.LocalTaskCJournal` is a **testable, unselected alternative** that demonstrates an ordinary root-owned local 0700 directory, `flock`, write-once fsynced intent/result/cancel records, duplicate denial and conservative no-retry semantics. Its Python 3.12/3.13 CI passes; it does not use S3, AWS IAM assumptions, signatures or a new storage device. It is **not a second deployed sender**, and host-install must not install or activate a second service on account of this library. If the shared library has no eventual consumer, it can be removed in source review without affecting the selected gateway; avoid maintaining two local journal authorities.

## Exact tested source contract

- root-control PR #47: `6a545931a79e3f700dbf769b8a87fe33f9a6e620`, trusted local journal workflow `43077286924`, Python 3.12/3.13 PASS.
- host-deploy PR #30: direct trusted Host gateway code plus dedicated trusted-Host source workflow; pin the reviewed head at native Work acceptance.
- host-install PR #35: exact three-owner `task-c-trusted-three-owner.yml` source workflow, Python 3.12/3.13 PASS; native import check and selected one-service unit.

## Native cutover remains a separate Work operation

Verify real installed package/interpreter and selected commit IDs, existing retained registry Host identity, original gateway and SSM command records, the current compiler target and effective instance IAM role, and existing journal ownership. The previous gateway may have used `DynamicUser=yes`; do not start the new root-mode gateway concurrently or reset its request/command history during ownership reconciliation. Then run bounded native duplicate, crash/reboot/lost-ack/cancel validation before a separately authorized first Fonts submission.

**Native status: HOLD.** No extra EBS, S3, signer, registrar, new AWS principal, native SendCommand or Fonts dispatch is part of this Regular source task.
