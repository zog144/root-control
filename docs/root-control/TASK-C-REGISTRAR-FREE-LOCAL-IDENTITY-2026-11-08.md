# Task C registrar-free local installation identity — selected source contract

2026-11-08 · Source candidate only; native service placement and SSM remain HOLD.

## Decision

Ordinary host-install and host-identify installation, startup, standalone identity recovery, directory-backed `/state` preparation, and future upgrades require **no Command Center, registrar, registered-installation signature, or new observer-signing process**. Host-install PR #35 owns the locally authenticated, descriptor-retained STATE backend and its marker/configuration reconciliation. A local installation has no implicit control grant.

A *separately opted-in Task C protected remote-operation service* may select that same local Host without a registry signer, but must still independently prove real Host/STATE identity and storage placement, obtain the **existing** operator-signed installation-storage establishment approval, authenticate the signed installer commit and external checkpoint anchor, and verify independent approvals for each original GitHub operation. None of these Task C-only approvals authorize the Host boot process, local identity generation or `/state` creation.

## Source contract

- **Explicit versioned selector**: `zog-task-c-local-installation-selection-v1`, selected only by runtime schema `zog-protected-task-c-installed-runtime-local-v1`. Never auto-select from a missing registry, bad signature or gateway-controlled flag. Existing `zog-task-c-registered-installation-v1` continues with its independently pinned public key and original validation.
- **Separate stable local scope**: opaque Host ID/fingerprint/target digest/installation ID/STATE ID plus the actual existing host-install installation and STATE UUIDs as **separate strings**, without UUID-to-opaque conversion. It does not include Command Center registry/controller IDs. The local record is protected-installed metadata, *not a signature, authorization or evidence of native installation*.
- **Existing protected storage approval**: operator's Ed25519 approval still covers the hash of that exact locally selected record, stable installation storage scope, account/bucket/prefix, immutable genesis, distinct S3 writer and GetObject-only reader roles, anchor identity and retention disposition. The native installer-signed commit remains a separate Task C storage establishment record, not a newly introduced general Host registrar. Historical field `registry_sha256` in this v3 S3/anchor wire format is the digest of the **selected installation record** for local mode; it does not mean it was registry-signed.
- **Fresh direct STATE observation**: root-control owner and separately privileged broker invoke `zog.host_install.state_inspect.inspect_live` directly on the same trusted Host. It verifies actual /state descriptor, mounted-volume vs XFS/ext4 root-directory, UUID/PARTUUID, mount IDs/devices/inode/ownership, marker bytes, nested mount exclusion and recheck. In local mode it also requires actual host-install installation/STATE UUIDs to equal the explicit, operator-approved selection. No signed mapping, observer public pin, freshness token, caller boolean or gateway JSON authorizes a claim. Standalone host-install `control_authority=None` remains valid; its absence is **not** a Task C grant. Task C grant originates separately in signed original-operation policy.
- **Original operation fence unchanged**: GitHub original event issuer verification, operator-signed operation-specific approval, distinct owner/broker/GitHub issuance custodians, installation/checkpoint binding, protected monotonic S3 claims and per-scope revocation, one-time SSM SendCommand attempt and uncertain-send denial, reboot and recovery semantics, authenticated local peer IPC, read-only broker and independently protected owner SSM session.
- **No permission escalation**: host-deploy gateway public pin `APPROVED_PIN_SHA256=None`; native owner send/broker admission constants remain disabled. Existing gateway-to-owner-to-SSM path and trusted-shared-Host threat model are unchanged. GitHub Actions OIDC is SQS-dispatch only.

## Exact reviewed source snapshot

- root-control PR #47: `403b31c7936ade614760e28e949ad66343e17260`.
- host-deploy PR #30: `63c222ef71a3e0b0c9a1fb0abb8072e564d4e906`.
- host-install PR #35: `b08f074727e21926cb6460766b53f0d0696855e5`.

Source tests: [root v3, 147 tests per Python lane](https://github.com/zog144/root-control/actions/runs/42491935243); [root original owner, 141/lane](https://github.com/zog144/root-control/actions/runs/42491935245); [root storage, 76/lane](https://github.com/zog144/root-control/actions/runs/42491935256); [root legacy readonly, 63/lane](https://github.com/zog144/root-control/actions/runs/42491935261); [host-deploy exact 3-owner v3, 141/lane](https://github.com/zog144/host-deploy/actions/runs/42491987610); [host-deploy legacy v2, 115/lane](https://github.com/zog144/host-deploy/actions/runs/42491987616). All passed Python 3.12 and 3.13. Source fixtures use synthetic identity, operator keys and checkpoint; none authenticate the actual registry Host.

## Still required before native admission (Work)

1. Separately approve *remote Task C enrollment* on the selected Host, authenticate the real local existing host-identify key/fingerprint, independently selected opaque Task C IDs, AWS IID/account/region and selected host-install installation/STATE UUIDs. No newly enrolled registrar/observer signing authority. Reconcile the exact current PR #35 wheel/RECORD and local directory marker.
2. Authenticate actual `state_inspect.inspect_live` kernel/descriptor readback and retained filesystem topology, selected root directory or dedicated ext4 mount, original identity retention and safe restart/reboot.
3. Establish the **two distinct independent** protected owner ledger and authority mounts, immutable new S3 genesis/history/retention, external anchor and original operator-signed storage establishment/installer commit. Root-directory `/state` cannot stand in for either independent Task C mount.
4. Inspect exact installed root-control/host-deploy/host-install module bytes, systemd service/socket source, root-only owner/readonly broker credentials and gateway IAM denial. Prove true authenticated IPC, per-operation approval, revocation, claim collision, lost SSM acknowledgement and reboot with no repeat send.
5. Only after a separate real operator installation acceptance may native owner/broker or graphical SQS/SSM activity proceed.

**Disposition: source implementation and exact-head cross-owner CI PASS; native identity, mounted storage, signing custodian provenance, credential sessions and SSM remain HOLD.** No file creation/mount on the registry Host, credential or key issuance, AWS IAM/S3 change, Fonts issue, SQS submission or SSM command was performed by these source changes.
