# Source closure: issuer + Task C + inherited-user builds

This branch combines the previously selected issuer-capable root-control
systemd lifecycle (including credential inspection, mutation fencing and
reconciliation), the existing Task C trusted-Host journal and the no-account-
selector finite build backend. Box-control must be the issuer-enabled companion
that also removes build UID/GID selection. Do not reuse a separate source
checkout to mask missing modules.

The selected compilation process uses its existing execution context, including
UID 0, with no per-build User/Group override and no dedicated compiler-worker
provisioning. Certificate issuer execution identities belong to box-control's
ordinary application grant model; those are not compilation worker accounts.

Source tests are not native issuance or compilation. Native acceptance and
installation remain separate.
