# Build execution uses the existing process identity (2026-11-14)

This source change removes the alternate controller/build-worker user contract from finite image-build jobs. The caller cannot supply UID/GID in the build registration or build request. root-control's privileged build mechanism uses the effective UID/GID of its running service for workspace setup, and the transient service has no `User=` or `Group=` override. Under the selected trusted-Host deployment, SSM and root-control run as their already installed system-service identities. No dedicated build-owner or build-worker accounts are created or looked up by this protocol.

This change does not add privileges to a running process or change the credentials of an existing service. The root-control socket access policy, fixed build root, cgroup lifetime, resource limits, namespace restrictions, and durable job identities remain separate mechanics, not alternate account provisioning. Moving image-build into box-control's ordinary application execution model is a subsequent architectural improvement, not a condition for this correction.

Old registration and job records containing execution user/group fields remain evidence only; the new canonical request rejects them, and pre-existing jobs must be observed or explicitly retired rather than resumed with rewritten request bytes. A running root-control service's effective identity is authoritative; there is no UID/GID option in the request or controller policy.

Tests assert omission of systemd User/Group, rejection of caller-supplied UID/GID, and workspace handling under the executing process's credentials. Native acceptance must inspect actual effective process credentials and service properties without assuming a separate passwd account.
