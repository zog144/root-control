# Build execution uses the existing process identity (2026-11-14)

This source change removes the alternate controller/build-worker user contract from finite image-build jobs. The caller cannot supply UID/GID in the build registration or build request. root-control's privileged build mechanism uses the effective UID/GID of its running service for workspace setup, and the transient service has no `User=` or `Group=` override. Under the selected trusted-Host deployment, SSM and root-control run as their already installed system-service identities. No dedicated build-owner or build-worker accounts are created or looked up by this protocol.

This change does not add privileges to a running process or change the credentials of an existing service. The root-control socket access policy, fixed build root, cgroup lifetime, resource limits, namespace restrictions, and durable job identities remain separate mechanics, not alternate account provisioning. Moving image-build into box-control's ordinary application execution model is a subsequent architectural improvement, not a condition for this correction.

Old registration and job records containing execution user/group fields remain evidence only; the new canonical request rejects them, and pre-existing jobs must be observed or explicitly retired rather than resumed with rewritten request bytes. A running root-control service's effective identity is authoritative; there is no UID/GID option in the request or controller policy.

Tests assert omission of systemd User/Group, rejection of caller-supplied UID/GID, and workspace handling under the executing process's credentials. Native acceptance must inspect actual effective process credentials and service properties without assuming a separate passwd account.

## Native effective-credentials acceptance

Source checks cover both effective UID/GID 0/0 and a nonzero pair, reject `User`, `Group`, `execution_user_id` and `execution_group_id` request fields, and require the transient unit properties to omit `User=` and `Group=`. These source tests do not prove that the systemd system manager inherits a non-root calling process. On a system manager, an unspecified `User=` ordinarily defaults to root. The selected privileged root-control service ordinarily runs as root as well. There is **no root-rejection rule**.

`acceptance/build_inherited_identity.py` is an explicit opt-in, disposable-Host systemd identity probe. It creates one bounded transient service with no `User=`/`Group=`, reads the actual child `/proc/<pid>/status` kernel effective and filesystem credentials while the child is running, compares them with an explicitly identified installed root-control daemon PID, then stops and unreferences the diagnostic service. This proves or disproves the identity relationship under the native systemd manager, without assuming any passwd account. It does **not** submit an image-build job, migrate a project or prove the entire build RootDirectory setup. A full native finite-build acceptance must still verify the actual build job's PID tree and preserved cgroup/cleanup behavior before declaring the integrated compiler runtime ready.

Example **only after separate disposable-Host acceptance authorization**:

```sh
python3 acceptance/build_inherited_identity.py --disposable-host --controller-pid PID --output /tmp/zog-build-identity-evidence.json
```

No new user, setuid, sudo, runuser, systemd User/Group override or account-specific gate is introduced. Do not infer a user from `$USER`, `$HOME`, passwd home or a hard-coded numeric ID.
