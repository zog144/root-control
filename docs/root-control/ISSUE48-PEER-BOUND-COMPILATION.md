# Issue #48 — peer-bound inherited execution of finite builds

Source selection is based on the complete issuer + Task C controller
and root-control PR #54's systemd 252 literal-dollar encoding.

**Kernel identity only:** at the accepted Unix socket, root-control
captures SO_PEERCRED (pid, effective UID, primary GID) before queuing
the decoded build request. The peer may be exact `0:0` or an existing nonzero UID/GID pair; mixed-zero and malformed identities fail closed.
No JSON request can supply, override or select execution UID, GID,
`User=` or `Group=`. New schema-2 registration and schema-2 job
records retain the authenticated numeric peer identity. Every
registration, prepare and start must match the same peer; an old
schema-1 or otherwise identity-bearing record is readable but is
not eligible for replay or rebinding.

**Systemd:** root-control stays privileged to manage systemd while
setting numeric User/Group exclusively from that saved authenticated
peer. Existing read-only RootDirectory, private network, NoNewPrivileges,
capability bounding, memory/cgroup limits, journal-barrier, and strict
recovery/readback remain intact. On systemd 252, literal `$` is
doubled in the transient D-Bus ExecStart wire argv only; the original
request remains unchanged. No dedicated compiler user, install-time
account creation, setuid invocation, shell workaround, or direct
systemd/SSM compiler launch is provided.

**Project access:** before import, root-control tests conservative
effective-peer DAC access for the Project, prepared root, source
workspace and output workspace, recursively. Missing or inaccessible
paths identify ENOENT or EACCES. Root-control no longer chowns/chmods
the application workspaces to manufacture access. Actual systemd
execution still enforces kernel access checks.

## Native acceptance gate — root-control Work + box-control Work

The repository source tests can show simulated peer binding and read
a running Linux process's actual /proc UID/GID, but they do not prove
a newly launched compiler child on the installed systemd 252 Host.
Do not report issue #48 as native accepted from source CI alone.

Native Work must install and attest this exact issuer-capable controller,
verify box-control's existing UID/GID (including `0:0`) and ensure it can
connect to its authorized Unix socket, then create one **disposable**
resource/job through box-control's existing API. The requested command
must remain alive long enough for readback and contain literal dollar
arguments including `$IMAGE_BUILD_SOURCE`, `$(sha256sum x)` and
`awk '{print $1}'`. Do not use an archived Boot A ID.

The test job should have a bounded runtime, read-only root, private
network, no privileged capabilities and MemoryMax. Run as the actual
box-control client, retaining its kernel identity:

```sh
python3 acceptance/build_peer_bound_live.py \
  --accepted-disposable-build --phase running \
  --project-root PROJECT --build-root-id RESOURCE_ID \
  --job-id JOB_ID --request-json ORIGINAL_REQUEST.json
```

The checker queries `build_observe` on the **normal root-control Unix
socket**, verifies systemd's numeric User/Group against the connection
peer, the live kernel child EUID/EGID, its cgroup and exact /proc argv.
Record the resulting InvocationID. Before unit cleanup, run
`--phase terminal --expected-invocation-id ID` with the same identity
to verify controller exit status, journal evidence and cgroup cleanup.

Any missing child, mismatched owner, wrong argv, stale
invocation, unresolved journal barrier, failed/unknown terminal result
or inaccessible Project is a failed acceptance. Source review and CI
are necessary but not sufficient to close issue #48.

Historical identity-bearing and failed Boot A records remain unchanged.
Do not restart archived R5 request 0111471e2132a31f052621e0fbab31f6;
follow image-build's authorized distinct-operation recovery contract.


## Compiler root peer acceptance (2026-11-22)

The compiler peer may be **0:0** when that is its actual kernel identity.
No new account, identity selector, `runuser`, `sudo` or alternative
execution user is introduced. The service process continues to enforce
rootfs isolation, read-only mounts, `PrivateNetwork`,
`PrivateDevices`, `NoNewPrivileges`, empty
`CapabilityBoundingSet`/`AmbientCapabilities`, cgroup limits and
exact per-job saved-identity recovery. Do not interpret UID 0 as permission
to bypass these boundaries. Partial-zero peers and malformed credentials
remain rejected.

For root compilation on systemd 252, the exact accepted and durable
`User=0` and `Group=0` are submitted by root-control in its transient
unit, derived solely from `SO_PEERCRED`. Test the actual child UID/GID
from `/proc` and verify the `ExecStart` encoded `$$` representation
readback while the child's original argv contains literal single `$`.
When the barrier is enabled, its root stop-hook credentials may now
authenticate *only* against the saved unit, token, boot, pidfd,
`ControlPID`, invocation and `SubState=stop-post`.
The protected terminal evidence is checked against the saved root identity.

Use the same read-only `acceptance/build_peer_bound_live.py` checker
with the root caller's actual effective UID/GID. A second
`--phase terminal` invocation must reuse the exact running
`InvocationID`. This checker never launches the build or changes
unit state; Work must use the already supported controller API for a
**new disposable bounded** operation, then verify cleanup. No historical
Boot A job is replayable.
