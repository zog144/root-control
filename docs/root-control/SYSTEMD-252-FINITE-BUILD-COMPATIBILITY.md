# systemd 252 finite-build transient unit compatibility

The previous root-control build backend submitted `ExecStartEx` and optional
`ExecStopPostEx`. The R4 compiler Host's systemd 252 reports these as
unknown transient-unit settings; the unit can be `bad-setting`, with no
usable `ExecStart` property for the controller to verify.

On systemd 250–253 this source uses typed D-Bus `ExecStart` and
`ExecStopPost` (`a(sasb)`) instead, including the legacy hook
ignore-failure boolean. On 254+ the current `Ex` properties and
`no-env-expand` flags remain. The legacy path rejects a `$` in
a build command *before* writing `start_attempted`, rather than
risking silent argument expansion by systemd.

Build resource constraints, security, mounts, inherited process identity,
and the saved job/attempt contract are unchanged. Legacy ExecStart D-Bus
readback normalizes to the exact original command argv. A pre-existing
`bad-setting` unit with empty/mismatched ExecStart remains untrusted,
even after installing this corrected controller.

**Native acceptance before R4 continuation:** install the revision
on an authorized native systemd 252 Host; execute a *new disposable*
bounded test job and verify the real transient unit is loaded, has
the expected `ExecStart` and optional `ExecStopPost`, the same
invocation and saved command, retained resource limits, final exit
status and cleanup. These source tests model the typed properties,
not the real PID 1 execution path.

Only after native acceptance, use the normal authenticated observation
to refresh existing R4 configure job `1b9ae889…` *without re-registering
or retrying its start*. Merely finding Meson's success message in the
journal does not satisfy the saved unit's execution identity; if
independent matching exit evidence cannot be authenticated, retain
its uncertain state and request explicit recovery authority.
Preserve all old failures, completed packages, parent generation,
and `273de2a0…` PID1/boot evidence. No compiler submission or
generation publication was performed by this source correction.
