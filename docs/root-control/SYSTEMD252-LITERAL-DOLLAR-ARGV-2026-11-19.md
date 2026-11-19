# Boot A: literal dollar arguments under systemd 252

The prior PR #53 source correctly used legacy D-Bus `ExecStart` and
`ExecStopPost` on systemd 252, but rejected any dollar sign in argv.

systemd 252's `StartTransientUnit` `ExecStart` setter accepts
`a(sasb)` with a stored argv array. Before calling execve, the
systemd executor calls `replace_env_argv`. It replaces a doubled
dollar `$$` by one literal `$`, without shell evaluation.
Therefore the **legacy D-Bus command argv only** doubles every
dollar; the executable path argument is still the original absolute
path. The canonical source request and all saved request hashes
retain the **original** bytes. No shell wrapper or alternate user
is introduced.

The protected build job record stores
`exec_argv_encoding=systemd-252-dollar-doubled-v1` for a new
systemd 250–253 start, prior to systemd submission. Observation
computes the expected encoded argv from the original saved command
and that exact mode; the native D-Bus `ExecStart` readback must match
byte-for-byte. An unencoded, double-encoded, missing or mismatched
command, or unknown encoding mode, remains a hard failure. Older
attempts lacking the mode keep the historical strict readback rule.
On 254+, `ExecStartEx` with `no-env-expand` remains unchanged.

The legacy encoder fails closed for NUL, invalid UTF-8 and an
encoded argument exceeding the Linux maximum string length. Such
requests fail *before* the durable attempted-start marker and before
journal-barrier registration or systemd job submission.

## Native acceptance — root-control Work, with image-build Work

This source PR does not claim systemd-252 execution acceptance.
After selecting exact reviewed root-control bytes and inspecting
their installed digest, create a **new disposable** registered
build job via the supported box-control/root-control execution
contract, not direct systemd commands. Select a legitimate in-root
interpreter already present in the approved rootfs, e.g., Python
running a bounded sleep with extra arguments. Ensure the test job
stays alive for long enough to examine its argv. The *original*
argv shall include separate arguments resembling:

```text
$IMAGE_BUILD_SOURCE
${IMAGE_BUILD_SOURCE}
$(sha256sum "$IMAGE_BUILD_SOURCE")
awk '{print $1}'
$$
price=$5
```

Set `IMAGE_BUILD_SOURCE` in the job environment to a distinguishable
value, so an unintended substitution cannot accidentally go
unnoticed. Store and submit the request as a JSON argv array, not
through a local shell, to avoid client-side expansion.

Use `acceptance/systemd252_literal_argv_readback.py` as the installed
root-control process's **read-only** verification helper:

```sh
python3 acceptance/systemd252_literal_argv_readback.py \
  --disposable-accepted-job --phase running \
  --project-root PROJECT --build-root-id BUILD_ROOT_ID --job-id JOB_ID
```

It reads the protected saved job, systemd's actual `LoadState` and
`ExecStart`, the child `MainPID` and kernel
`/proc/<MainPID>/cmdline`, and compares all values to the original
request. It reports evidence hashes only; it never launches or
stops a build or mutates the retained job. After the child exits,
run `--phase terminal` before the unit has been cleaned up, verifying
the same invocation, status=0, result=success, empty cgroup and
reconciled journal status through `BuildBackend.observe`.

A missing unit, absent/mismatched argv, error exit or incomplete
journal is **NOT** a passed test. Preserve observed failure and
unknown states for investigation.

## Boot A retention and continuation boundary

Keep image-build PR #25 source `cb73951000a3e7774ab798f58240c2a8f24d82bb`,
parent generation `45a81ec3…`, R5 manifest
`ecfcf4c16c5b2020252ba753630b41aa58dbde155b83c8ac7dea4c736edfee97`,
and prior test request `0111471e2132a31f052621e0fbab31f6`
as unmodified historical evidence. Its outcome is `unknown`;
it had completed cleanup and retained resources. Do not
retry that request ID or reinterpret its successful
`pyelftools-build` predecessor as test success.

Only after native identity/property/argv/terminal verification
passes may image-build Work create a **distinct** new Boot A
operation ID through the authorized producer, retaining original
evidence, with no direct SSM/systemd bypass and no generation
publication inferred from this source change.
