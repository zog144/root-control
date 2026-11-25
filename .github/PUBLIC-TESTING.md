# Public source testing and acceptance boundaries

Both source workflows check out `zog144/image-build` directly at
`1f07e83dbd80dacb9bed0d6494c697375f0e26cd`. They verify the Git revisions and
Python import paths for the component checkouts. Each keeps its existing
`zog144/box-control` pin:

| Workflow | box-control commit |
| --- | --- |
| [Public source verification](workflows/ci.yml) | `a3e939b7a22ef6277ae9712961ffbd5a18ccac39` |
| [Privileged socket regression](workflows/privileged-socket-regression.yml) | `b7934882cfacd2fbfd60c7964713ed3dde7f9460` |

These are the dependencies for the root-control suites. Full image-build
workloads and its own suites have additional dependencies and acceptance steps.

The public dependency checkout is anonymous/read-only: it does not use private
cross-repository tokens. The workflow builds a wheel and source archive,
verifies licensing and canonical `zog.root_control` namespace, compiles the
native journal helper source and runs controlled Python 3.12/3.13 pytest suites.

Source-level and mocked D-Bus/systemd fixtures are not equivalent to a
running systemd manager on a properly enrolled Zog host. Explicit opt-in
`test_execution_identity_systemd_live.py`, journal attribution, privileged
identity registries, D-Bus service and recovery testing remain separate gates.
They must run only on authorized disposable hosts with the relevant owner
approval. Historical private acceptance results retain their original
source identities and are not relabeled to the new public Git commit.

The dedicated privileged socket workflow runs on PRs into both `main` and
`unstable` and checks that the required tests ran without skips or failures.

The box-control public compatibility pipeline independently runs the four previously deselected symbolic identity cases with no `--deselect` and enforces their JUnit presence and absence of skips/errors/failures. Both repositories' current component source identities are checked against their exact public companion revisions.

Workflow triggers alone do not configure GitHub branch protection. Requiring `privileged-socket-regression` (and companion box-control security/compatibility contexts) for merge requires repository administrator rules on `main` and `unstable`.
