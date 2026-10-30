# Public source testing and acceptance boundaries

The public workflow tests the separately developed root-control source against
published, immutable public sources: `zog144/box-control` at
`a3e939b7a22ef6277ae9712961ffbd5a18ccac39` and aggregate `zog144/zog`
at `d47d86b363824c718d9c165124cb55bbed12e0f9` for the image-build
and other unchanged shared dependencies. A temporary PEP 420 namespace overlay exposes non-controller public aggregate
modules without its regular `zog/__init__.py` or its historical copies of
`root_control` and `box_control`; the new public root-control and box-control
source trees take precedence.

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

When image-build is published with reviewed public revisions, replace the
historical aggregate dependency with that exact source and re-run complete
cross-component zero-skip acceptance with the appropriate host environment.


## October 22, 2026 — current companion and mandatory security CI

Public source CI now checks out current reviewed box-control `a3e939b7a22ef6277ae9712961ffbd5a18ccac39`, verifying that exact revision against the current root-control checkout on both Python 3.12/3.13. The dedicated `privileged-socket-regression.yml` checks the same exact box-control pin and runs on PRs into both `main` and `unstable`, with no skipped/deselected security tests; source-only execution is not real kernel peer or systemd acceptance.

The box-control public compatibility pipeline independently runs the four previously deselected symbolic identity cases with no `--deselect` and enforces their JUnit presence and absence of skips/errors/failures. Both repositories' current component source identities are checked independently of the historical Zog dependency fixture.

Workflow triggers alone do not configure GitHub branch protection. Requiring `privileged-socket-regression` (and companion box-control security/compatibility contexts) for merge requires repository administrator rules on `main` and `unstable`.
