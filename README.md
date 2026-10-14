# root-control

**Documentation:** [Technical manual](docs/root-control/README.md) · [Source traceability](docs/root-control/TRACEABILITY.md). The manual organizes current concepts; linked detailed sources preserve exact contracts and historical evidence.

Root-control is Zog's privileged local execution backend. It accepts the narrow
local RPCs issued by box-control, validates them again at the privilege boundary,
and performs systemd, process, workspace, build-resource and journal-barrier
operations that require host privileges.

The human-facing program name remains `root-control`. The canonical Python import
path is `zog.root_control`.

## Development

Development happens on `unstable`. The component was originally
split from box-control during private development. This public repository starts
fresh Git history; old private commits and their verified identities are not
represented as public Git ancestry.

The current implementation reuses selected unprivileged state/validation
helpers from `zog.box_control` and image-build interfaces. For a reproducible
public compatibility check, GitHub Actions selects reviewed public box-control
source and a pinned public `zog` aggregate for the remaining dependency; see
[public CI guidance](.github/PUBLIC-TESTING.md). A separate latest-companion
integration run is required when image-build has an approved public revision.

A standalone source distribution and wheel can be built with:

```sh
python -m pip install build
python -m build
```

Public Python publication is not performed from this repository. Release-build
copies `src/zog/root_control/` into the aggregate `zog` distribution.

The privileged daemon entry point is:

```text
root-control = zog.root_control.daemon:main
```

The native journal barrier helper source is packaged at
`zog.root_control/native/journal-wait.c`.

## Public source license and verification limits

Original first-party files are licensed under `BSD-3-Clause OR GPL-3.0-only`;
see [LICENSE](LICENSE), [LICENSES](LICENSES/) and
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md). Public CI verifies Python
source and packaging using published public dependency revisions; it does not
establish privileged live-systemd, reboot, production identity-grant or
journal-barrier acceptance. Historical private records remain separate.
