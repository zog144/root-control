# root-control public source and dependency notices

Original first-party Python code, native journal-wait helper, documentation,
tests and controlled acceptance fixture in this public repository are licensed
under `BSD-3-Clause OR GPL-3.0-only`. See [LICENSE](LICENSE) and the complete
terms in [LICENSES](LICENSES/). Earlier copyright notices retain their authorship.

Root-control depends on separate box-control and image-build interfaces and
`dbus-next==0.2.3`. No source of those components is vendored here. Python,
setuptools, pytest, systemd, journald, the Linux kernel and any packaged
third-party host tools retain their respective copyrights and licenses.
Redistribution must check the exact dependencies and binaries actually bundled.

This new public repository does not import private Git commits or handoff tags,
private operational grants or live host records, systemd journals, remote host
identities or privileged deployment credentials. Disposable-host probes are
optional and do not authorize execution against production systems. Public PyPI
publication remains the responsibility of release-build's aggregate `zog`
distribution, not this standalone development component.
