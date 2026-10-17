# Host-welcome console observer: root-control privileged peer ruling

**Date:** 2026-10-17. **Owner:** root-control Regular. **Source stage only.**

The reviewed observer is NOT a new root-control operation, socket consumer grant, systemd lifecycle authority, mount capability, or root-side daemon. Its approved route is:

```text
host-welcome UID -> /run/host-welcome/controller-progress.sock (mode 0600, SocketUser=welcome UID)
                 -> box-control read-only broker (controller owner UID, exact peer UID)
                 -> saved controller build/runtime evidence
                 -> existing root-control mechanism (only where authenticated controller owner requires an observation)
```

The station web listener remains its original separately installed socket. Neither station nor welcome consumers ever connect directly to `/run/zog/root-control.sock`.

The privileged root-control daemon enforces exact configured numeric `ROOT_CONTROL_CONTROLLER_UID` via `SO_PEERCRED` before decoding a request, with unconfigured root-only fallback. Its existing test `test_console_progress_consumer_never_inherits_general_privileged_socket` explicitly rejects different dedicated host-welcome and station UIDs even if the supplied GID is the same. The installed controller UID must match the reviewed host-install protected grant; do not copy an illustrative test UID into production. Do not add the welcome UID to the controller owner group, modify ACLs or introduce a general root-control proxy.

The new box-control broker startup contract for the dedicated console role also pins exact Unix listener pathname, owner UID, mode, root-owned ancestry, fixed root-control transport and exact executing controller-owner UID. See [controller contract](https://github.com/zog144/box-control/blob/unstable/docs/box-control/HOST-WELCOME-CONTROLLER-OBSERVER-2026-10-17.md). Host-install MUST supply both numeric UIDs through the root-protected unit, never from a request or username guess.

**No new privileged RPC or root-control runtime is needed.** The console progress socket itself is host-install owned and socket-activated; the server is unprivileged. Source-level peer tests do not prove installed filesystem ACLs, actual supplementary groups, SELinux labels, NAT namespaces, systemd socket activation or persistence across reboot. Host-install/host-deploy Work must produce native disposable-host evidence before enablement. The separate certificate issuer, browser, graphical login, greetd and image-build publication gates remain independent.

**Disposition:** root-control peer separation reviewed and regression case committed; native host socket/UID acceptance NO-GO until independently verified.
