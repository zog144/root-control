# Historical SSH issuer bridge — superseded

The 2026-10-27 SSH forced-command design is retained only in repository history and review discussion. It is not an approved or selectable credential transport.

The approved direction is the purpose-scoped HTTPS receiver in `zog.root_control.issuer_https_receiver` (root-control PR #16). The reusable security properties survive the migration: exact Host/installation/STATE and owner authority, independent station signer and TLS trust, current credential revision, issuer UID/grant/storage, durable one-time request identity, pre/post authority recheck, bounded secret-free failure, and the existing anonymous-FD `issuer_credentials.install_from_fd` installation path.

The following SSH-specific assumptions are retired and must not be installed or used as fallback: SSH client identities, `known_hosts`, sshd Match User key-to-UID mapping, forced commands, remote shell command selectors, and the station SSH broker socket. Draft PR #13 is superseded by PR #16 and must not be merged.

The HTTPS receiver remains source-only and disabled. Station-access PR #9 and host-deploy PR #6 still need one exact interoperable wire/receipt contract before native release; root-control must not fabricate a receipt or silently translate authority fields. No credential, DNS, ACME, certificate, nginx, retained issuer, STATE, or RF5BGA operation is authorized by this migration.
