# Root-owner issuer-only Cloudflare credential bridge — source contract

**Date:** 2026-10-15  
**Components:** `zog.root_control.issuer_credentials`, `zog.root_control.issuer_station_transfer`, box-control `issuer_lifecycle_broker`  
**Producer:** station-access `zog-station-issuer-cloudflare-read-v1`  
**Status:** implemented and source-tested; native deployment and DNS-01 acceptance **NOT** established.

## Trust boundaries

There are **three independent identities**: the root-owned issuer authorization and offline installer; the station-access **vault-reader UID/GID** (not the station web UID); and the persistent `certify-manage` application UID/GID. The host-deploy automation UID is a fourth identity that may use the **separate** selected-operation broker; it cannot access root-control's daemon socket, the station vault-reader socket, or `certificate-data`.

The trust chain is:

1. A separately reviewed and verified station assignment and host-owner approval establish exact project, certificate, zone, credential UUID and revision, signed receipt fingerprint, issuer grant/storage and expiry. This owner's protected `0600 root:root` record exists at `/etc/zog/issuer-credentials/<sha256(canonical project path)>.approval.json`. **This module does not manufacture an approval from a station browser request or validate Ed25519 receipts; those remain host-deploy/assignment-authority duties.**
2. The root-only `publish-projection` command reads a **nonsecret** station projection from an inherited file descriptor; no caller-selected output path exists. It checks the exact nested root approval, current root-owned certificate DNS-01 policy, managed application UID/GID grant/storage, and prior installation-revision ledger. An extra field or different assignment ID/revision, credential ID/revision, certificate/policy, zone or grant is refused.
3. Root-control durably writes `<project-digest>.reader-peer.json` mode `0600 root:root` with pinned nonroot reader UID/GID, exact approval digest and fixed socket. It then atomically publishes `<project-digest>.station-reader.json` mode `0440 root:<vault-reader-gid>`; its contents have schema `zog-station-issuer-reader-authorization-v1`. The root-owned directory is non-writable by either station identity. Changed reader UID/GID requires a separately reviewed migration.
4. The **only** token source used by the regular provisioning flow is the inherited, root-owned fixed AF_UNIX socket `/run/zog/issuer-cloudflare-reader.sock` (configured identically as `HOST_ISSUER_CREDENTIAL_SOCKET_PATH` in station-access). The socket inode must be `0600` and owned by the exact vault-reader UID, with root-controlled no-symlink ancestors. Root connects and verifies the socket peer's kernel `SO_PEERCRED` UID before sending any request.
5. Wire: canonical ASCII JSON, terminated with `\n`, exact fields `schema="zog-station-issuer-cloudflare-read-v1"`, `operation="read-approved-cloudflare-issuer-token"`, `authorization_id=<sha256 of canonical root approval JSON>`, and `nonce=<32 fresh lowercase hex>`. Root calls `shutdown(SHUT_WR)`. Station checks it is talking to UID 0, records the nonce durably, verifies its assignment/vault identity before and after decrypt, and returns **only** the bounded ASCII token bytes (no framing, INI or status).
6. Root verifies the response bytes, unchanged original nonsecret projection and pinned peer, then passes token bytes over an anonymous pipe FD to the already implemented offline `install_from_fd`. The install validates the same expected authorization digest again under the normal project lock. No token is stored in argv, environment, controller request JSON, privileged response or durable audit.
7. The existing root installer rejects unresolved issuer operations and incomplete recovery; atomically writes the exact `dns_cloudflare_api_token = ...\n` line to the existing grant/storage's `certificate-data/dns/cloudflare.ini` with `0700` owned parents and `0600` owned file. It fsyncs the secret and directory, durably publishes a nonsecret installed ledger, and clears a two-phase pending blocker. Every storage ancestor is walked using `O_DIRECTORY|O_NOFOLLOW`. A symlink, hardlink, inappropriate DAC or conflicting revision blocks rather than repairs.
8. Privileged selected `certify-manage issue`/`renew` with DNS-01 requires matching protected root approval, installed ledger, private file, original grant/storage and no pending blocker at systemd start. Changes in zone, policy, assignment, credential revision, expired/revoked owner policy or file mode fail closed. Revocation must be propagated by the trusted host owner; these offline components **do not automatically poll station-access or independently verify Cloudflare token permissions**.

The protected root-owner approval has exact schema `zog-issuer-cloudflare-credential-v1`. The complete closed field set is: `schema`, `state="approved"`, `project`, `certificate_id="station-web"`, `assignment_id` UUID, `assignment_revision` positive integer, `credential_id` UUID, `credential_revision` positive integer, `zone_id`, `zone_name`, `grant_id` 32 lowercase hex, `storage_id` 32 lowercase hex, `policy_sha256` 64 lowercase hex, `receipt_sha256` 64 lowercase hex, and `expires_at` epoch integer. Both GUID fields must use canonical lowercase UUID formatting; project is the already approved canonical controller project root. The separate station-readable projection wraps this **exact** authorization and adds `origin`, `installation_id`, `host_id`, `account_id`, and `owner_user_id` under a fixed v1 schema. Refer to [station-access producer contract](https://github.com/zog144/station-access/blob/unstable/docs/station-access/ISSUER-ONLY-CLOUDFLARE-READER.md) for the full example; do not publish a token in the projection.

## Offline root CLI

After root-owned approval and trust review, the site owner creates `/etc/zog/issuer-credentials` as an existing root-owned directory with mode **0755** (traversable by the dedicated vault reader only as needed; it contains no readable secret). Authorization files are mode **0600**; projection is the **only** mode-0440 file. Station's dedicated vault reader process must have precisely the projection's group, a root-controlled socket path and the original secret/vault database, **not** a general station web service identity.

Trusted host-deploy installer uses an already-open, nonsecret projection FD (illustrative FD 3; **do not** supply secret text on CLI):

```sh
python3 -m zog.root_control.issuer_station_transfer publish-projection \
  /canonical/approved/project --projection-fd 3 \
  --reader-uid <trusted-vault-reader-uid> \
  --reader-gid <trusted-vault-reader-gid>
```

Only after station reader socket installation and protected projection are independently verified should the root owner invoke:

```sh
python3 -m zog.root_control.issuer_station_transfer transfer /canonical/approved/project
```

The second command accepts **no plaintext token, provider credential ID, arbitrary file path, policy override or destination**. This is an offline privileged command, **not** a new root-control daemon RPC. It never adjusts service UID/GID, publishes nginx credentials, reloads a consumer or activates a timer.

An explicit root-admin/offline `python3 -m zog.root_control.issuer_credentials install <project> --token-fd <inherited-fd>` remains available for deliberately reviewed recovery/manual authority, but must not be exposed as an unauthenticated service endpoint or used by host-deploy's unattended scheduler in place of the station reader.

## Cross-identity lifecycle interface

`zog.box_control.issuer_lifecycle_broker` is a separate socket-activated non-root project-owner process. It pins `project`, immutable `generation`, immutable `software-view`, and exactly one host-deploy `authorized-uid` at service startup. It authenticates `SO_PEERCRED` before parsing requests. Its `start` command accepts only the original signed `request_id` and `program` equal to `renew` or `stage`; selection is durably checked and executed by the existing controller. Its `issue`, `result`, `cancel` and `observe` methods are restricted to the exact saved `certify-manage` operation/runtime identity. It cannot run `issue`, `inspect`, `recover`, another application, a command, shell, unmanaged image, arbitrary root-control operation or write a private certificate.

Host-deploy should adopt `IssuerLifecycleClient(<approved-socket-path>)` and retain its own request ledger. It must independently inspect the issuer's real X.509 lineage using the approved issuer identity/verified delivery bridge, in addition to the existing trusted **read-only** `IssuerObserverClient`. `journal-ready` by itself is not X.509 acceptance, nginx readiness or a publication grant.

## Native acceptance — required before activation

Host-deploy Work must establish: canonical root approval and pinned policy source; correct signed assignment provenance and highest-seen revisions; actual vault reader `SO_PEERCRED` and root-only caller; projection byte equality and `0440 root:vault-reader-group`; no station web or host-deploy access to token socket; real reader UID different from station web/controller/issuer; original issuer UID/GID and `0700/0600` private storage; rotation without cross-UID disclosure; revoked/stale authority refusal; crash after token publication but before ledger durability; storage symlink/DAC denial; no token in logs/argv/environment/CI/controller records; trusted host-deploy renew/stage socket; and real DNS-01 staging CA, issuer inspection, private staging, consumer verification and reboot.

Source tests are not substitutes for a native root-owned file/link/mount acceptance or a real ACME challenge. **Do not enable automatic DNS-01 or production certificate publication until native acceptance passes.**
