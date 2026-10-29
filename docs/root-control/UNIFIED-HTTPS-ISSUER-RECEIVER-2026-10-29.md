# Canonical HTTPS credential receiver — source-only interoperability correction

Review scope: root-control [PR #16](https://github.com/zog144/root-control/pull/16). **NO-GO for live delivery, issuer mutation, and native activation.** Source-default `LIVE_NETWORK_ACTIVATION = False`; no automatic retry or SSH fallback. No retained Host, provisioned issuer, STATE, certificate, Certbot, DNS, nginx or EC2 changed.

## Exact upstream owners and signed bytes

- Sole wire/state-machine owner: `zog.host_identify.credential_delivery` 0.3.5, commit `4a176373ff4cb47a66a8ab1b5fd3d6ff01ff2a3b`.
- Producer adapter / public vectors: station-access PR #10, commit `51295bd7a458a621ccbf33eab03da43ba84ce71a`. The fixture is copied byte-for-byte to `tests/fixtures/credential-delivery-v1-vector.json`; an exact-pin GitHub Actions workflow checks `cmp` and runs upstream `verification/credential_v1/test_shared_interop.py` unmodified on Python 3.12 and 3.13.
- Fixed origin-only HTTPS endpoints, no redirects, no proxy or aliases: POST `/.well-known/zog/credential-delivery/v1` -> strictly canonical application/json signed envelope (200); POST same `/receipt` -> empty 204; POST same `/cancel` -> empty 204. Uniform secret-free denial; never call old `/api/hosts/credential-delivery/v1/receive/`. **Receiver accepts these proposed paths at source level; station producer/native listener owner must confirm final deployment before native admission.**
- Authorization is `zog-credential-authorization-envelope-v1` Ed25519 signed by an independently pinned Credential Authority, not the certificate-assignment signer or TLS CA; authorization ID and revision are UUID/int, not the local SHA-256 issuer grant identifier.
- HostIdentity signs canonical `zog-credential-request-v1` with `credential_delivery.prepare_request` and RFC 9421 `signatures.sign`. Authority signs `zog-credential-delivery-envelope-v1`. Only after signature, origin, current authorization, exact Host / installation / STATE / consumer / purpose / revision and local issuer checks does the protected root receiver call `credential_delivery.secret_bytes` and feed the existing anonymous FD `issuer_credentials.install_from_fd`.
- Installer's own root-owned grant, pending ledger, storage, 0600 file and persistent backing admission remain authoritative. The receiver now additionally calls `issuer_credentials.require_installed` for the exact protected grant and `inspect` after install, **before** preparing its HostIdentity RFC 9421 signed `zog-credential-installation-receipt-v1`. No generic controller RPC is exported.
- An explicitly selected `zog-credential-cancel-v1` is signed by the same HostIdentity key. Cancellation is not an implicit retry; pending/uncertain network delivery sets `rotation_required` conservatively and cannot be retransmitted.

## Protected local source contract / migration

Existing root-owned per-project HTTPS profile (schema `zog-issuer-https-credential-client-v1`) still pins owner-ledger bytes, station certificate-assignment signer, TLS CA, exact installation/STATE/Host fingerprint and issuer storage/grant/UID/revision. The canonical replacement **adds**:

- `delivery_credential_id`: stable protocol token beginning `cloudflare-` (distinct from original local issuer UUID credential_id);
- `credential_authorization_id`: Credential Authority signed UUID (distinct from local `authorization_id` SHA256);
- `credential_authorization_revision`: strictly positive signed revision;
- `credential_authority_pin_sha256`: byte pin of root-owned `/etc/zog/issuer-credentials/credential-authority.json` (a separate pin file with `schema`, `registry_id`, Ed25519 public key and fingerprint).

Per-project protected signed `<sha256(Project)>.credential-authorization.json` is required in issuer credential root. No unsigned/coerced local approval and no old draft request may substitute. Installed owner must provision and attest these files independently before any native enablement; a missing signed authorization is a denial.

Source-only receiver ledger and operation files live under the already-installed root-only `https-receipts` directory as `<sha256(Project)>.credential-ledger.json` and `<sha256(Project)>.operation.json`. Both contain **no secret, no secret digest and no delivery envelope**. The shared state machine's `new_ledger`, `advance_authorization`, `admit_request`, `record_delivery`, `record_installation`, and `record_cancel` are called with root-owned atomic/fsynced writes. The existing root-only issuer lock serializes ledger mutation. Interrupted outgoing requests remain pending/rotation-held; interrupted installation retains issuer_credentials' separate pending barrier. No guessing that a station accepted a receipt. A future operator-owned reconciliation contract is required to resolve unknown ack state; never automatically redeliver or release a history lock.

## Remaining cross-owner contract differences / explicit native NO-GO

1. Station-access PR #10 is a pure source adapter and vectors, **not a production listener**. Its PR #9 experimental raw-token ingress and old request/response/replay tables must remain disabled and must not coexist with canonical paths. Station must implement actual protected HTTP request/receipt/cancel endpoints with durable nonce+ledger transactions, signed authorization and envelope response, secret-free 403/503 framing, no upstream response buffering/logging, and receipt/cancel ack/expiry handling.
2. Station owner must explicitly confirm the three fixed paths, POST Content-Digest/Signature-Input wire bytes, Ed25519 authority key identity and deployment host: exact origin and signed `@target-uri` cannot be aliased by nginx. Source vectors/interop passing are not this live confirmation.
3. Host-install must install/attest root-owned independent Credential Authority pin, signed authorization envelope, revised profile, host-signing identity, local project issuer authority and inherited protected SHA/FD/barrier semantics, including wheel RECORD/native reboot continuity. Existing installed profiles cannot silently be treated as canonical.
4. Host-deploy PR #6 is **not modified here**. Its old custom `zog-protected-credential-delivery-request-v1`/receipt and source pins must be migrated separately to canonical profiles, authority/assignment/credential revision, owner grant, and signed receipt/cancel semantics.
5. A native disposable acceptance must demonstrate expiry/revocation, Host/STATE/owner/proxy/signer substitution, unsigned/partial/oversize responses, concurrent attempts, durable uncertain deliveries, cancellation after delivery/rotation, reboot, FD/storage fidelity and no secret leakage. Only then may a separate approved source change deliberately enable `LIVE_NETWORK_ACTIVATION`.

No live token, SSH bridge, issuer activation, RF5BGA retry, host-deploy changes or new EC2 resource was authorized or performed.
