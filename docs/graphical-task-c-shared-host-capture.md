# Shared-host original-event capture

Copyright (c) 2026 Alex Black.

This deployment option trusts the entire intake host and its administrators,
including the gateway, with request intake and direct compiler execution. It
supersedes gateway-no-direct-SSM and separate capture-machine requirements only
when explicitly selected by the operator. It does not claim to withstand a
compromised intake host. The normal owner path retains approval, immutable
identity, claims, cancellation, revocation and original-history checks.

The capture service holds only the webhook HMAC secret, not Ed25519 signing
keys. An independently deployed event signer rechecks the preserved raw body.
A trusted intake host with the HMAC secret could forge such evidence; physical
separation of the signer does not remove this accepted trust assumption.

The bounded WSGI factory is
`zog.root_control.graphical_task_c_capture_app:create_app()`. The examples use
Gunicorn behind an existing HTTPS server and a Unix socket. Root installs the
selected exact source trees and runtime dependencies read-only, creates the
service account, installs a root-owned non-writable policy JSON at
`/etc/zog/github-capture/policy.json` containing exactly `repository_id`,
`actor_id`, and `actor`, and installs the existing authentic issuer HMAC at
`/etc/zog/github-capture/webhook.hmac` (0400). systemd LoadCredential delivers
both the policy and secret to the service, without opening parent configuration
directories to the service account. Do not put it in argv, source, environment or logs.

StateDirectory is owned by the capture identity, mode0700. Publication uses a
nonblocking interprocess lock and refuses storage beyond4096 records or64MiB
(with a worst-case receipt reservation); it never deletes uncertain receipts.
At capacity, operators must archive evidence through a separately reviewed
retention process. nginx limits requests to64KiB, and the worker deadline is15s.
The receiver cannot make IP connections. Its process limits and journal rate
limit bound operational load; upstream rate limiting remains a host concern.

Use the examples only after verifying their selected paths, local nginx group,
actual TLS routing and installed source/dependency bytes. Do not restart an
unrelated portal or gateway. Verify nginx syntax before reload and preserve a
rollback copy. Test malformed/unsigned requests against the native endpoint;
positive synthetic HMAC tests belong in separate fixture storage, never in the
real authority archive. Actual original GitHub delivery and issuer verification
remain native acceptance gates, not inferred from a listening endpoint.

This service does not install owner authority, create S3 genesis, sign grants,
submit builds, or alter any existing native-admission hard flag. Broker-specific
GetObject-only credential and authenticated peer/history checks remain intact.

## Runtime access

Keep the capture runtime root-owned. When preparing it under umask077, give
only the dedicated zog-github-capture group read/traverse access to its venv
and selected source import trees, and traverse access to their parent
directories. Do not recursively open /etc/zog, receipts, secrets or unrelated
program trees. Install the runtime-access.conf example as a service drop-in;
nginx remains the socket group, while the supplementary group reads code.

The example requirements.lock pins the runtime wheels used in this pass,
including their SHA256 hashes. It is an exact tested deployment selection,
not a replacement for the component's normal dependency declarations. Source
repositories and dependency wheels must be acquired separately; do not vendor
their contents into consumers. Native installed source and dependency RECORD
verification are required in addition to fixture tests.
