# Mandatory independent cross-role public pin custody

This appendix is part of the Task C prospective issuance candidate and supplements [the issuance runbook](graphical-task-c-original-authority-issuance-2026-11-05.md). It is not evidence that any key has already been accepted.

## Operator signer Host

The operator signing machine must have a separately enrolled 32-byte Ed25519 seed at `/etc/zog/graphical-task-c-issuance/operator.private` (root-owned, mode 0400) and its independently authenticated exact 32-byte public pin at `operator.public` (0600). To sign a *broker-purpose* approval it must **also** possess the previously accepted, independently provisioned event issuer public key at `accepted-event-issuer.public` (0600). That key is not taken from `issuer_public_hex` in an input manifest; the manifest's value must match the installed accepted pin byte-for-byte.

The operator signing Host must not hold the event issuer's private seed or the GitHub webhook HMAC secret. Public-key rollover is a separate reviewed authority-epoch operation; it cannot be used to retroactively sign a historical GitHub issue or replace the original S3 genesis.

## Independent GitHub event issuer Host

The event issuer machine holds its own `event.private` (0400), `event.public` (0600), GitHub webhook HMAC secret `github-webhook.hmac` (0400), and the **separately authenticated and installed operator public key** at `accepted-operator.public` (0600). Event signing rejects a registry merely signed by a manifest-supplied key. The installed operator public pin must match both the registry's verifying key and `operator_public_hex` exactly and must differ from the issuer key.

The event issuer must neither possess the operator private seed nor accept an event from a mutable GitHub issue API response. It must revalidate the original raw HMAC-SHA256 webhook bytes and exact numeric repository/actor identities. Re-delivery with a new delivery string is fenced using a separate create-only raw-event SHA-256 claim, not merely a matching GitHub-delivery header.

## Separate keyless HTTPS webhook capture Host

The optional `graphical_task_c_webhook_capture.capture_wsgi` WSGI factory must run behind an independently attested HTTPS ingress on a separate identity. The capture service receives only the exact HMAC secret and externally pinned numeric GitHub repository/actor IDs. It must **not** hold either Ed25519 private key, an SSM or checkpoint-writer credential, or permission to mutate original S3 history. Native Work must independently attest TLS routing, source/RECORD/unit bytes, capture directory (0700), capture identity, and create-only delivery receipts before moving the original raw signed delivery into the event issuer's protected input directory.

## Work acceptance is not self-asserted

Before approving an actual issuance, Work independently compares the two public-key fingerprints against out-of-band original enrollment receipts and the native installer's selected authority pins; verifies the *real* original Host/installation/STATE, gateway process and S3 tuple/history/anchor; tests private-key denial from the deployed gateway; and checks that the exact installed signer binaries and credentials are unchanged on reboot. Missing input means **HOLD**, not key creation or pin replacement. Issuance source tests use synthetic keys and never constitute key enrollment evidence. Both owner and broker native admission switches remain OFF.
