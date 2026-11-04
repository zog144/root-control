# External append-only graphical checkpoint

Copyright (c) 2026 Alex Black. BSD-3-Clause OR GPL-3.0-only.

`graphical_s3_checkpoint.S3AppendOnlyCheckpoint` supplies the existing protected
ledger checkpoint interface. It is an external storage adapter, not a native
admission receipt. The Task C sender remains disabled until the installed owner,
peer, authority, gateway and credential boundary have independent acceptance.

A trusted installer creates `000000.json` in a dedicated S3 prefix and pins its
canonical SHA-256, exact AWS account, bucket, prefix and scope in protected
configuration. Genesis contains schema `zog-graphical-s3-checkpoint-v1`, the
scope digest, sequence zero and action `genesis`. Runtime never creates genesis.
The scope digest binds the selected Host, installation, STATE and authority
through the existing original-operation contract.

Subsequent immutable, hash-linked numbered objects contain claims or revocation.
Each write uses `IfNoneMatch="*"`, followed by exact readback. Simultaneous writers
compete for the same next object. A conflict, timeout or lost acknowledgement
blocks the attempt; it never advances to another slot or retries the send.
The caller must configure explicit owner-private credentials, the fixed AWS
endpoint and SDK `total_max_attempts=1`. An absent genesis, invalid history,
access error or exhausted 256-slot bound blocks admission. One scope is suitable
for a bounded acceptance catalogue; no automatic rotation or garbage collection
is provided. Remote observations are reconstructed each time; no disk-restored
local highwater is trusted.

## Required deployment boundary

- The owner role can read its selected prefix and conditionally create numbered
  events. Explicitly deny replacing genesis, nonconditional writes, and deleting
  objects or versions. Neither gateway nor owner can alter bucket policy,
  lifecycle, replication, role policies or the pinned scope. Gateway receives no
  checkpoint credential and cannot assume the owner role.
- Verify the actual bucket policies and lifecycle rules. There must be no rule
  that expires these records, adds delete markers, or otherwise removes the
  visible history. S3 Object Lock alone does not prevent a delete marker from
  hiding a retained version. Do not infer this guarantee from versioning alone.
- The independently administered AWS storage/policy domain is the trust anchor.
  This protects against restoration of the owner/gateway host disks, not an AWS
  administrator intentionally deleting authority or rewriting policy.
- All local submission and revocation paths hold the same protected owner lock
  through sending. CAS arbitrates external claims, but is not a distributed
  lease or permission for multiple active owner daemons. Revocation does not
  cancel an already admitted external command.
- Provision original operation mappings and operator keys independently. Never
  treat matching gateway data, a source test or an unsigned status as approval.

This adapter is compatible with the file-ledger stream candidate in PR #36.
The alternative SQLite source in PR #37 is not silently selected or installed.
Neither earlier seqpacket nor an additional sender is enabled.

AWS specifies conditional-write behavior and policy enforcement at:
https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html
https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes-enforce.html
