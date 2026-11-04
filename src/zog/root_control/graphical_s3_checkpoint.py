"""Append-only external checkpoint; deployment policy is a separate admission gate.

Copyright (c) 2026 Alex Black. BSD-3-Clause OR GPL-3.0-only.

A trusted installer creates and pins genesis. Runtime never initializes missing
history. Every transition occupies the next immutable key using IfNoneMatch=*.
No local highwater, listing, latest-version pointer, or automatic write retry.
The bucket must independently prohibit overwrite, deletion, expiration and
policy changes by both owner and gateway. This does not defend against the
independent AWS administrator destroying the authority.
"""
from __future__ import annotations

import re

from botocore.exceptions import BotoCoreError, ClientError

from . import graphical_operation_owner_source as contract
from .graphical_native_owner import hold, strict

SCHEMA = "zog-graphical-s3-checkpoint-v1"
MAX_EVENTS = 256
MAX_BYTES = 8192


class S3AppendOnlyCheckpoint:
    """Implements ProtectedLedger's checkpoint interface using a pinned S3 client.

    Constructor inputs are installer-owned, never IPC inputs. Use an explicit
    owner-private credential session, fixed AWS endpoint and single-attempt SDK
    configuration. All callers must share the owner's submission/revocation
    lock through the send boundary. Conditional creation additionally arbitrates
    competing claim writers; conflicts and ambiguous replies always fail closed.
    """

    def __init__(self, client, *, bucket, prefix, account_id, scope_digest,
                 genesis_sha256):
        if (type(bucket) is not str or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket)
                or type(prefix) is not str or not re.fullmatch(r"[a-z0-9/-]{1,160}", prefix)
                or not prefix.endswith("/") or "//" in prefix
                or type(account_id) is not str or not re.fullmatch(r"[0-9]{12}", account_id)
                or not contract.match(scope_digest, contract.SHA)
                or not contract.match(genesis_sha256, contract.SHA)):
            hold()
        self.client = client
        self.bucket = bucket
        self.prefix = prefix
        self.account = account_id
        self.scope = scope_digest
        self.genesis_sha = genesis_sha256

    def _args(self, sequence):
        return {"Bucket": self.bucket,
                "Key": self.prefix + f"{sequence:06d}.json",
                "ExpectedBucketOwner": self.account}

    def _get(self, sequence):
        try:
            response = self.client.get_object(**self._args(sequence))
        except ClientError as exc:
            # AccessDenied, timeouts and generic 404 responses are not absence.
            if (exc.response.get("Error", {}).get("Code") == "NoSuchKey"
                    and exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode") == 404):
                return None
            hold()
        except BotoCoreError:
            hold()
        stream = response.get("Body")
        try:
            if (type(response.get("ContentLength")) is not int
                    or not 0 < response["ContentLength"] <= MAX_BYTES
                    or response.get("DeleteMarker") is True):
                hold()
            raw = stream.read(MAX_BYTES + 1)
            if len(raw) != response["ContentLength"]:
                hold()
            return strict(raw)
        except (OSError, BotoCoreError, AttributeError, TypeError):
            hold()
        finally:
            if stream is not None:
                stream.close()

    def _scan(self, scope_digest):
        if scope_digest != self.scope:
            hold()
        genesis = self._get(0)
        if (genesis != {"schema": SCHEMA, "scope_sha256": self.scope,
                       "sequence": 0, "action": "genesis"}
                or contract.digest(genesis) != self.genesis_sha):
            hold()
        previous = self.genesis_sha
        claims = {}
        revoked = False
        for sequence in range(1, MAX_EVENTS + 1):
            row = self._get(sequence)
            if row is None:
                return sequence, previous, claims, revoked
            if (set(row) != {"schema", "scope_sha256", "sequence", "previous_sha256",
                             "action", "operation_id", "request_sha256"}
                    or row["schema"] != SCHEMA or row["scope_sha256"] != self.scope
                    or type(row["sequence"]) is not int or row["sequence"] != sequence
                    or row["previous_sha256"] != previous or revoked):
                hold()
            if row["action"] == "claim":
                operation = row["operation_id"]
                if (not contract.match(operation, contract.H32)
                        or not contract.match(row["request_sha256"], contract.SHA)
                        or operation in claims):
                    hold()
                claims[operation] = row["request_sha256"]
            elif row["action"] == "revoke":
                if row["operation_id"] is not None or row["request_sha256"] is not None:
                    hold()
                revoked = True
            else:
                hold()
            previous = contract.digest(row)
        # Bounded work; exhaustion blocks instead of pruning safety evidence.
        hold()

    def _append(self, sequence, previous, action, operation=None, digest=None):
        if sequence >= MAX_EVENTS:
            hold()
        row = {"schema": SCHEMA, "scope_sha256": self.scope,
               "sequence": sequence, "previous_sha256": previous,
               "action": action, "operation_id": operation, "request_sha256": digest}
        try:
            result = self.client.put_object(**self._args(sequence),
                Body=contract.canonical(row), ContentType="application/json",
                IfNoneMatch="*")
            if result.get("ResponseMetadata", {}).get("HTTPStatusCode") != 200:
                hold()
        except (ClientError, BotoCoreError):
            # Includes 409, 412 and lost ACK. Never advance to another slot.
            hold()
        if self._get(sequence) != row:
            hold()

    def claim_once(self, scope_digest, operation_id, request_digest):
        if (not contract.match(operation_id, contract.H32)
                or not contract.match(request_digest, contract.SHA)):
            hold()
        sequence, previous, claims, revoked = self._scan(scope_digest)
        if revoked or operation_id in claims:
            hold()
        self._append(sequence, previous, "claim", operation_id, request_digest)

    def revoke(self, scope_digest):
        sequence, previous, _, revoked = self._scan(scope_digest)
        if revoked:
            hold()
        self._append(sequence, previous, "revoke")

    def inspect_current(self, scope_digest):
        _, _, _, revoked = self._scan(scope_digest)
        return {"revoked": revoked}

    def inspect_claim(self, scope_digest, operation_id, request_digest):
        if (not contract.match(operation_id, contract.H32)
                or not contract.match(request_digest, contract.SHA)):
            hold()
        _, _, claims, _ = self._scan(scope_digest)
        if claims.get(operation_id) != request_digest:
            hold()
        return {"scope_sha256": scope_digest, "operation_id": operation_id,
                "request_sha256": request_digest}
