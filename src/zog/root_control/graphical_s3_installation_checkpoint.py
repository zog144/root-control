"""Installation-scoped append-only S3, with *separate* per-request claims/revoke.

The stable installation digest selects the S3 genesis and prefix. Per-operation
scope, request digest and ID are separately authenticated by the protected
owner before a claim; a revocation blocks its own request scope, not unrelated
future requests on this installation. No genesis creation or retry after lost ACK.
"""
from __future__ import annotations

from botocore.exceptions import ClientError, BotoCoreError

from . import graphical_operation_owner_source as operation
from .graphical_native_owner import hold
from .graphical_s3_checkpoint import S3AppendOnlyCheckpoint, MAX_EVENTS
from .graphical_installation_storage_authority import (
    GENESIS_SCHEMA, prospective_genesis,
)

SCHEMA = "zog-task-c-installation-checkpoint-v1"


class S3InstallationCheckpoint(S3AppendOnlyCheckpoint):
    """Same owner-selected S3 credential, stronger independent scope model.

    approved is a fixed installed map:
      {operation_scope_sha256: {operation_id: full_request_sha256, ...}}
    The map is *not* selected by a gateway IPC request.
    """

    def __init__(self, client, *, bucket, prefix, account_id,
                 installation_scope_sha256, registry_sha256,
                 genesis_sha256, approved):
        super().__init__(
            client, bucket=bucket, prefix=prefix, account_id=account_id,
            scope_digest=installation_scope_sha256,
            genesis_sha256=genesis_sha256)
        if (not operation.match(registry_sha256, operation.SHA)
                or type(approved) is not dict or not approved
                or genesis_sha256 != operation.digest(prospective_genesis(
                    installation_scope_sha256, registry_sha256))):
            hold()
        unique_ids = set()
        selected = {}
        for op_scope, rows in approved.items():
            if (not operation.match(op_scope, operation.SHA) or
                    type(rows) is not dict or not rows):
                hold()
            selected[op_scope] = {}
            for op_id, request_sha in rows.items():
                if (not operation.match(op_id, operation.H32) or
                        not operation.match(request_sha, operation.SHA) or
                        op_id in unique_ids):
                    hold()
                selected[op_scope][op_id] = request_sha
                unique_ids.add(op_id)
        self.registry_sha = registry_sha256
        self.approved = selected

    def _scan_installation(self):
        genesis = self._get(0)
        if (genesis != prospective_genesis(self.scope, self.registry_sha)
                or operation.digest(genesis) != self.genesis_sha):
            hold()
        claims = {}
        revoked_scopes = set()
        previous = self.genesis_sha
        for sequence in range(1, MAX_EVENTS + 1):
            row = self._get(sequence)
            if row is None:
                return sequence, previous, claims, revoked_scopes
            if (type(row) is not dict
                    or set(row) != {
                        "schema", "installation_scope_sha256", "sequence",
                        "previous_sha256", "action", "operation_scope_sha256",
                        "operation_id", "request_sha256"}
                    or row["schema"] != SCHEMA
                    or row["installation_scope_sha256"] != self.scope
                    or type(row["sequence"]) is not int
                    or row["sequence"] != sequence
                    or row["previous_sha256"] != previous
                    or not operation.match(row["operation_scope_sha256"],
                                           operation.SHA)):
                hold()
            scope = row["operation_scope_sha256"]
            if row["action"] == "claim":
                op_id = row["operation_id"]
                if (not operation.match(op_id, operation.H32)
                        or not operation.match(row["request_sha256"],
                                               operation.SHA)
                        or (scope in self.approved and
                            self.approved[scope].get(op_id) !=
                                row["request_sha256"])
                        or op_id in claims or scope in revoked_scopes):
                    hold()
                # Earlier immutable events may belong to a previously
                # completed request no longer present in this runtime's
                # active signed-operation registry. Still verify every old
                # event's syntax/hash link and globally unique ID. For any
                # *currently selected* scope also enforce its exact signed
                # approval/request map.
                claims[op_id] = (scope, row["request_sha256"])
            elif row["action"] == "revoke":
                if (row["operation_id"] is not None
                        or row["request_sha256"] is not None
                        or scope in revoked_scopes):
                    hold()
                revoked_scopes.add(scope)
            else:
                hold()
            previous = operation.digest(row)
        hold()  # A full sequence cannot wrap, truncate or prune evidence.

    def _append_installation(self, sequence, previous, action, scope,
                             op_id=None, request_sha=None):
        if sequence >= MAX_EVENTS:
            hold()
        row = {
            "schema": SCHEMA,
            "installation_scope_sha256": self.scope,
            "sequence": sequence,
            "previous_sha256": previous,
            "action": action,
            "operation_scope_sha256": scope,
            "operation_id": op_id,
            "request_sha256": request_sha,
        }
        try:
            result = self.client.put_object(
                **self._args(sequence), Body=operation.canonical(row),
                ContentType="application/json", IfNoneMatch="*")
            if result.get("ResponseMetadata", {}).get("HTTPStatusCode") != 200:
                hold()
        except (ClientError, BotoCoreError):
            # 409, 412, network loss and uncertain ACK are irrevocable HOLDS.
            hold()
        if self._get(sequence) != row:
            hold()

    def claim_once(self, scope_digest, operation_id, request_digest):
        if (scope_digest not in self.approved or
                self.approved[scope_digest].get(operation_id) != request_digest):
            hold()
        sequence, previous, claims, revoked = self._scan_installation()
        if operation_id in claims or scope_digest in revoked:
            hold()
        self._append_installation(
            sequence, previous, "claim", scope_digest,
            operation_id, request_digest)

    def revoke(self, scope_digest):
        if scope_digest not in self.approved:
            hold()
        sequence, previous, _, revoked = self._scan_installation()
        if scope_digest in revoked:
            hold()
        self._append_installation(sequence, previous, "revoke", scope_digest)

    def inspect_current(self, scope_digest):
        if scope_digest not in self.approved:
            hold()
        _, _, _, revoked = self._scan_installation()
        return {"revoked": scope_digest in revoked}

    def current_witness(self, scope_digest):
        if scope_digest not in self.approved:
            hold()
        sequence, head, _, revoked = self._scan_installation()
        return {"sequence": sequence - 1,
                "history_sha256": head,
                "revoked": scope_digest in revoked}

    def inspect_claim(self, scope_digest, operation_id, request_digest):
        if (scope_digest not in self.approved or
                self.approved[scope_digest].get(operation_id) != request_digest):
            hold()
        _, _, claims, _ = self._scan_installation()
        if claims.get(operation_id) != (scope_digest, request_digest):
            hold()
        return {"scope_sha256": scope_digest,
                "operation_id": operation_id,
                "request_sha256": request_digest}
