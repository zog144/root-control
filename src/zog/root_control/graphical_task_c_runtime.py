"""Original Task C stream operation executor; never grants authority from IPC.

Copyright (c) 2026 Alex Black. BSD-3-Clause OR GPL-3.0-only.

Pure source adapter connecting the independently signed root registry to the
protected ledger, append-only external checkpoint, fixed owner SSM sender and
read-only SSM result inspection. The executable remains disabled pending
independent native source/installation/credential and peer admission.
"""
from __future__ import annotations

import base64
import re

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import graphical_operation_owner_source as contract
from . import graphical_task_c_owner as taskc
from .graphical_native_owner import SelectedOwner, hold
from .graphical_s3_checkpoint import S3AppendOnlyCheckpoint
from .graphical_s3_installation_checkpoint import S3InstallationCheckpoint

RESULT_SCHEMA = "zog-graphical-task-c-owner-observation-v2"
RESULT_DOMAIN = b"zog-graphical-task-c-owner-observation-v2\0"
COMMAND_ID = re.compile(r"[A-Za-z0-9-]{1,128}\Z")


class TaskCExecutor:
    """Original-operation admission; no caller-selected target, script or keys.

    Executor construction is restricted to the protected service. Fake owner
    and inspector objects are usable in source tests only. Neither those
    objects nor the registry can be supplied through the Unix socket.
    """

    def __init__(self, registry, *, protected_owner, ssm_inspector, backend_recheck=None):
        if (not isinstance(registry, taskc.ProtectedOriginalRegistry)
                or not isinstance(protected_owner, SelectedOwner)
                or not isinstance(protected_owner.signer, Ed25519PrivateKey)
                or not isinstance(protected_owner.ledger.checkpoint,
                                  (S3AppendOnlyCheckpoint, S3InstallationCheckpoint))
                or (backend_recheck is not None
                    and not callable(backend_recheck))
                or (isinstance(protected_owner.ledger.checkpoint,
                               S3InstallationCheckpoint)
                    and backend_recheck is None)
                or not callable(getattr(ssm_inspector, "inspect", None))):
            hold()
        self.registry = registry
        self.owner = protected_owner
        self.inspector = ssm_inspector
        self.backend_recheck = backend_recheck
        selected = self.owner.installed
        if (set(selected["approved"]) != set(registry.entries)
                or set(selected["commands"]) != set(registry.entries)
                or selected["identity"] != contract.digest(selected["scope"])
                or registry.key != self.owner.operator_key):
            hold()
        for operation_id, item in registry.entries.items():
            req = item["owner_request"]
            command = selected["commands"][operation_id]
            if (contract.digest(req) != selected["approved"][operation_id]
                    or contract.scope_from_request(req) != selected["scope"]
                    or command["approval_id"] != item["approval"].get("approval_id")):
                hold()

    def _current(self, req):
        # Called only while holding the owner critical section. Remote S3
        # current history is checked before anything is signed.
        row = self.owner.ledger.inspect(req, scope=self.owner.installed)
        witness = self.owner.ledger.checkpoint.current_witness(
            self.owner.installed["identity"])
        if (row["revoked"] or witness["revoked"] or
                type(witness["sequence"]) is not int or
                witness["sequence"] < 1 or
                not contract.match(witness["history_sha256"], contract.SHA)):
            hold()
        command_id = row["command_id"]
        if command_id is None:
            return row, "uncertain", witness
        if (not isinstance(command_id, str)
                or COMMAND_ID.fullmatch(command_id) is None):
            hold()
        state = self.inspector.inspect(command_id)
        if state not in ("pending", "success", "failed"):
            hold()
        return row, state, witness

    def _preflight_succeeded(self, original, stage_id):
        preflight_operation = taskc.preflight_id(original["request_id"], stage_id)
        selected = self.registry.entries.get(preflight_operation)
        if selected is None:
            hold()
        # The same operator-signed original identity must be selected for
        # both operations; the preflight must not inherit the stage claim.
        if (selected["stage_operation_id"] != stage_id
                or selected["original"]["operation_id"] != preflight_operation):
            hold()
        for key in taskc.ORIGINAL_KEYS - {"operation_id"}:
            if selected["original"][key] != original[key]:
                hold()
        row, state, witness = self._current(selected["owner_request"])
        if row["outcome"] != "SENT_ORIGINAL" or state != "success":
            hold()

    def _claim_and_send(self, item, *, now):
        req = item["owner_request"]
        operation_id = req["operation_id"]
        command = self.owner.installed["commands"][operation_id]
        approval = item["approval"]
        grant = contract.verify_original_operator_approval(
            req, approval, externally_pinned_operator_key=self.owner.operator_key,
            expected_approval_id=command["approval_id"], now=now)
        if (contract.scope_from_request(req) != self.owner.installed["scope"]
                or grant["request_sha256"] !=
                self.owner.installed["approved"][operation_id]):
            hold()
        # Same serialized lock covers independent S3 claim, local fsync,
        # one SSM attempt and local result fsync. Never send on a lost ACK.
        self.owner.ledger.claim(req, scope=self.owner.installed,
                                preapproved_sha=grant["request_sha256"])
        command_id = self.owner.sender.send_fixed(operation_id, command)
        if (type(command_id) is not str or
                COMMAND_ID.fullmatch(command_id) is None):
            hold()
        self.owner.ledger.record(req, command_id)

    def handle(self, frame, *, now):
        if type(now) is not int:
            hold()
        # A frame is a selector, not a signed grant. Re-run the strict parser
        # even for source callers; the Unix transport parses it first.
        if self.backend_recheck is not None:
            # A live protected backend observer is required on each v3 call
            # even for an observe-only frame. No caller-provided flag counts.
            evidence = self.backend_recheck()
            if (type(evidence) is not dict
                    or set(evidence) != {
                        "backend", "registry_sha256",
                        "installation_scope_sha256", "live_snapshot_sha256",
                        "observation_sha256"}
                    or evidence["installation_scope_sha256"] !=
                       self.owner.ledger.checkpoint.scope
                    or evidence["registry_sha256"] !=
                       self.owner.ledger.checkpoint.registry_sha
                    or evidence["backend"] not in (
                        "mounted-volume", "root-directory")
                    or any(not contract.match(evidence[k], contract.SHA)
                           for k in ("registry_sha256",
                                     "installation_scope_sha256",
                                     "live_snapshot_sha256",
                                     "observation_sha256"))):
                hold()
        parsed = taskc.parse_frame(taskc.canonical(frame) + b"\n")
        item = self.registry.select(parsed)
        request = item["owner_request"]
        with self.owner.ledger.locked():
            if parsed["action"] == "submit-original":
                self._preflight_succeeded(item["original"], item["stage_operation_id"])
                self._claim_and_send(item, now=now)
            elif parsed["action"] == "preflight-original":
                self._claim_and_send(item, now=now)
            elif parsed["action"] != "observe-original":
                hold()

            row, ssm_state, witness = self._current(request)
            is_preflight = request["operation_id"] != item["stage_operation_id"]
            if row["outcome"] != "SENT_ORIGINAL":
                status = "claimed-uncertain"
            elif is_preflight:
                status = ("preflight-ready" if ssm_state == "success" else
                          "preflight-failed" if ssm_state == "failed" else
                          "preflight-pending")
            else:
                # A failure must never share a success-shaped label.
                # Neither status implies immutable image-generation success.
                status = ("stage-succeeded" if ssm_state == "success" else
                          "stage-failed" if ssm_state == "failed" else
                          "stage-pending")
            body = {
                "schema": RESULT_SCHEMA,
                "action": parsed["action"],
                "nonce": parsed["nonce"],
                "operation_id": request["operation_id"],
                "request_sha256": contract.digest(request),
                "original_request_sha256": parsed["original_request_sha256"],
                "scope_sha256": self.owner.installed["identity"],
                "host_id": request["host_id"],
                "installation_id": request["installation_id"],
                "state_volume_id": request["state_volume_id"],
                "authority_epoch": request["authority_epoch"],
                "command_id": row["command_id"],
                "ssm_state": ssm_state,
                "status": status,
                "revoked": row["revoked"],
                "checkpoint_sequence": witness["sequence"],
                "checkpoint_head_sha256": witness["history_sha256"],
            }
            sig = self.owner.signer.sign(RESULT_DOMAIN + contract.canonical(body))
            return {**body, "signature_ed25519":
                    base64.b64encode(sig).decode("ascii")}
