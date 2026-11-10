"""Task C v3 read-only broker: installation history, scoped operation consent.

A separately authenticated native installer selects the registered installation,
genesis, anchored commit and GetObject-only role. The signed broker purpose and
original operator/GitHub grants remain per operation. No S3 writes, discovery,
SSM credential, new genesis, or native admission is available here.
"""
from __future__ import annotations

import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import graphical_operation_owner_source as op
from . import graphical_task_c_owner as taskc
from . import graphical_task_c_origin as origin
from . import graphical_installation_storage_authority as storage
from .graphical_native_owner import hold

PURPOSE_SCHEMA = "zog-task-c-installation-readonly-purpose-v3"
PURPOSE_DOMAIN = b"zog-task-c-installation-readonly-purpose-v3\0"
PURPOSE_FIELDS = frozenset((
    "schema", "pin_sha256", "original_checkpoint_sha256",
    "original_event_sha256", "operator_public_sha256",
    "issuer_public_sha256", "owner_source_sha256",
    "broker_source_sha256", "readonly_role_arn", "writer_role_arn",
    "ssm_role_arn", "host_id", "installation_id", "state_volume_id",
    "scope_sha256", "installation_scope_sha256",
    "installation_storage_commit_sha256",
    "gateway_uid", "gateway_gid", "gateway_cgroup",
    "gateway_executable_sha256", "expires_at", "signature_ed25519",
))
BROKER_CONFIG_SCHEMA = "zog-task-c-readonly-broker-installed-v3"


def verify_installation_broker_selection(
    *, storage_record, storage_commit, root_row, broker_config,
    registry, evidence, operator_key, issuer_key, observation_public,
    pin, pin_sha, approval, broker_signer, selected_broker_sha,
    selected_root_source_sha, now,
):
    """Pure v3 selection, requiring signed operation and fixed installation.

    The caller must FIRST validate the registered installation, installer
    commit and independently retained anchor via root's native storage reader.
    A syntactically valid record supplied by a gateway is never sufficient.
    """
    from . import graphical_task_c_trust_authority as trust
    from zog.host_deploy.gateway import graphics_owner_trust_history as wire

    from . import graphical_task_c_root_backed_storage as root_backed
    local_root_mode = (type(root_row) is dict and root_row.get("schema") in (
        "zog-protected-task-c-installed-runtime-root-backed-v4",
        "zog-protected-task-c-installed-runtime-local-root-backed-v4"))
    required_fields = (root_backed.AUTHORITY_KEYS if local_root_mode
                       else storage.AUTHORITY_KEYS)
    required_schema = (root_backed.AUTHORITY_SCHEMA if local_root_mode
                       else storage.AUTHORITY_SCHEMA)
    required_mode = (root_backed.MODE if local_root_mode
                     else storage.SOURCE_MODE)
    if (type(storage_record) is not dict
            or set(storage_record) != required_fields
            or storage_record.get("schema") != required_schema
            or storage_record.get("mode") != required_mode
            or type(storage_commit) is not dict
            or type(root_row) is not dict
            or root_row.get("schema") not in (
                "zog-protected-task-c-installed-runtime-v3",
                "zog-protected-task-c-installed-runtime-local-v1",
                "zog-protected-task-c-installed-runtime-root-backed-v4",
                "zog-protected-task-c-installed-runtime-local-root-backed-v4")
            or type(root_row.get("storage_authority")) is not dict
            or root_row["storage_authority"].get(
                "storage_authority_sha256") != op.digest(storage_record)
            or root_row["storage_authority"].get(
                "storage_commit_sha256") != op.digest(storage_commit)
            or root_row["storage_authority"].get(
                "installation_scope_sha256") !=
                storage_record["installation_scope_sha256"]
            or type(broker_config) is not dict
            or set(broker_config) != {
                "schema", "broker_source_sha256", "root_source_sha256",
                "gateway_uid", "gateway_gid", "gateway_cgroup",
                "gateway_executable_sha256", "boot_id"}
            or broker_config.get("schema") != BROKER_CONFIG_SCHEMA
            or not op.match(selected_root_source_sha, op.SHA)
            or broker_config.get("broker_source_sha256") != selected_broker_sha
            or broker_config.get("root_source_sha256") != selected_root_source_sha
            or type(operator_key) is not bytes or len(operator_key) != 32
            or type(issuer_key) is not bytes or len(issuer_key) != 32
            or operator_key == issuer_key
            or not isinstance(registry, taskc.ProtectedOriginalRegistry)
            or registry.key != operator_key
            or type(observation_public) is not bytes or len(observation_public) != 32
            or not hasattr(broker_signer, "public_key")
            or type(pin) is not dict or set(pin) != wire.PIN_KEYS
            or pin.get("schema") != wire.PIN_SCHEMA_V3
            or type(approval) is not dict or set(approval) != PURPOSE_FIELDS
            or approval.get("schema") != PURPOSE_SCHEMA
            or type(now) is not int
            or type(approval.get("expires_at")) is not int
            or not now <= approval["expires_at"] <= now + 900
            or not op.match(selected_broker_sha, op.SHA)
            or type(broker_config.get("gateway_uid")) is not int
            or broker_config["gateway_uid"] < 1000
            or type(broker_config.get("gateway_gid")) is not int
            or broker_config["gateway_gid"] <= 0
            or type(broker_config.get("gateway_cgroup")) is not str
            or not broker_config["gateway_cgroup"].startswith("/system.slice/")
            or not broker_config["gateway_cgroup"].endswith(".service")
            or not op.match(broker_config.get("gateway_executable_sha256"), op.SHA)):
        hold()
    entries = list(registry.entries.values())
    if not entries:
        hold()
    request = entries[0]["owner_request"]
    op_scope = op.digest(op.scope_from_request(request))
    if (any(op.digest(op.scope_from_request(e["owner_request"])) != op_scope
            for e in entries)
            or any(e["owner_request"]["host_id"] != root_row.get("host_id")
                   or e["owner_request"]["installation_id"] !=
                        root_row.get("installation_id")
                   or e["owner_request"]["state_volume_id"] !=
                        root_row.get("state_volume_id") for e in entries)):
        hold()
    signer_pub = broker_signer.public_key().public_bytes_raw()
    expected_pin_sha = op.digest(pin)
    if (pin["broker_public_key"] != signer_pub.hex()
            or pin["owner_observation_public_key"] != observation_public.hex()
            or pin["scope_sha256"] != op_scope
            or pin["installation_id"] != request["installation_id"]
            or pin["state_volume_id"] != request["state_volume_id"]
            or pin["original_checkpoint_sha256"] != op.digest(storage_record)
            or pin["installed_owner_source"] != selected_root_source_sha[7:]
            or pin["installed_broker_source"] != selected_broker_sha[7:]
            or pin_sha != expected_pin_sha):
        hold()
    selected = {
        "schema": PURPOSE_SCHEMA,
        "pin_sha256": pin_sha,
        "original_checkpoint_sha256": op.digest(storage_record),
        "original_event_sha256": op.digest(evidence),
        "operator_public_sha256": trust.digest_bytes(operator_key),
        "issuer_public_sha256": trust.digest_bytes(issuer_key),
        "owner_source_sha256": selected_root_source_sha,
        "broker_source_sha256": selected_broker_sha,
        "readonly_role_arn": storage_record["checkpoint_reader_role_arn"],
        "writer_role_arn": storage_record["checkpoint_writer_role_arn"],
        "ssm_role_arn": root_row.get("ssm", {}).get("role_arn"),
        "host_id": request["host_id"],
        "installation_id": request["installation_id"],
        "state_volume_id": request["state_volume_id"],
        "scope_sha256": op_scope,
        "installation_scope_sha256":
            storage_record["installation_scope_sha256"],
        "installation_storage_commit_sha256": op.digest(storage_commit),
        "gateway_uid": broker_config["gateway_uid"],
        "gateway_gid": broker_config["gateway_gid"],
        "gateway_cgroup": broker_config["gateway_cgroup"],
        "gateway_executable_sha256":
            broker_config["gateway_executable_sha256"],
        "expires_at": approval["expires_at"],
    }
    if (any(approval.get(k) != v for k,v in selected.items())
            or not op.match(approval.get("pin_sha256"), op.SHA)
            or any(type(approval.get(k)) is not str
                   or not trust.ROLE.fullmatch(approval[k])
                   for k in ("readonly_role_arn","writer_role_arn",
                             "ssm_role_arn"))
            or len({selected[k] for k in ("readonly_role_arn",
                  "writer_role_arn", "ssm_role_arn")}) != 3
            or trust.ROLE.fullmatch(
                selected["readonly_role_arn"]).group(1) !=
                storage_record["checkpoint_account_id"]
            or root_row.get("checkpoint", {}).get("account_id") !=
                storage_record["checkpoint_account_id"]
            or root_row["checkpoint"].get("region") !=
                storage_record["checkpoint_region"]
            or root_row["checkpoint"].get("bucket") !=
                storage_record["checkpoint_bucket"]
            or root_row["checkpoint"].get("prefix") !=
                storage_record["checkpoint_prefix"]
            or root_row["checkpoint"].get("genesis_sha256") !=
                storage_record["checkpoint_genesis_sha256"]
            or root_row["checkpoint"].get("role_arn") !=
                storage_record["checkpoint_writer_role_arn"]
            or root_row.get("operator_key_sha256") !=
                trust.digest_bytes(operator_key)
            or root_row.get("origin_issuer_public_sha256") !=
                trust.digest_bytes(issuer_key)
            or root_row.get("origin_evidence_sha256") != op.digest(evidence)
            or root_row.get("observation_public_sha256") !=
                trust.digest_bytes(observation_public)):
        hold()
    try:
        signed = base64.b64decode(
            approval["signature_ed25519"], validate=True)
        if (len(signed) != 64 or
                base64.b64encode(signed).decode("ascii") !=
                approval["signature_ed25519"]):
            hold()
        Ed25519PublicKey.from_public_bytes(operator_key).verify(
            signed, PURPOSE_DOMAIN + op.canonical(selected))
    except (ValueError, TypeError, InvalidSignature):
        hold()
    origin.verify_installed_evidence(
        evidence, registry=registry, pinned_issuer_key=issuer_key, now=now)
    return selected["readonly_role_arn"], op_scope
