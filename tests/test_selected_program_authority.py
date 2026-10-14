"""Privileged systemd refuses any unrecorded or forged selected-program start."""
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from zog.root_control.systemd import BusctlSystemdBackend, SystemdBackendError
from zog.box_control.operations import OperationStore
from zog.box_control.requests import ApplicationRequestStore
from zog.box_control.model import ApplicationRuntimeState
from zog.box_control.runtime.reference import (
    ApplicationRuntimeReference, ProgramRuntimeReference, RuntimeReferenceStore,
)


def evidence(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    expected = {
        "unit_name": "zog-project-ABC123-renew.service",
        "runtime_id": "ABC123",
        "application_name": "certify-manage",
        "program_name": "renew",
        "selected_program": "renew",
        "command": ["/usr/bin/python3", "-m", "zog.certify_manage", "renew"],
        "environment": [["SAFE", "yes"]],
        "working_directory": "/",
        "user": "200001",
        "group": "200001",
        "execution_timeout_seconds": 120,
        "execution_binding": {"schema": "zog-execution-identity-v1",
                              "uid": 200001, "gid": 200001},
        "persistent_storage_id": "a" * 32,
    }
    saved_program = {
        "name": "renew", "command": list(expected["command"]),
        "environment": list(expected["environment"]), "working_directory": None,
        "user": "200001", "group": "200001", "execution_timeout_seconds": 120,
    }
    record = {
        "new_runtime_id": "ABC123", "operation": "launch",
        "request_id": "REQ1", "phase": "launching",
        "selected_program": "renew",
        "attempted_units": [expected["unit_name"]],
        "application": {
            "name": "certify-manage", "selected_program": "renew",
            "programs": [saved_program],
            "execution_binding": dict(expected["execution_binding"]),
            "storage_id": expected["persistent_storage_id"],
        },
    }
    ref = ApplicationRuntimeReference(
        runtime_id="ABC123", application="certify-manage",
        instance_id="certify-manage", generation="image",
        state=ApplicationRuntimeState.STARTING,
        request_id="REQ1", execution_binding=dict(expected["execution_binding"]),
        programs=(ProgramRuntimeReference(
            program="renew", unit_name=expected["unit_name"],
            command=tuple(expected["command"]),
        ),),
    )
    record["references"] = RuntimeReferenceStore.encode({"ABC123": ref})
    request = SimpleNamespace(
        operation=SimpleNamespace(value="launch"), application="certify-manage",
        program_name="renew",
    )
    monkeypatch.setattr(OperationStore, "records", lambda _self: [record])
    monkeypatch.setattr(ApplicationRequestStore, "load", lambda _self, _path: request)
    return project, expected, record, request


def test_privileged_exact_selected_intent_is_accepted(tmp_path, monkeypatch):
    project, definition, _record, _request = evidence(tmp_path, monkeypatch)
    BusctlSystemdBackend._validate_program_selection(project, definition)


@pytest.mark.parametrize("field,value", [
    ("selected_program", "issue"),
    ("program_name", "issue"),
    ("command", ["/usr/bin/python3", "-m", "zog.certify_manage", "issue"]),
    ("execution_binding", {"schema": "zog-execution-identity-v1", "uid": 0, "gid": 0}),
    ("persistent_storage_id", "b" * 32),
    ("user", "0"),
    ("environment", [["TOKEN", "override"]]),
])
def test_privileged_forged_selection_command_or_identity_denied(tmp_path, monkeypatch, field, value):
    project, definition, _record, _request = evidence(tmp_path, monkeypatch)
    changed = dict(definition, **{field: value})
    with pytest.raises(SystemdBackendError, match="selected"):
        BusctlSystemdBackend._validate_program_selection(project, changed)


@pytest.mark.parametrize("mutate", ["no-record", "wrong-phase", "missing-start-intent",
                                     "wrong-snapshot", "wrong-request", "extra-program"])
def test_privileged_rejects_missing_or_conflicting_durable_authority(tmp_path, monkeypatch, mutate):
    project, definition, record, request = evidence(tmp_path, monkeypatch)
    if mutate == "no-record":
        monkeypatch.setattr(OperationStore, "records", lambda _self: [])
    elif mutate == "wrong-phase":
        record["phase"] = "prepared"
    elif mutate == "missing-start-intent":
        record["attempted_units"] = []
    elif mutate == "wrong-snapshot":
        record["application"]["selected_program"] = "issue"
    elif mutate == "extra-program":
        record["application"]["programs"].append(dict(record["application"]["programs"][0], name="issue"))
    else:
        request.program_name = "issue"
    with pytest.raises(SystemdBackendError, match="selected"):
        BusctlSystemdBackend._validate_program_selection(project, definition)


@pytest.mark.parametrize("command", ["issue", "renew", "inspect"])
def test_certificate_lifecycle_requires_explicit_selector_even_if_transport_is_forged(tmp_path, command):
    definition = dict(application_name="certify-manage", program_name=command,
                      selected_program=None)
    with pytest.raises(SystemdBackendError, match="selected-program"):
        BusctlSystemdBackend._validate_program_selection(tmp_path, definition)


def test_legacy_multiservice_without_selector_remains_compatible(tmp_path):
    BusctlSystemdBackend._validate_program_selection(
        tmp_path, dict(application_name="station-access", program_name="web"))



def test_privileged_rejects_selected_runtime_unit_or_command_drift(tmp_path, monkeypatch):
    project, definition, record, _request = evidence(tmp_path, monkeypatch)
    raw = dict(record["references"])
    altered = RuntimeReferenceStore.decode(raw)["ABC123"]
    from dataclasses import replace
    changed = replace(altered, programs=(replace(altered.programs[0], unit_name="foreign.service"),))
    record["references"] = RuntimeReferenceStore.encode({"ABC123": changed})
    with pytest.raises(SystemdBackendError, match="selected"):
        BusctlSystemdBackend._validate_program_selection(project, definition)
