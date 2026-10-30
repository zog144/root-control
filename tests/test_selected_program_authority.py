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


@pytest.mark.parametrize("command", ["issue", "renew", "inspect", "stage"])
def test_certificate_lifecycle_requires_explicit_selector_even_if_transport_is_forged(tmp_path, command):
    definition = dict(application_name="certify-manage", program_name=command,
                      selected_program=None)
    with pytest.raises(SystemdBackendError, match="selected-program"):
        BusctlSystemdBackend._validate_program_selection(tmp_path, definition)


@pytest.mark.parametrize("program,selected", [
    ("inspect-server", None),
    ("inspect-server", "inspect-server"),
    ("recover", None),
    ("probe", "probe"),
])
def test_unreviewed_certificate_daemon_or_program_is_rejected_even_with_grant(tmp_path, program, selected):
    definition = dict(application_name="certify-manage", program_name=program,
                      selected_program=selected,
                      execution_binding={"schema": "zog-execution-identity-v1",
                                         "uid": 200001, "gid": 200001},
                      persistent_storage_id="a" * 32)
    with pytest.raises(SystemdBackendError, match="unsupported certificate"):
        BusctlSystemdBackend._validate_program_selection(tmp_path, definition)


def test_certificate_preparation_is_not_a_selected_runtime(tmp_path):
    BusctlSystemdBackend._validate_program_selection(
        tmp_path, dict(application_name="certify-manage",
                       program_name="prepare", selected_program=None))
    with pytest.raises(SystemdBackendError, match="not a selected runtime"):
        BusctlSystemdBackend._validate_program_selection(
            tmp_path, dict(application_name="certify-manage",
                           program_name="prepare", selected_program="prepare"))


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



def test_privileged_selected_stage_matches_exact_saved_stage_operation(tmp_path, monkeypatch):
    from dataclasses import replace
    project, definition, record, request = evidence(tmp_path, monkeypatch)
    stage_unit = definition["unit_name"].replace("-renew.service", "-stage.service")
    stage_command = ["/usr/bin/python3", "-m", "zog.certify_manage", "stage"]
    definition.update(
        unit_name=stage_unit, program_name="stage", selected_program="stage",
        command=stage_command,
    )
    record.update(selected_program="stage", attempted_units=[stage_unit])
    record["application"]["selected_program"] = "stage"
    record["application"]["programs"][0].update(name="stage", command=stage_command)
    prior = RuntimeReferenceStore.decode(record["references"])["ABC123"]
    change = replace(prior, programs=(replace(
        prior.programs[0], program="stage", unit_name=stage_unit,
        command=tuple(stage_command),
    ),))
    record["references"] = RuntimeReferenceStore.encode({"ABC123": change})
    request.program_name = "stage"
    BusctlSystemdBackend._validate_program_selection(project, definition)
    with pytest.raises(SystemdBackendError, match="selected"):
        BusctlSystemdBackend._validate_program_selection(
            project, dict(definition, selected_program="renew")
        )


@pytest.mark.parametrize("application,program", [
    ("greetd", "daemon"),
    ("login-manager", "greet"),
    ("display-manager", "greetd"),
    ("desktop", "greetd"),
    ("local-login-manager", "server"),
    ("desktop", "seatd"),
])
def test_unapproved_local_login_manager_never_reaches_systemd(application, program):
    definition = {"application_name": application, "program_name": program,
                  "user": "0", "group": "0", "command": ["/usr/bin/true"]}
    with pytest.raises(SystemdBackendError, match="local seat"):
        BusctlSystemdBackend._validate_local_login_manager(definition)


def test_local_login_fence_preserves_unprivileged_graphical_and_issuer_services():
    for application, program in (
        ("firefox", "browser"),
        ("x11-server", "xorg"),
        ("i3", "session"),
        ("certify-manage", "renew"),
        ("station-access", "web"),
    ):
        BusctlSystemdBackend._validate_local_login_manager(
            {"application_name": application, "program_name": program}
        )


def test_local_login_fence_occurs_before_any_systemd_runtime_path_inspection():
    with pytest.raises(SystemdBackendError, match="local seat"):
        BusctlSystemdBackend._validate_service_definition(
            "/not-a-real-project", "generation", {
                "application_name": "greetd", "program_name": "daemon",
                "unit_name": "forged.service",
            }
        )
