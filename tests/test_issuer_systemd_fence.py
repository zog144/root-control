"""Actual privileged systemd selected start path uses the durable root epoch.

No real PID1 / certificate issuance. Only the validation and dispatch adapter
are replaced; the execution ledger/lock and start_service wrapper are real.
"""
import os
import threading
from contextlib import contextmanager

import pytest

from zog.root_control.systemd import BusctlSystemdBackend, SystemdBackendError
from zog.root_control import issuer_execution_fence as epoch
from zog.root_control.issuer_execution_fence import IssuerExecutionFence, IssuerFenceDenied


@pytest.fixture
def entry(tmp_path, monkeypatch):
    protected = tmp_path / "execution"
    protected.mkdir(mode=0o700)
    fd = os.open(protected, os.O_RDONLY | os.O_DIRECTORY)
    commit = "f" * 64
    initial = IssuerExecutionFence(fd, owner_uid=os.getuid())
    initial.initialize(trusted_commit_sha256=commit, boot_id="a"*32)

    @contextmanager
    def installed():
        yield IssuerExecutionFence(fd, owner_uid=os.getuid()), commit

    monkeypatch.setattr(epoch, "installed_fence", installed)
    monkeypatch.setattr(epoch, "current_boot_id", lambda: "a"*32)
    backend = BusctlSystemdBackend()
    commands = []
    monkeypatch.setattr(backend, "_validate_service_definition", lambda *args: None)
    monkeypatch.setattr(backend, "_validate_program_selection",
                        lambda *args: "REQ1")
    monkeypatch.setattr(backend, "_start_service_validated",
                        lambda **kw: commands.append(kw["definition"]["program_name"]))
    monkeypatch.setattr(backend, "observe", lambda **kw: {
        "exists": True, "unit_name": kw["unit_name"], "transient": True,
        "invocation_id": "b"*32,
    })
    definition = {
        "application_name": "certify-manage", "selected_program": "renew",
        "program_name": "renew", "unit_name": "zog-issuer-RUNTIME1-renew.service",
        "runtime_id": "RUNTIME1",
    }
    try:
        yield backend, definition, commands, initial
    finally:
        os.close(fd)


def start(backend, definition):
    return backend.start_service(project_root="/synthetic", generation="candidate",
                                 definition=definition)


def test_real_start_service_enters_root_epoch_before_dispatch(entry):
    backend, definition, commands, fence = entry
    start(backend, definition)
    assert commands == ["renew"]
    state = fence._read()
    saved = state["operations"]["REQ1"]
    assert saved["program"] == "renew" and saved["phase"] == "running"
    assert saved["runtime_id"] == "RUNTIME1"
    assert saved["invocation_id"] == "b"*32
    with pytest.raises(SystemdBackendError, match="protected selected"):
        start(backend, definition)
    assert commands == ["renew"]


def test_real_start_service_does_not_launch_on_revoked_epoch(entry):
    backend, definition, commands, fence = entry
    fence.revoke(publish_pending_revocation=lambda: True)
    with pytest.raises(SystemdBackendError, match="protected selected"):
        start(backend, definition)
    assert commands == []


def test_real_start_service_retains_uncertain_result_and_prevents_retry(entry, monkeypatch):
    backend, definition, commands, fence = entry
    def lost(**kw):
        commands.append("attempted")
        raise OSError("simulated PID1 response loss")
    monkeypatch.setattr(backend, "_start_service_validated", lost)
    with pytest.raises(SystemdBackendError, match="protected selected"):
        start(backend, definition)
    assert commands == ["attempted"]
    assert fence._read()["operations"]["REQ1"]["phase"] == "admission-uncertain"
    with pytest.raises(SystemdBackendError):
        start(backend, definition)
    assert commands == ["attempted"]


def test_kernel_boot_epoch_marks_original_runtime_for_cleanup(entry, monkeypatch):
    backend, definition, commands, fence = entry
    start(backend, definition)
    monkeypatch.setattr(epoch, "current_boot_id", lambda: "c"*32)
    monkeypatch.setattr(backend, "_validate_program_selection",
                        lambda *args: "REQ2")
    with pytest.raises(SystemdBackendError):
        start(backend, definition)
    state = fence._read()
    assert state["boot_id"] == "c"*32
    assert state["operations"]["REQ1"]["phase"] == "cancel-pending"
    assert commands == ["renew"]


def test_other_apps_remain_unchanged_and_legacy_issuer_is_denied(entry):
    backend, definition, commands, _ = entry
    generic = dict(definition, application_name="gedit", selected_program=None,
                   program_name="editor")
    start(backend, generic)
    assert commands == ["editor"]
    with pytest.raises(SystemdBackendError, match="requires approved broker"):
        start(backend, dict(definition, selected_program="issue",
                            program_name="issue"))
    assert commands == ["editor"]


def test_no_second_privileged_selected_start_entrypoint_is_exposed():
    """Generic daemon RPC must pass through the single protected wrapper."""
    import inspect
    from pathlib import Path
    from zog.root_control import systemd
    source = inspect.getsource(systemd.BusctlSystemdBackend.start_service)
    # The minimal root-control source test intentionally lacks the separate
    # box-control image-build dependency required to import daemon itself.
    handler = (Path(systemd.__file__).parent / "daemon.py").read_text()
    assert "with installed_fence()" in source
    assert "fence.admit(" in source
    assert "fence.reboot(" in source
    assert "self.systemd.start_service(" in handler
    assert "self.systemd._start_service_validated(" not in handler
    assert "issuer_execution_adapter" not in handler
    assert not (Path(systemd.__file__).parent /
                "issuer_execution_adapter.py").exists()
