"""The *real selected systemd admission adapter* uses the root fence.

All tests are synthetic, with a private directory and an injected backend.
Neither actual PID1 nor any protected Host directory is mutated.
"""
import hashlib
import inspect
import json
import os
import threading
from contextlib import contextmanager

import pytest

from zog.root_control import issuer_execution_adapter as adapter
from zog.root_control.issuer_execution_fence import (
    IssuerExecutionFence, IssuerFenceDenied, STATE,
)
from zog.root_control.systemd import BusctlSystemdBackend

BOOT = "a"*32
COMMIT = b'{"installation":"reviewed"}'


@pytest.fixture
def shared(tmp_path, monkeypatch):
    folder = tmp_path / "execution"
    folder.mkdir(mode=0o700)
    fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    fence = IssuerExecutionFence(fd, owner_uid=os.getuid())
    fence.initialize(trusted_commit_sha256=hashlib.sha256(COMMIT).hexdigest(),
                     boot_id=BOOT)
    @contextmanager
    def source(*, for_revocation=False):
        # Exact same inode and lock, independent open file descriptions.
        current = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            yield current, hashlib.sha256(COMMIT).hexdigest()
        finally:
            os.close(current)
    monkeypatch.setattr(adapter, "protected_execution_directory", source)
    monkeypatch.setattr(adapter, "_boot_id", lambda: BOOT)
    monkeypatch.setattr(adapter, "_saved_request_id",
                        lambda project_root, definition: "REQ-1")
    yield fence, folder
    os.close(fd)


class Backend:
    def __init__(self):
        self.jobs = 0
        self.invocation_id = "d"*32
    def _validate_program_selection(self, project_root, definition):
        assert project_root == "/example"
        assert definition["selected_program"] == "renew"
    def observe(self, **kwargs):
        return {"exists": True, "invocation_id": self.invocation_id}


DEF = {"application_name": "certify-manage", "selected_program": "renew",
       "runtime_id": "abcdef1234567890abcdef1234567890",
       "unit_name": "zog-certify-abcdef1234567890abcdef1234567890.service"}


def test_actual_selected_adapter_serializes_dispatch_with_revocation(shared):
    fence, folder = shared
    started, release, revoked = (threading.Event() for _ in range(3))
    backend = Backend()
    errors = []
    def dispatch():
        backend.jobs += 1
        started.set()
        assert release.wait(3)
    def launch():
        try:
            adapter.admit_selected_start(
                backend, project_root="/example", definition=DEF, dispatch=dispatch)
        except BaseException as exc:
            errors.append(exc)
    worker = threading.Thread(target=launch)
    worker.start()
    assert started.wait(3)
    revoker = threading.Thread(
        target=lambda: (fence.revoke(publish_pending_revocation=lambda: True),
                        revoked.set()))
    revoker.start()
    assert not revoked.wait(.05)
    release.set()
    worker.join(3)
    revoker.join(3)
    assert not errors and not worker.is_alive() and not revoker.is_alive()
    assert revoked.is_set()
    assert backend.jobs == 1
    record = json.loads((folder/STATE).read_text())
    assert record["revoked"] is True
    assert record["operations"]["REQ-1"]["phase"] == "cancel-pending"
    with pytest.raises(IssuerFenceDenied):
        adapter.admit_selected_start(
            backend, project_root="/example", definition=DEF, dispatch=dispatch)
    assert backend.jobs == 1


def test_lost_real_dispatch_ack_is_never_reexecuted(shared):
    fence, folder = shared
    backend = Backend()
    count = []
    def dispatched_but_lost():
        count.append("PID1 may have accepted")
        raise OSError("lost systemd ack")
    with pytest.raises(OSError):
        adapter.admit_selected_start(
            backend, project_root="/example", definition=DEF,
            dispatch=dispatched_but_lost)
    assert json.loads((folder/STATE).read_text())[
        "operations"]["REQ-1"]["phase"] == "admission-uncertain"
    with pytest.raises(IssuerFenceDenied):
        adapter.admit_selected_start(
            backend, project_root="/example", definition=DEF,
            dispatch=dispatched_but_lost)
    assert len(count) == 1
    with pytest.raises(IssuerFenceDenied):
        fence.reconcile(
            request_id="REQ-1",
            verify_stopped_and_clean=lambda **_kw: False,
        )


def test_absent_or_invalid_observation_remains_uncertain(shared):
    fence, folder = shared
    backend = Backend()
    backend.invocation_id = None
    dispatched = []
    with pytest.raises(IssuerFenceDenied):
        adapter.admit_selected_start(
            backend, project_root="/example", definition=DEF,
            dispatch=lambda: dispatched.append(1))
    assert dispatched == [1]
    assert json.loads((folder/STATE).read_text())[
        "operations"]["REQ-1"]["phase"] == "admission-uncertain"


def test_exact_systemd_launch_path_is_fenced_and_not_an_optional_preflight():
    source = inspect.getsource(BusctlSystemdBackend.start_service)
    assert "admit_selected_start(" in source
    assert "dispatch=dispatch_job" in source
    assert "if (definition.get(\"application_name\") == \"certify-manage\"" in source
    assert "else:\n                dispatch_job()" in source
    # The ELSE applies to non-selected services; selected 'issue' is
    # deliberately denied by the fixed fence, not executed unfenced.


def test_unsupported_selected_program_rejected_without_dispatch(shared):
    b = Backend()
    definition = {**DEF, "selected_program":"issue"}
    touched = []
    with pytest.raises(IssuerFenceDenied):
        adapter.admit_selected_start(
            b, project_root="/example", definition=definition,
            dispatch=lambda: touched.append(1))
    assert touched == []
