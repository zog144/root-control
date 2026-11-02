"""Source-only actual selected PID1 cancellation/reboot reconciliation regression."""
import os
from contextlib import contextmanager
from types import SimpleNamespace
import pytest

from zog.root_control import issuer_execution_reconcile as cleanup
from zog.root_control import issuer_execution_fence as module
from zog.root_control.issuer_execution_fence import IssuerExecutionFence, IssuerFenceDenied

BOOT = "a" * 32
NEXT = "b" * 32
COMMIT = "c" * 64
INVOCATION = "d" * 32
UNIT = "zog-issuer-RUNTIME1-renew.service"


@pytest.fixture
def prepared(tmp_path, monkeypatch):
    folder = tmp_path / "root"
    folder.mkdir(mode=0o700)
    fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
    fence = IssuerExecutionFence(fd, owner_uid=os.getuid())
    fence.initialize(trusted_commit_sha256=COMMIT, boot_id=BOOT)
    fence.admit(request_id="REQ1", program="renew", boot_id=BOOT,
                trusted_commit_sha256=COMMIT,
                native_launch=lambda **kw: {"request_id": kw["request_id"],
                  "program": "renew", "runtime_id": "RUNTIME1",
                  "invocation_id": INVOCATION})
    @contextmanager
    def installed(*, for_revocation=False):
        assert for_revocation is True
        yield fence, COMMIT
    monkeypatch.setattr(cleanup, "installed_fence", installed)
    monkeypatch.setattr(cleanup, "current_boot_id", lambda: BOOT)
    monkeypatch.setattr(cleanup, "_authoritative_unit",
                        lambda project_root, request_id:
                            (UNIT, "RUNTIME1", "renew") if request_id == "REQ1"
                            else (_ for _ in ()).throw(IssuerFenceDenied()))
    calls = []
    class Backend:
        def _validate_unit(self, project_root, unit_name):
            assert project_root == "/synthetic" and unit_name == UNIT
        def observe(self, *, project_root, unit_name):
            calls.append(("observe", unit_name))
            return dict(self.observation)
        def stop(self, *, project_root, unit_name):
            calls.append(("stop", unit_name))
            if getattr(self, "lost", False):
                raise OSError("StopUnit acknowledgement lost")
            self.observation = {"exists": False, "unit_name": unit_name}
        def release(self, *, project_root, unit_name):
            calls.append(("release", unit_name))
    backend = Backend()
    backend.observation = {"exists": True, "unit_name": UNIT,
                           "transient": True, "invocation_id": INVOCATION}
    try:
        yield fence, backend, calls
    finally:
        os.close(fd)


def reconcile(backend, witness=lambda **kw: True):
    return cleanup.reconcile_selected_issuer(
        backend, project_root="/synthetic", request_id="REQ1",
        trusted_cleanup_witness=witness)


def test_exact_invocation_bounded_stop_and_cleanup(prepared):
    fence, backend, calls = prepared
    witnessed = []
    assert reconcile(backend, lambda **kw: witnessed.append(kw) or True)["phase"] == "terminal"
    assert [name for name, _ in calls] == ["observe", "stop", "release", "observe"]
    assert witnessed[0]["invocation_id"] == INVOCATION
    assert witnessed[0]["unit_name"] == UNIT
    assert fence._read()["operations"]["REQ1"]["phase"] == "terminal"


@pytest.mark.parametrize("foreign", [
    {"invocation_id": "e"*32}, {"unit_name": "zog-foreign.service"},
    {"transient": False}, {"exists": "unknown"},
])
def test_foreign_unit_or_uncertain_observation_never_stops(prepared, foreign):
    fence, backend, calls = prepared
    backend.observation.update(foreign)
    with pytest.raises(IssuerFenceDenied):
        reconcile(backend)
    assert not any(x[0] == "stop" for x in calls)
    assert fence._read()["operations"]["REQ1"]["phase"] == "cancel-pending"


def test_interrupted_stop_and_lost_response_keep_cancel_pending(prepared):
    fence, backend, calls = prepared
    backend.lost = True
    with pytest.raises(IssuerFenceDenied):
        reconcile(backend)
    assert fence._read()["operations"]["REQ1"]["phase"] == "cancel-pending"
    backend.lost = False
    assert reconcile(backend)["phase"] == "terminal"
    assert [kind for kind, _ in calls].count("stop") == 2


def test_uncertain_execution_does_not_stop_a_foreign_unit(prepared):
    fence, backend, calls = prepared
    # A lost StartTransientUnit response does NOT prove unit ownership.
    state = fence._read()
    state["operations"]["REQ1"]["runtime_id"] = None
    state["operations"]["REQ1"]["invocation_id"] = None
    state["operations"]["REQ1"]["phase"] = "admission-uncertain"
    fence._write(state)
    with pytest.raises(IssuerFenceDenied):
        reconcile(backend)
    assert not any(x[0] == "stop" for x in calls)
    assert fence._read()["operations"]["REQ1"]["phase"] == "cancel-pending"


def test_reboot_requires_clean_identity_and_noreplay(prepared, monkeypatch):
    fence, backend, calls = prepared
    monkeypatch.setattr(cleanup, "current_boot_id", lambda: NEXT)
    with pytest.raises(IssuerFenceDenied):
        reconcile(backend, lambda **kw: False)
    state = fence._read()
    assert state["boot_id"] == NEXT
    assert state["operations"]["REQ1"]["phase"] == "cancel-pending"
    assert state["operations"]["REQ1"]["boot_id"] == BOOT
    assert reconcile(backend)["phase"] == "terminal"
    with pytest.raises(IssuerFenceDenied):
        fence.admit(request_id="REQ1", program="renew", boot_id=NEXT,
                    trusted_commit_sha256=COMMIT,
                    native_launch=lambda **kw: pytest.fail("replayed"))


def test_stop_ack_is_not_cleanup_proof(prepared):
    fence, backend, calls = prepared
    original = backend.stop
    def ack_without_termination(**kwargs):
        calls.append(("stop", kwargs["unit_name"]))
    backend.stop = ack_without_termination
    with pytest.raises(IssuerFenceDenied):
        reconcile(backend)
    assert fence._read()["operations"]["REQ1"]["phase"] == "cancel-pending"


def test_original_program_mismatch_cannot_stop_or_finalize(prepared, monkeypatch):
    """A different selected operation must not inherit a retained InvocationID."""
    fence, backend, calls = prepared
    monkeypatch.setattr(cleanup, "_authoritative_unit",
                        lambda project_root, request_id:
                            (UNIT, "RUNTIME1", "inspect"))
    with pytest.raises(IssuerFenceDenied):
        reconcile(backend)
    assert calls == []
    assert fence._read()["operations"]["REQ1"]["phase"] == "running"


def test_original_program_mismatch_cannot_relabel_completed_cleanup(
        prepared, monkeypatch):
    fence, backend, calls = prepared
    assert reconcile(backend)["phase"] == "terminal"
    calls.clear()
    monkeypatch.setattr(cleanup, "_authoritative_unit",
                        lambda project_root, request_id:
                            (UNIT, "RUNTIME1", "stage"))
    with pytest.raises(IssuerFenceDenied):
        reconcile(backend)
    assert calls == []
    assert fence._read()["operations"]["REQ1"]["program"] == "renew"
    assert fence._read()["operations"]["REQ1"]["phase"] == "terminal"
