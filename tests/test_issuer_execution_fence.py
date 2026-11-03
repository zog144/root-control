"""Source-only issuer execution admission and revocation tests."""
import os
import json
import threading

import pytest

from zog.root_control.issuer_execution_fence import IssuerExecutionFence, IssuerFenceDenied, STATE

BOOT = "a" * 32
NEXT_BOOT = "b" * 32
COMMIT = "c" * 64


@pytest.fixture
def fenced(tmp_path):
    root = tmp_path / "protected"
    root.mkdir(mode=0o700)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    fence = IssuerExecutionFence(fd, owner_uid=os.getuid())
    fence.initialize(trusted_commit_sha256=COMMIT, boot_id=BOOT)
    try:
        yield fence, root
    finally:
        os.close(fd)


def result(**args):
    return {"request_id": args["request_id"], "program": args["program"],
            "runtime_id": "RUNTIME1", "invocation_id": "d" * 32}


@pytest.mark.parametrize("program", ["renew", "inspect", "stage"])
def test_revoke_serializes_with_running_admission(fenced, program):
    fence, root = fenced
    begun, release, revoked = (threading.Event() for _ in range(3))
    findings = []
    def launch(**args):
        begun.set()
        assert release.wait(3)
        return result(**args)
    def start():
        findings.append(fence.admit(request_id="REQ-1", program=program,
                     boot_id=BOOT, trusted_commit_sha256=COMMIT,
                     native_launch=launch))
    worker = threading.Thread(target=start)
    worker.start()
    assert begun.wait(3)
    other = threading.Thread(target=lambda: (
        fence.revoke(publish_pending_revocation=lambda: True), revoked.set()))
    other.start()
    assert not revoked.wait(.04)
    release.set()
    worker.join(3)
    other.join(3)
    assert not worker.is_alive() and not other.is_alive()
    assert revoked.is_set() and findings[0]["phase"] == "running"
    with pytest.raises(IssuerFenceDenied):
        fence.admit(request_id="REQ-2", program=program, boot_id=BOOT,
                    trusted_commit_sha256=COMMIT, native_launch=result)


def test_lost_launch_reply_never_replays(fenced):
    fence, root = fenced
    count = []
    def uncertain(**args):
        count.append(args)
        raise OSError("lost launch result")
    # The protected adapter redacts the callback's external error while
    # retaining its durable uncertain-launch record for reconciliation.
    with pytest.raises(IssuerFenceDenied):
        fence.admit(request_id="REQ-1", program="renew", boot_id=BOOT,
                    trusted_commit_sha256=COMMIT, native_launch=uncertain)
    assert len(count) == 1
    assert json.loads((root / STATE).read_text())["operations"]["REQ-1"]["phase"] == "admission-uncertain"
    with pytest.raises(IssuerFenceDenied):
        fence.admit(request_id="REQ-1", program="renew", boot_id=BOOT,
                    trusted_commit_sha256=COMMIT, native_launch=result)
    with pytest.raises(IssuerFenceDenied):
        fence.admit(request_id="REQ-2", program="inspect", boot_id=BOOT,
                    trusted_commit_sha256=COMMIT, native_launch=result)
    with pytest.raises(IssuerFenceDenied):
        fence.reconcile(request_id="REQ-1", verify_stopped_and_clean=lambda **kw: False)
    assert fence.reconcile(request_id="REQ-1", verify_stopped_and_clean=lambda **kw: True)["phase"] == "terminal"
    with pytest.raises(IssuerFenceDenied):
        fence.admit(request_id="REQ-1", program="renew", boot_id=BOOT,
                    trusted_commit_sha256=COMMIT, native_launch=result)
    assert fence.admit(request_id="REQ-2", program="inspect", boot_id=BOOT,
                       trusted_commit_sha256=COMMIT, native_launch=result)["phase"] == "running"


def test_reboot_reconciles_without_relaunch(fenced):
    fence, root = fenced
    fence.admit(request_id="REQ-1", program="renew", boot_id=BOOT,
                trusted_commit_sha256=COMMIT, native_launch=result)
    state = fence.reboot(new_boot_id=NEXT_BOOT)
    assert state["epoch"] == 2
    assert state["operations"]["REQ-1"]["phase"] == "cancel-pending"
    with pytest.raises(IssuerFenceDenied):
        fence.admit(request_id="REQ-2", program="stage", boot_id=NEXT_BOOT,
                    trusted_commit_sha256=COMMIT, native_launch=result)
    claims = []
    def clean(**kw):
        claims.append(kw)
        return kw["original_boot_id"] == BOOT and kw["invocation_id"] == "d"*32
    assert fence.reconcile(request_id="REQ-1", verify_stopped_and_clean=clean)["phase"] == "terminal"
    assert len(claims) == 1
    assert fence.reboot(new_boot_id=NEXT_BOOT)["epoch"] == 2
    assert fence.admit(request_id="REQ-2", program="stage", boot_id=NEXT_BOOT,
                       trusted_commit_sha256=COMMIT, native_launch=result)["phase"] == "running"


def test_revoked_fence_is_terminal_across_reboot(fenced):
    fence, root = fenced
    fence.admit(request_id="REQ-1", program="renew", boot_id=BOOT,
                trusted_commit_sha256=COMMIT, native_launch=result)
    assert fence.revoke(publish_pending_revocation=lambda: True)["revoked"] is True
    assert fence.reconcile(request_id="REQ-1", verify_stopped_and_clean=lambda **kw: True)["phase"] == "terminal"
    assert fence.reboot(new_boot_id=NEXT_BOOT)["revoked"] is True
    with pytest.raises(IssuerFenceDenied):
        fence.admit(request_id="REQ-2", program="stage", boot_id=NEXT_BOOT,
                    trusted_commit_sha256=COMMIT, native_launch=result)


def test_corrupted_ledger_and_foreign_install_commit_fail_closed(fenced):
    fence, root = fenced
    with pytest.raises(IssuerFenceDenied):
        fence.initialize(trusted_commit_sha256="e"*64, boot_id=BOOT)
    (root / STATE).write_text('{"invalid":true}')
    with pytest.raises(IssuerFenceDenied):
        fence.admit(request_id="REQ-1", program="renew", boot_id=BOOT,
                    trusted_commit_sha256=COMMIT, native_launch=result)



def test_actual_systemd_start_service_serializes_with_revoke(fenced, monkeypatch):
    """Exercise actual BusctlSystemdBackend.start_service, not only model."""
    from contextlib import contextmanager
    from zog.root_control import issuer_execution_fence as module
    from zog.root_control.systemd import BusctlSystemdBackend
    fence, root = fenced
    started, release, revoked = (threading.Event() for _ in range(3))
    @contextmanager
    def native_source():
        yield fence, COMMIT
    monkeypatch.setattr(module, "installed_fence", native_source)
    monkeypatch.setattr(module, "current_boot_id", lambda: BOOT)
    backend = BusctlSystemdBackend()
    monkeypatch.setattr(backend, "_validate_service_definition",
                        lambda *args, **kwargs: None)
    monkeypatch.setattr(backend, "_validate_program_selection",
                        lambda *args, **kwargs: "REQ-NATIVE")
    dispatches = []
    def admitted(**kwargs):
        dispatches.append(kwargs)
        started.set()
        assert release.wait(3)
    monkeypatch.setattr(backend, "_start_service_validated", admitted)
    monkeypatch.setattr(backend, "observe", lambda **kwargs: {
        "exists": True, "unit_name": kwargs["unit_name"],
        "transient": True, "invocation_id": "d"*32,
    })
    definition = {
        "application_name": "certify-manage",
        "selected_program": "renew",
        "runtime_id": "c"*32,
        "unit_name": "zog-certify-" + "c"*32 + ".service",
    }
    errors = []
    def start():
        try:
            backend.start_service(project_root="/synthetic",
                                  generation="any", definition=definition)
        except Exception as exc:
            errors.append(exc)
    worker = threading.Thread(target=start)
    worker.start()
    assert started.wait(3)
    revoker = threading.Thread(target=lambda: (
        fence.revoke(publish_pending_revocation=lambda: True),revoked.set()))
    revoker.start()
    assert not revoked.wait(.05)
    release.set()
    worker.join(3);revoker.join(3)
    assert not worker.is_alive() and not revoker.is_alive()
    assert not errors and revoked.is_set() and len(dispatches) == 1
    assert json.loads((root / STATE).read_text())[
        "operations"]["REQ-NATIVE"]["phase"] == "cancel-pending"
    with pytest.raises(Exception, match="protected selected issuer admission unavailable"):
        backend.start_service(project_root="/synthetic",
                              generation="any", definition=definition)
    assert len(dispatches) == 1


def test_real_systemd_admission_lost_reply_keeps_uncertain_record(fenced, monkeypatch):
    from contextlib import contextmanager
    from zog.root_control import issuer_execution_fence as module
    from zog.root_control.systemd import BusctlSystemdBackend
    fence, root = fenced
    @contextmanager
    def native_source():
        yield fence, COMMIT
    monkeypatch.setattr(module, "installed_fence", native_source)
    monkeypatch.setattr(module, "current_boot_id", lambda: BOOT)
    backend=BusctlSystemdBackend()
    monkeypatch.setattr(backend, "_validate_service_definition",
                        lambda *a, **kw: None)
    monkeypatch.setattr(backend, "_validate_program_selection",
                        lambda *a, **kw: "REQ-UNCERTAIN")
    count=[]
    def lost(**kw):
        count.append(1)
        raise OSError("PID1 acknowledgement unavailable")
    monkeypatch.setattr(backend,"_start_service_validated",lost)
    definition={"application_name":"certify-manage","selected_program":"renew",
                "runtime_id":"c"*32,"unit_name":"zog-certify-"+ "c"*32+".service"}
    for attempt in range(2):
        with pytest.raises(Exception,match="protected selected issuer admission unavailable"):
            backend.start_service(project_root="/synthetic",
                                  generation="any", definition=definition)
    assert count==[1]
    assert json.loads((root/STATE).read_text())[
        "operations"]["REQ-UNCERTAIN"]["phase"]=="admission-uncertain"



def test_revocation_publication_loss_keeps_terminal_epoch_and_same_marker_retry(fenced):
    fence, folder = fenced
    fence.admit(request_id="REQ-1", program="inspect", boot_id=BOOT,
                trusted_commit_sha256=COMMIT, native_launch=result)
    sent=[]
    def lost_marker():
        sent.append(1)
        raise OSError("interrupted after durable terminal epoch")
    with pytest.raises(IssuerFenceDenied):
        fence.revoke(publish_pending_revocation=lost_marker)
    state=json.loads((folder/STATE).read_text())
    assert state["revoked"] is True and state["epoch"] == 2
    assert state["operations"]["REQ-1"]["phase"] == "cancel-pending"
    with pytest.raises(IssuerFenceDenied):
        fence.admit(request_id="REQ-2",program="renew",boot_id=BOOT,
                    trusted_commit_sha256=COMMIT,native_launch=result)
    accepted=[]
    assert fence.revoke(publish_pending_revocation=lambda:
                        (accepted.append(1),True)[1])["epoch"] == 2
    assert accepted == [1] and sent == [1]
    assert fence.reboot(new_boot_id=NEXT_BOOT)["revoked"] is True

def test_missing_stable_writer_lock_with_existing_epoch_is_hard_hold(fenced):
    """Never bootstrap a second lock for a durable old execution ledger."""
    from zog.root_control.issuer_execution_fence import (
        IssuerExecutionFence, LOCK, STATE,
    )
    fence, root = fenced
    before=(root/STATE).read_bytes()
    (root/LOCK).unlink()
    with pytest.raises(IssuerFenceDenied):
        IssuerExecutionFence(fence.dirfd,owner_uid=os.getuid())
    assert not (root/LOCK).exists()
    assert (root/STATE).read_bytes()==before
    with pytest.raises(IssuerFenceDenied):
        fence.admit(request_id="REQ-NO-LOCK",program="renew",boot_id=BOOT,
                    trusted_commit_sha256=COMMIT,
                    native_launch=lambda **kw:pytest.fail("must never start"))
    assert (root/STATE).read_bytes()==before


def test_active_fence_refuses_replaced_writer_inode_without_republishing(fenced):
    """Do not use a substituted writer inode in a long-lived root instance."""
    from zog.root_control.issuer_execution_fence import LOCK,STATE
    fence,root=fenced
    original=(root/STATE).read_bytes()
    (root/LOCK).rename(root/"retained-original-lock")
    (root/LOCK).write_bytes(b"")
    (root/LOCK).chmod(0o600)
    with pytest.raises(IssuerFenceDenied):
        fence.reboot(new_boot_id=NEXT_BOOT)
    with pytest.raises(IssuerFenceDenied):
        fence.revoke(publish_pending_revocation=lambda:
                     pytest.fail("no marker under replaced lock"))
    assert (root/STATE).read_bytes()==original


def test_missing_lock_denies_even_after_durable_terminal_revocation(fenced):
    from zog.root_control.issuer_execution_fence import (
        IssuerExecutionFence, LOCK,STATE,
    )
    fence,root=fenced
    fence.revoke(publish_pending_revocation=lambda:True)
    prior=(root/STATE).read_bytes()
    (root/LOCK).unlink()
    with pytest.raises(IssuerFenceDenied):
        IssuerExecutionFence(fence.dirfd,owner_uid=os.getuid())
    assert (root/STATE).read_bytes()==prior
    assert not (root/LOCK).exists()


def test_new_fence_refuses_replaced_lock_inode_after_existing_epoch(fenced):
    """Cross-process substitution cannot inherit existing admission authority."""
    fence, root = fenced
    from zog.root_control.issuer_execution_fence import LOCK, STATE, IssuerExecutionFence
    old = (root / STATE).read_bytes()
    (root / LOCK).rename(root / "retained-first-lock")
    (root / LOCK).write_bytes(b"")
    (root / LOCK).chmod(0o600)
    newly_opened = IssuerExecutionFence(fence.dirfd, owner_uid=os.getuid())
    with pytest.raises(IssuerFenceDenied):
        newly_opened.admit(
            request_id="REQ-REPLACED", program="stage", boot_id=BOOT,
            trusted_commit_sha256=COMMIT,
            native_launch=lambda **kw: pytest.fail("split writer lock launch"))
    with pytest.raises(IssuerFenceDenied):
        newly_opened.revoke(
            publish_pending_revocation=lambda: pytest.fail("split writer marker"))
    assert (root / STATE).read_bytes() == old


def test_fresh_fence_reopens_same_inode_across_reboot_and_retains_uncertainty(fenced):
    from zog.root_control.issuer_execution_fence import IssuerExecutionFence
    fence, root = fenced
    fence.admit(
        request_id="REQ-SAVED", program="renew", boot_id=BOOT,
        trusted_commit_sha256=COMMIT,
        native_launch=lambda **kwargs: {
            "request_id": kwargs["request_id"], "program": kwargs["program"],
            "runtime_id": "RUNTIME1", "invocation_id": "d" * 32})
    reread = IssuerExecutionFence(fence.dirfd, owner_uid=os.getuid())
    current = reread.reboot(new_boot_id=NEXT_BOOT)
    assert current["operations"]["REQ-SAVED"]["phase"] == "cancel-pending"
    assert current["lock_inode"] == os.stat(root / "selected-issuer-execution.lock").st_ino
    with pytest.raises(IssuerFenceDenied):
        reread.admit(
            request_id="REQ-NEW", program="stage", boot_id=NEXT_BOOT,
            trusted_commit_sha256=COMMIT,
            native_launch=lambda **kw: pytest.fail("replayed uncertain operation"))


def test_pre_v2_ledger_without_immutable_lock_inode_fails_closed(fenced):
    from zog.root_control.issuer_execution_fence import IssuerExecutionFence
    fence, root = fenced
    record = fence._read()
    record.pop("lock_inode")
    record["schema"] = "zog-root-selected-issuer-execution-fence-v1"
    fence._write(record)
    later = IssuerExecutionFence(fence.dirfd, owner_uid=os.getuid())
    with pytest.raises(IssuerFenceDenied):
        later.reboot(new_boot_id=NEXT_BOOT)
    assert not any(root.glob(".selected-issuer-fence-*"))
