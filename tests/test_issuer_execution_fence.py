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
    with pytest.raises(OSError):
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
