"""Trusted Host source acceptance: one durable SSM send; no external authority."""
import json
import os
import threading
from pathlib import Path

import pytest

from zog.root_control.task_c_trusted_host import (
    LocalTaskCJournal, SubmissionBlocked, intent, SCHEMA,
)

OP = "a" * 32
REQUEST = "b" * 64
TARGET = {"account_id": "123456789012", "region": "us-east-1",
          "instance_id": "i-0123456789abcdef0"}


class Sender:
    instance = TARGET["instance_id"]

    def __init__(self, *, error=None):
        self.calls = []
        self.error = error

    def submit_command(self, script, *, seconds):
        self.calls.append((script, seconds))
        if self.error is not None:
            raise self.error
        return "command-once-123"


def store(tmp_path):
    assert os.geteuid() == 0
    root = tmp_path / "operations"
    root.mkdir(mode=0o700)
    return root


def submit(journal, sender, **changes):
    args = dict(operation_id=OP, request_sha256=REQUEST,
                script="set -eu\necho compile", seconds=300,
                target=TARGET, sender=sender)
    args.update(changes)
    return journal.submit_once(**args)


def test_one_real_submit_interface_and_durable_records(tmp_path):
    root = store(tmp_path)
    sender = Sender()
    journal = LocalTaskCJournal(root)
    assert submit(journal, sender) == "command-once-123"
    assert sender.calls == [("set -eu\necho compile", 300)]
    claim, result, cancellation = journal.inspect(OP)
    assert claim["schema"] == SCHEMA
    assert claim["target"] == TARGET
    assert claim["request_sha256"] == REQUEST
    assert claim["document"] == "AWS-RunShellScript"
    assert result["command_id"] == "command-once-123"
    assert cancellation is None
    journal.close()
    # A second process/reboot inherits the retained file and never resends.
    second = LocalTaskCJournal(root)
    with pytest.raises(SubmissionBlocked):
        submit(second, sender)
    assert len(sender.calls) == 1
    second.close()


def test_uncertain_reply_crash_never_retries(tmp_path):
    root = store(tmp_path)
    sender = Sender(error=TimeoutError("lost acknowledgement"))
    journal = LocalTaskCJournal(root)
    with pytest.raises(TimeoutError):
        submit(journal, sender)
    prior, returned, cancelled = journal.inspect(OP)
    assert prior is not None and returned is None and cancelled is None
    journal.close()
    reopened = LocalTaskCJournal(root)
    sender.error = None
    with pytest.raises(SubmissionBlocked):
        submit(reopened, sender)
    assert len(sender.calls) == 1
    reopened.close()


def test_record_failure_after_send_is_uncertain_without_resubmission(tmp_path, monkeypatch):
    from zog.root_control import task_c_trusted_host as module
    root = store(tmp_path)
    sender = Sender()
    original = module._write_once
    def fail_command(directory, name, row):
        if name.endswith(".command.json"):
            raise OSError("power loss after SSM send")
        return original(directory, name, row)
    monkeypatch.setattr(module, "_write_once", fail_command)
    journal = LocalTaskCJournal(root)
    with pytest.raises(OSError):
        submit(journal, sender)
    journal.close()
    monkeypatch.setattr(module, "_write_once", original)
    another = LocalTaskCJournal(root)
    with pytest.raises(SubmissionBlocked):
        submit(another, sender)
    assert len(sender.calls) == 1
    another.close()


def test_cancellation_before_submission_is_durable(tmp_path):
    root = store(tmp_path)
    sender = Sender()
    journal = LocalTaskCJournal(root)
    journal.cancel(OP, reason="operator-cancelled")
    journal.close()
    restored = LocalTaskCJournal(root)
    with pytest.raises(SubmissionBlocked):
        submit(restored, sender)
    claim, command, cancel = restored.inspect(OP)
    assert claim is None and command is None
    assert cancel["reason"] == "operator-cancelled"
    assert sender.calls == []
    restored.close()


def test_same_identity_with_different_request_cannot_repeat(tmp_path):
    root = store(tmp_path)
    sender = Sender()
    j = LocalTaskCJournal(root)
    submit(j, sender)
    with pytest.raises(SubmissionBlocked):
        submit(j, sender, request_sha256="c" * 64)
    assert len(sender.calls) == 1
    j.close()


def test_corrupt_or_symlinked_intent_blocks_without_send(tmp_path):
    root = store(tmp_path)
    claim = root / (OP + ".intent.json")
    claim.symlink_to(tmp_path / "absent")
    sender = Sender()
    j = LocalTaskCJournal(root)
    with pytest.raises(SubmissionBlocked):
        submit(j, sender)
    assert sender.calls == []
    j.close()


def test_second_concurrent_attempt_cannot_send_twice(tmp_path):
    root = store(tmp_path)
    entered = threading.Event()
    release = threading.Event()
    sender = Sender()

    def send(script, *, seconds):
        sender.calls.append((script, seconds))
        entered.set()
        if not release.wait(timeout=3):
            raise TimeoutError("blocked test sender")
        return "command-once-123"

    sender.submit_command = send
    first = LocalTaskCJournal(root)
    second = LocalTaskCJournal(root)
    results = []
    def worker():
        try:
            results.append(submit(first, sender))
        except Exception as exc:
            results.append(exc)
    thread = threading.Thread(target=worker)
    thread.start()
    assert entered.wait(timeout=3)
    release.set()
    thread.join(timeout=3)
    assert not thread.is_alive()
    with pytest.raises(SubmissionBlocked):
        submit(second, sender)
    assert results == ["command-once-123"]
    assert len(sender.calls) == 1
    first.close()
    second.close()


@pytest.mark.parametrize("mutation", (
    {"operation_id": "../bad"}, {"request_sha256": "bad"},
    {"script": ""}, {"seconds": 0}, {"seconds": 21601},
    {"target": {"account_id": "bad", "region": "us-east-1",
                "instance_id": TARGET["instance_id"]}},
    {"target": {**TARGET, "instance_id": "foreign"}},
))
def test_invalid_operation_or_target_never_sends(tmp_path, mutation):
    root = store(tmp_path)
    journal = LocalTaskCJournal(root)
    sender = Sender()
    with pytest.raises(SubmissionBlocked):
        submit(journal, sender, **mutation)
    assert sender.calls == []
    journal.close()


def test_not_root_or_unprotected_directory_denied(tmp_path, monkeypatch):
    from zog.root_control import task_c_trusted_host as module
    root = store(tmp_path)
    root.chmod(0o777)
    with pytest.raises(SubmissionBlocked):
        LocalTaskCJournal(root)
    root.chmod(0o700)
    monkeypatch.setattr(module.os, "geteuid", lambda: 1001)
    with pytest.raises(SubmissionBlocked):
        LocalTaskCJournal(root)
