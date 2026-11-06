"""Offline issuance custody and monotonic claims (synthetic source only)."""
import pytest
from zog.root_control import graphical_task_c_issuance_cli as cli
from zog.root_control import graphical_task_c_issuance as protocol


def test_event_role_requires_independent_operator_pin(monkeypatch):
    operator_key = b"o"*32
    event_key = b"e"*32
    monkeypatch.setattr(cli,"read",lambda path,limit=32:operator_key)
    assert cli.require_peer_key(
        cli.PINNED_OPERATOR_FOR_EVENT,operator_key.hex(),event_key)==operator_key
    for forged in (event_key.hex(),(b"f"*32).hex(),"bad",None):
        with pytest.raises(protocol.IssuanceDenied):
            cli.require_peer_key(
                cli.PINNED_OPERATOR_FOR_EVENT,forged,event_key)


def test_operator_role_requires_independent_event_pin(monkeypatch):
    operator_key=b"o"*32
    issuer_key=b"e"*32
    monkeypatch.setattr(cli,"read",lambda path,limit=32:issuer_key)
    assert cli.require_peer_key(
        cli.PINNED_EVENT_FOR_OPERATOR,issuer_key.hex(),operator_key)==issuer_key
    with pytest.raises(protocol.IssuanceDenied):
        cli.require_peer_key(
            cli.PINNED_EVENT_FOR_OPERATOR,(b"f"*32).hex(),operator_key)
    with pytest.raises(protocol.IssuanceDenied):
        cli.require_peer_key(
            cli.PINNED_EVENT_FOR_OPERATOR,operator_key.hex(),operator_key)


def test_claim_and_receipt_are_create_only(tmp_path,monkeypatch):
    monkeypatch.setattr(cli,"OUTPUT",tmp_path)
    monkeypatch.setattr(cli,"protected",lambda path:None)
    (tmp_path/"claims"/"github-event").mkdir(parents=True)
    (tmp_path/"receipts"/"github-event").mkdir(parents=True)
    cli.claimed("github-event","real-format-synthetic-delivery")
    with pytest.raises(FileExistsError):
        cli.claimed("github-event","real-format-synthetic-delivery")
    receipt={"schema":"synthetic-source","status":"not-installed"}
    first=cli.published("github-event","real-format-synthetic-delivery",receipt)
    assert first["status"]=="receipt-written-not-installed"
    with pytest.raises(FileExistsError):
        cli.published("github-event","real-format-synthetic-delivery",receipt)
