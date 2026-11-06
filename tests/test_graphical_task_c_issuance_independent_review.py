"""Independent issuer source review: enrollment pins, signer separation, consent.

All keys/records are synthetic. No native signing authority is installed.
"""
import inspect
import io
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import pytest

from zog.root_control import graphical_task_c_issuance as issuance
from zog.root_control import graphical_task_c_issuance_cli as cli
from zog.root_control import graphical_operation_owner_source as owner


def test_original_record_cannot_be_selected_from_manifest(monkeypatch):
    record={"checkpoint":"synthetic","scope":"sha256:"+"a"*64}
    digest=issuance.sha(owner.canonical(record))
    def selected(path, *, limit=65536, mode=0o600):
        assert path == cli.ACCEPTED_ORIGINAL
        assert limit == 72
        return (digest+"\n").encode("ascii")
    monkeypatch.setattr(cli,"read",selected)
    assert cli.require_selected_original(record)==digest
    with pytest.raises(issuance.IssuanceDenied):
        cli.require_selected_original({**record,"checkpoint":"changed"})
    monkeypatch.setattr(cli,"read",lambda *a,**k:b"sha256:" + b"0"*64+b"\n")
    with pytest.raises(issuance.IssuanceDenied):
        cli.require_selected_original(record)


def test_event_source_commit_requires_independent_commit_pin(monkeypatch):
    commit="a"*40
    def selected(path, *, limit=65536, mode=0o600):
        assert path == cli.ACCEPTED_DISPATCH
        assert limit == 41
        return (commit+"\n").encode("ascii")
    monkeypatch.setattr(cli,"read",selected)
    assert cli.require_selected_dispatch(commit)==commit
    for other in ("b"*40, "not-a-commit", "A"*40):
        with pytest.raises(issuance.IssuanceDenied):
            cli.require_selected_dispatch(other)


@pytest.mark.parametrize("role,forbidden",[
    ("operator","event.private"),
    ("operator","github-webhook.hmac"),
    ("event","operator.private")])
def test_signing_host_refuses_cocustody_before_loading_own_key(
        role,forbidden,monkeypatch):
    accesses=[]
    monkeypatch.setattr(cli.os.path,"lexists",
                        lambda p: str(p).endswith(forbidden))
    monkeypatch.setattr(cli,"read",lambda *a,**k:
                        accesses.append(a) or pytest.fail("read key despite role collision"))
    with pytest.raises(issuance.IssuanceDenied):
        cli.key(role)
    assert accesses==[]


def test_operator_sees_exact_canonical_message_before_confirming(monkeypatch):
    candidate={"schema":"synthetic-test","checkpoint_genesis_sha256":"sha256:"+"a"*64,
               "host_id":"b"*64,"state_volume_id":"c"*64}
    expected=issuance.sha(owner.canonical(candidate))
    class TTY:
        def __init__(self): self.written=""
        def __enter__(self): return self
        def __exit__(self,*args): return False
        def write(self,s): self.written+=s
        def flush(self): pass
        def readline(self,n): return "APPROVE "+expected+"\n"
    tty=TTY()
    monkeypatch.setattr("builtins.open",lambda path,*a,**k:
                        tty if path=="/dev/tty" else pytest.fail("wrong source"))
    cli.confirm("preflight and stage",candidate)
    assert owner.canonical(candidate).decode("ascii") in tty.written
    assert expected in tty.written


def test_issuer_command_uses_pin_guards_before_signer_claim():
    code=inspect.getsource(cli.run)
    assert code.index("require_selected_original(m[\"original_checkpoint\"])") < code.index(
        'claimed("operator-registry",identity)')
    assert code.index('require_selected_dispatch(m["original_commit_sha"])') < code.index(
        'claimed("github-event",delivery)')
    assert code.index('require_selected_original(m["record"])') < code.index(
        'claimed("operator-purpose",identity)')


@pytest.mark.parametrize("substitution",("source_revision","lane","task"))
def test_authenticated_issue_cannot_authorize_different_signed_fonts_operation(substitution):
    import sys
    from pathlib import Path
    sys.path.insert(0,str(Path(__file__).resolve().parent))
    from test_graphical_task_c_issuance import sample, pub
    from zog.root_control import graphical_task_c_owner as taskc
    from zog.root_control import graphical_task_c_trust_authority as trust
    operator, event_signer, stage, pre, registry, args = sample()
    changed=dict(stage)
    changed[substitution] = {
        "source_revision":"3"*40,
        "lane":"another-graphical-lane",
        "task":"graphics-fonts-image-v1",
    }[substitution]
    new_pre={**changed,"operation_id":pre["operation_id"]}
    record={
        "schema":trust.ORIGINAL_SCHEMA,
        "host_id":changed["host_id"],
        "installation_id":changed["installation_id"],
        "state_volume_id":changed["state_volume_id"],
        "checkpoint_account_id":"123456789012",
        "checkpoint_region":"us-east-1",
        "checkpoint_bucket":"synthetic-original-bucket",
        "checkpoint_prefix":"synthetic/original/",
        "checkpoint_scope_sha256":owner.digest(owner.scope_from_request(changed)),
        "checkpoint_genesis_sha256":"sha256:"+"e"*64,
        "checkpoint_role_arn":"arn:aws:iam::123456789012:role/SyntheticOriginalWriter",
        "root_source_revision":trust.OWNER_SOURCE,
    }
    original=registry[stage["operation_id"]]["mapping"]["original"]
    signed=issuance.issue_original_registry(
        stage_request=changed,preflight_request=new_pre,stage_original=original,
        original_checkpoint=record,
        approval_ids={stage["operation_id"]:"c"*32,pre["operation_id"]:"d"*32},
        expires_at=480,now=400,
        sign_operator=operator.sign,pinned_operator_public=pub(operator))
    args={**args,"registry":taskc.ProtectedOriginalRegistry(
        signed,pinned_operator_public_key=pub(operator))}
    with pytest.raises(issuance.IssuanceDenied):
        issuance.attest_original_github_event(**args)
