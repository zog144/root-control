"""Independent exact-source selected issuer admission/revocation security regression.

root-control protected systemd epoch + box-control fixed public projection
+ host-install original immutable commit identities. The same transient
test-owned directory represents the two protection levels; no Host or
real systemd unit is touched. Requires sudo only for 0444 root-owned pins.
"""
import hashlib
import json
import os
from pathlib import Path
import pytest

from zog.root_control.issuer_execution_fence import (
    IssuerExecutionFence,IssuerFenceDenied,STATE,LOCK,
)
from zog.box_control import issuer_broker_authority as broker_authority
from zog.host_install import certificate_selected_broker_install as installer
from test_issuer_broker_revocation_admission import (
    canonical,projection,commit_for_projection,
)

BOX_HEAD="baca7f815974dbf685950c0c7e78f693dd0a96e2"
ROOT_REVIEWED="98da48c7dc897ba12ef609832a48d702c01bd948"
BOOT="a"*32
NEXT="b"*32


def test_exact_pinned_owner_components_are_not_silently_replaced():
    from zog.root_control import issuer_execution_fence
    assert installer.BOX_CONTROL_REVIEWED_COMMIT == BOX_HEAD
    assert issuer_execution_fence.REVIEWED_BOX_CONTROL == BOX_HEAD
    # The corrected root-control HEAD is review-only; do NOT promote
    # the installed root-control pin inside the immutable host-install grant.
    assert installer.ROOT_CONTROL_EXECUTION_REVIEWED_COMMIT == ROOT_REVIEWED
    assert broker_authority.COMMIT_NAME == installer.COMMIT_NAME
    assert broker_authority.REVOCATION_NAME == installer.REVOCATION_NAME


@pytest.mark.skipif(os.geteuid()!=0,reason="requires root-owned 0444 ephemeral fixture")
def test_pending_marker_lost_response_still_denies_real_execution(tmp_path):
    root=tmp_path/"etc-host-deploy"
    root.mkdir(mode=0o700)
    projection_file=root/Path(broker_authority.ROOT_PATH).name
    signed_projection=canonical(projection())
    projection_file.write_bytes(signed_projection)
    projection_file.chmod(0o444)
    commit_bytes=canonical(commit_for_projection(signed_projection))
    commit_file=root/broker_authority.COMMIT_NAME
    commit_file.write_bytes(commit_bytes)
    commit_file.chmod(0o444)
    parent=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    protected=root/"selected-issuer-execution"
    protected.mkdir(mode=0o700)
    private=os.open(protected,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        assert broker_authority._read_authority_in_parent(parent)==projection()
        fence=IssuerExecutionFence(private)
        commit_sha=hashlib.sha256(commit_bytes).hexdigest()
        fence.initialize(trusted_commit_sha256=commit_sha,boot_id=BOOT)
        count=[]
        def launch(**kwargs):
            count.append(kwargs)
            return {"request_id":kwargs["request_id"],"program":"renew",
                    "runtime_id":"RUNTIME1","invocation_id":"c"*32}
        assert fence.admit(request_id="REQUEST1",program="renew",boot_id=BOOT,
                           trusted_commit_sha256=commit_sha,
                           native_launch=launch)["phase"]=="running"
        def lost_marker():
            raise OSError("power loss after terminal execution epoch")
        with pytest.raises(IssuerFenceDenied):
            fence.revoke(publish_pending_revocation=lost_marker)
        persisted=json.loads((protected/STATE).read_bytes())
        assert persisted["revoked"] is True
        assert persisted["operations"]["REQUEST1"]["phase"]=="cancel-pending"
        assert not (root/broker_authority.REVOCATION_NAME).exists()
        assert not (root/broker_authority.PENDING_REVOCATION_NAME).exists()
        # The box non-root public reader cannot infer the private terminal
        # epoch until the marker is published. Root-control *must* be last
        # execution authority, not this advisory broker admission.
        assert broker_authority._read_authority_in_parent(parent)==projection()
        with pytest.raises(IssuerFenceDenied):
            fence.admit(request_id="REQUEST2",program="stage",boot_id=BOOT,
                        trusted_commit_sha256=commit_sha,
                        native_launch=lambda **kw:pytest.fail("execution escaped"))
        assert len(count)==1
        # A crash after first marker publication still denies even if the
        # final tombstone bytes are absent and the marker is malformed.
        def retry_same():
            (root/broker_authority.PENDING_REVOCATION_NAME).write_bytes(
                b'{"partial":')
            return True
        assert fence.revoke(publish_pending_revocation=retry_same)["revoked"]
        with pytest.raises(Exception):
            broker_authority._read_authority_in_parent(parent)
        assert fence.reboot(new_boot_id=NEXT)["revoked"]
        assert fence._read()["operations"]["REQUEST1"]["phase"]=="cancel-pending"
        with pytest.raises(IssuerFenceDenied):
            fence.admit(request_id="REQUEST3",program="inspect",boot_id=NEXT,
                        trusted_commit_sha256=commit_sha,
                        native_launch=lambda **kw:pytest.fail("reboot replay"))
    finally:
        os.close(private)
        os.close(parent)
