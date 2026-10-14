"""Opt-in live PID 1 acceptance for admin-activated execution identity grants.

Run only on a disposable or explicitly authorized host with an existing issued
grant. No grant allocation, account creation, rootfs modification or application
migration occurs in this test. The transient probe uses exactly the numeric
User=/Group= properties that root-control sends to systemd.
"""
import os
import re
import subprocess
import uuid
from pathlib import Path

import pytest

from zog.root_control.identities import resolve


@pytest.mark.skipif(
    not (os.environ.get("ZOG_LIVE_EXECUTION_IDENTITY_PROJECT")
         and os.environ.get("ZOG_LIVE_EXECUTION_IDENTITY_APPLICATION")),
    reason="requires explicit project/application and privileged live systemd acceptance",
)
def test_real_systemd_numeric_execution_identity_and_group_isolation():
    assert os.geteuid() == 0
    assert Path("/run/systemd/system").is_dir()
    project = os.environ["ZOG_LIVE_EXECUTION_IDENTITY_PROJECT"]
    application = os.environ["ZOG_LIVE_EXECUTION_IDENTITY_APPLICATION"]
    grant = resolve(project, application)  # verifies root-owned registry/NSS
    unit = "zog-execution-credential-probe-" + uuid.uuid4().hex[:12]
    command = [
        "systemd-run", "--system", "--collect", "--wait", "--pipe",
        "--unit=" + unit,
        "--property=Type=exec",
        "--property=User=" + str(grant["uid"]),
        "--property=Group=" + str(grant["gid"]),
        "/usr/bin/id", "-a",
    ]
    result = subprocess.run(command, capture_output=True, text=True, timeout=45)
    assert result.returncode == 0, (
        f"transient systemd identity probe failed: {result.stderr}\n{result.stdout}"
    )
    output = result.stdout
    assert re.search(r"\buid=" + str(grant["uid"]) + r"\b", output), output
    assert re.search(r"\bgid=" + str(grant["gid"]) + r"\b", output), output
    m = re.search(r"\bgroups=([^\n]+)", output)
    assert m, output
    members = [int(value) for value in re.findall(r"(?<![0-9])([0-9]+)\(", m.group(1))]
    assert set(members) == {grant["gid"]}, output
