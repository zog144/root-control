"""Both read-only Certbot evidence operations remain callable in the combined daemon."""
import pytest
from zog.root_control.daemon import RootControlDaemon
from zog.root_control import issuer_observation, issuer_inspection_result


@pytest.mark.parametrize("operation,module,method", [
    ("issuer_observe", issuer_observation, "observe_issuer_request"),
    ("issuer_inspect_result", issuer_inspection_result, "read_selected_inspection"),
])
def test_selected_certbot_evidence_dispatch(monkeypatch, tmp_path, operation, module, method):
    calls = []
    def reader(**kwargs):
        calls.append(kwargs)
        return {"schema": "test-issuer-evidence", "request_id": kwargs["request_id"]}
    monkeypatch.setattr(module, method, reader)
    controller = RootControlDaemon(tmp_path / "never-opened.sock")
    request = {"operation": operation, "project_root": str(tmp_path / "project"), "request_id": "REQ-1"}
    assert controller.handle(request) == {"ok": True, "result": {
        "schema": "test-issuer-evidence", "request_id": "REQ-1",
    }}
    assert calls == [{"project_root": str(tmp_path / "project"), "request_id": "REQ-1"}]
    for invalid in ({**request, "execution_user_id": 24202},
                    {**request, "source_file": "/etc/shadow"},
                    {"operation": operation, "project_root": str(tmp_path / "project")}):
        with pytest.raises((ValueError, KeyError), match="issuer inspection arguments"):
            controller.handle(invalid)
    assert len(calls) == 1
