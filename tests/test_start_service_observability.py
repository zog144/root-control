"""Bounded root-control issuer start RPC diagnostics, never issuer payloads."""
from types import SimpleNamespace

from zog.root_control import daemon as daemon_module


class Connection:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def test_start_timeout_diagnostics_include_operation_but_no_untrusted_payload(monkeypatch):
    emitted = []
    responses = []
    monkeypatch.setattr(daemon_module, "emit",
                        lambda name, **data: emitted.append((name, data)))
    stub = SimpleNamespace(
        handle=lambda request: {"ok": True},
        _respond=lambda conn, response, **kw: responses.append((response, kw)),
    )
    released = []
    slot = SimpleNamespace(release=lambda: released.append(True))
    request = {
        "operation": "systemd_start_service",
        "definition": {"environment": [["CF_API_TOKEN", "should-never-log"]]},
    }
    daemon_module.RootControlDaemon._serve_request(stub, Connection(), request, slot)
    assert released == [True]
    assert responses[0][1]["operation"] == "systemd_start_service"
    names = [name for name, _ in emitted]
    assert names == ["systemd-start-service-dispatched",
                     "systemd-start-service-handler-finished"]
    assert emitted[1][1]["rpc_ok"] is True
    assert emitted[1][1]["elapsed_seconds"] >= 0
    assert "should-never-log" not in repr(emitted)
