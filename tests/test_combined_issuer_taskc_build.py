"""One root-control runtime exports issuer, trusted Task C and inherited builds."""
import inspect
import pytest

from zog.root_control.build import BuildBackend
from zog.root_control.daemon import RootControlDaemon
from zog.root_control.task_c_trusted_host import LocalTaskCJournal
from zog.root_control.issuer_inspection_result import read_selected_inspection
from zog.root_control.issuer_observation import observe_issuer_request
from zog.root_control.systemd import BusctlSystemdBackend
from zog.box_control import issuer_lifecycle_broker
from zog.box_control import host_bindings


def test_combined_controller_issuer_and_build_exports():
    assert callable(read_selected_inspection)
    assert callable(observe_issuer_request)
    assert callable(LocalTaskCJournal.submit_once)
    assert callable(BusctlSystemdBackend.reconcile_selected_issuer)
    assert callable(BusctlSystemdBackend.start_service)
    assert callable(issuer_lifecycle_broker)
    assert callable(host_bindings.resolve)
    assert hasattr(host_bindings, '_CERT_POLICY_SOURCE')
    assert 'execution_user_id' not in inspect.signature(BuildBackend.register).parameters
    assert 'execution_group_id' not in inspect.signature(BuildBackend.register).parameters
    source = inspect.getsource(BuildBackend.start)
    assert "'User':" not in source and "'Group':" not in source


def test_controller_issuer_requests_are_exactly_selected(tmp_path, monkeypatch):
    from zog.root_control import issuer_inspection_result, issuer_observation
    observed = []
    monkeypatch.setattr(issuer_inspection_result, 'read_selected_inspection',
        lambda **kwargs: observed.append(('inspect', kwargs)) or {'verified': False})
    monkeypatch.setattr(issuer_observation, 'observe_issuer_request',
        lambda **kwargs: observed.append(('observe', kwargs)) or {'status': 'uncertain'})
    daemon = RootControlDaemon(tmp_path/'unused.sock')
    for operation, marker in [('issuer_inspect_result', 'inspect'),
                              ('issuer_observe', 'observe')]:
        request = {'operation': operation, 'project_root': str(tmp_path),
                   'request_id': 'REQ-123'}
        assert daemon.handle(request)['ok'] is True
        assert observed[-1] == (marker, {'project_root': str(tmp_path),
                                         'request_id': 'REQ-123'})
        with pytest.raises(ValueError, match='invalid .*issuer inspection arguments'):
            daemon.handle(dict(request, execution_user_id=24202))
