"""The same installed root-control source must expose both Task C and finite builds."""
import inspect

import pytest

from zog.root_control.build import BuildBackend, canonical_request
from zog.root_control.task_c_trusted_host import (
    LocalTaskCJournal, SubmissionBlocked, intent,
)


def test_one_runtime_exports_both_capabilities_without_user_selectors():
    assert callable(LocalTaskCJournal) and callable(BuildBackend.start)
    assert 'execution_user_id' not in inspect.signature(BuildBackend.register).parameters
    assert 'execution_group_id' not in inspect.signature(BuildBackend.register).parameters
    assert 'user' not in inspect.signature(BuildBackend.start).parameters
    assert 'group' not in inspect.signature(BuildBackend.start).parameters
    assert 'User' not in inspect.getsource(BuildBackend.start).split("'User':")
    assert 'Group' not in inspect.getsource(BuildBackend.start).split("'Group':")


def test_task_c_submission_intent_preserves_trusted_host_without_special_worker():
    selected = intent(
        operation_id='a' * 32, request_sha256='b' * 64,
        script='echo no-extra-account', seconds=120,
        target={'instance_id': 'i-0123456789abcdef0',
                'account_id': '123456789012', 'region': 'us-east-1'},
    )
    assert selected['document'] == 'AWS-RunShellScript'
    assert not {'execution_user_id', 'execution_group_id', 'User', 'Group'} & set(selected)


@pytest.mark.parametrize('field', ['execution_user_id', 'execution_group_id', 'User', 'Group'])
def test_finite_build_refuses_identity_selection(field):
    request = {
        'build_root_id': 'a' * 32,
        'source_workspace_id': 'a' * 32 + '-source',
        'output_workspace_id': 'a' * 32 + '-output',
        'command': ['cc'], 'environment': {'PATH': '/bin'},
        'working_directory': '/image-build/source',
        'startup_timeout_seconds': 10,
        'execution_timeout_seconds': 120,
        'termination_grace_seconds': 10,
        'resource_limits': {
            'thread-count-maximum': 32,
            'memory-maximum-bytes': 1 << 28,
        },
        'read_only_root': True, 'network_access': False,
    }
    assert canonical_request(request) == request
    from zog.root_control.systemd import SystemdBackendError
    with pytest.raises(SystemdBackendError, match='missing or unsupported fields'):
        canonical_request(dict(request, **{field: 0}))
