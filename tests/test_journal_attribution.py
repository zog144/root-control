"""Regression for output present in journald but lacking trusted attribution."""
import importlib.util
from pathlib import Path
import pytest
from zog.root_control import journal

spec = importlib.util.spec_from_file_location('journal_attribution',
    Path(__file__).resolve().parents[1] / 'acceptance/journal_attribution.py')
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)

@pytest.mark.parametrize('identity', [None, 'c' * 32])
def test_missing_or_wrong_trusted_identity_never_uses_unit_or_manager_field(monkeypatch, identity):
    record = dict(__CURSOR='cursor', MESSAGE='43', _BOOT_ID='b' * 32,
                  _SYSTEMD_UNIT='zog-test.service', INVOCATION_ID='a' * 32)
    if identity is not None:
        record['_SYSTEMD_INVOCATION_ID'] = identity
    commands = []
    def query(command, **kwargs):
        commands.append(command)
        return [record]
    monkeypatch.setattr(journal, 'run_bounded', query)
    page = dict(entries=[], next_cursor=None, has_more=False, status='ok')
    result = journal._read_page(page, Path('/fixture'), ['job'], 'b' * 32, 'a' * 32, None, 100)
    assert result['status'] == 'unavailable'
    assert result['entries'] == [] and result['next_cursor'] is None
    assert len(commands) == 1
    assert '_SYSTEMD_INVOCATION_ID=' + 'a' * 32 in commands[0]
    assert '_BOOT_ID=' + 'b' * 32 in commands[0]

def test_probe_separates_recorded_output_from_attributed_output():
    job = dict(unit='probe.service', outcome='success', boot_id='b' * 32, invocation_id='a' * 32)
    logs = [dict(MESSAGE='probe.service', _BOOT_ID='b' * 32, _SYSTEMD_INVOCATION_ID='a' * 32),
            dict(MESSAGE='probe.service-err', _BOOT_ID='b' * 32, INVOCATION_ID='a' * 32)]
    result = probe.classify(job, logs)
    assert result['recorded'] == 2 and result['attributed'] == 1 and not result['complete']
    logs[1]['_SYSTEMD_INVOCATION_ID'] = 'a' * 32
    assert probe.classify(job, logs)['complete']
    logs[1]['_BOOT_ID'] = 'c' * 32
    assert not probe.classify(job, logs)['complete']

def test_probe_rejects_duplicate_markers_and_expects_child_output():
    job = dict(unit='probe.service', outcome='child', boot_id='b' * 32, invocation_id='a' * 32)
    logs = [dict(MESSAGE='probe.service', _BOOT_ID='b' * 32, _SYSTEMD_INVOCATION_ID='a' * 32)] * 3
    assert not probe.classify(job, logs)['complete']
    logs = [dict(logs[0], MESSAGE='probe.service' + suffix) for suffix in ('', '-err', '-child')]
    assert probe.classify(job, logs)['complete']

def test_probe_properties_match_finite_job_lifecycle_without_payload_sleep():
    properties = dict(probe.properties('probe', 'marker', 'failure'))
    for key, value in {'Type':'exec', 'ExitType':'cgroup', 'AddRef':True,
                       'RemainAfterExit':False, 'StandardOutput':'journal', 'StandardError':'journal'}.items():
        assert properties[key].value == value
    assert properties['User'].value != 'root'
    assert 'sleep' not in properties['ExecStart'].value[0][1][2]

@pytest.mark.parametrize('mode,path,argv', [
    ('sync', '/usr/bin/journalctl', ['/usr/bin/journalctl', '--sync']),
    ('control', '/usr/bin/true', ['/usr/bin/true']),
])
def test_diagnostic_barrier_is_fixed_host_command_and_payload_stays_unprivileged(mode,path,argv):
    props = dict(probe.properties('probe','marker','failure',barrier=mode))
    assert props['ExecStopPostEx'].signature == 'a(sasas)'
    assert props['ExecStopPostEx'].value == [[path, argv, ['privileged']]]
    assert props['User'].value == 'nobody'
    assert 'RootDirectory' not in props and 'Environment' not in props
    assert props['TimeoutStopUSec'].value == 2_000_000
    assert '7' in props['ExecStart'].value[0][1][2]

def test_diagnostic_default_has_no_privileged_hook():
    assert 'ExecStopPostEx' not in dict(probe.properties('probe','marker','success'))
    with pytest.raises(ValueError):
        probe.properties('probe','marker','success',barrier='/untrusted/command')
