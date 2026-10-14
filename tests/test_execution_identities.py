import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from zog.root_control import identities
from zog.root_control.identities import ExecutionIdentityError
from zog.root_control.systemd import BusctlSystemdBackend, SystemdBackendError


def _registry(tmp_path, monkeypatch):
    path = tmp_path / "execution-identities.json"
    monkeypatch.setattr(identities, "REGISTRY", path)
    monkeypatch.setattr(identities, "_check_directory", lambda p: None)
    monkeypatch.setattr(identities, "_check_provision_lock", lambda fd: None)
    monkeypatch.setattr(identities, "_check_registry_file", lambda info: None)
    # Legacy grant tests are focused on grant durability. New activation tests
    # below exercise the independent host-NSS checks explicitly.
    monkeypatch.setattr(identities, "_checked_nss", lambda grant: identities.principal_name(grant))
    return path


def test_admin_provisioned_grants_are_distinct_and_stable(tmp_path, monkeypatch):
    registry = _registry(tmp_path, monkeypatch)
    monkeypatch.setattr(identities.os, "geteuid", lambda: 0)
    monkeypatch.setattr(identities, "_host_unused", lambda uid, gid: None)
    project = tmp_path / "project"
    project.mkdir()
    first = identities.provision(project, "portal", first_uid=27000, last_uid=27004)
    again = identities.provision(project, "portal", first_uid=27000, last_uid=27004)
    other = identities.provision(project, "archive-mirror", first_uid=27000, last_uid=27004)
    assert first == again
    assert first["uid"] == first["gid"] == 27000
    assert other["uid"] == other["gid"] == 27001
    assert first["grant_id"] != other["grant_id"]
    assert identities.resolve(project, "portal") == first
    assert registry.stat().st_mode & 0o022 == 0
    with pytest.raises(ExecutionIdentityError, match="disagrees"):
        identities.verify(project, "portal", dict(first, uid=27002))


def test_registry_provision_is_privileged_and_fail_closed(tmp_path, monkeypatch):
    _registry(tmp_path, monkeypatch)
    monkeypatch.setattr(identities.os, "geteuid", lambda: 1000)
    with pytest.raises(ExecutionIdentityError, match="administrator"):
        identities.provision(tmp_path, "portal", first_uid=27000, last_uid=27001)
    with pytest.raises(ExecutionIdentityError, match="not provisioned"):
        identities.resolve(tmp_path, "portal")


def test_uid_collisions_and_tampered_registry_block(tmp_path, monkeypatch):
    registry = _registry(tmp_path, monkeypatch)
    monkeypatch.setattr(identities.os, "geteuid", lambda: 0)
    def checked(uid, gid):
        if uid == 27000:
            raise ExecutionIdentityError("execution UID collides with host account")
    monkeypatch.setattr(identities, "_host_unused", checked)
    project = tmp_path / "project"
    project.mkdir()
    grant = identities.provision(project, "portal", first_uid=27000, last_uid=27001)
    assert grant["uid"] == 27001
    raw = json.loads(registry.read_text())
    raw["grants"].append(dict(grant, grant_id="b" * 32, application="other"))
    registry.write_text(json.dumps(raw))
    with pytest.raises(ExecutionIdentityError, match="duplicate or shared"):
        identities.resolve(project, "portal")


def test_root_control_rejects_forged_numeric_user_or_group(tmp_path, monkeypatch):
    _registry(tmp_path, monkeypatch)
    monkeypatch.setattr(identities.os, "geteuid", lambda: 0)
    monkeypatch.setattr(identities, "_host_unused", lambda uid, gid: None)
    project = tmp_path / "project"
    project.mkdir()
    grant = identities.provision(project, "portal", first_uid=27000, last_uid=27001)
    raw = dict(application_name="portal", execution_binding=grant,
               persistent_storage_id="a" * 32,
               user="27000", group="27000", bind_paths=[])
    assert BusctlSystemdBackend._validate_execution_binding(project, raw) == grant
    with pytest.raises(SystemdBackendError, match="numeric User/Group"):
        BusctlSystemdBackend._validate_execution_binding(
            project, dict(raw, user="regular"))
    with pytest.raises(SystemdBackendError, match="protected execution identity"):
        BusctlSystemdBackend._validate_execution_binding(
            project, dict(raw, execution_binding=dict(grant, uid=27001)))


def test_managed_numeric_persistent_storage_needs_no_host_passwd(tmp_path, monkeypatch):
    _registry(tmp_path, monkeypatch)
    monkeypatch.setattr(identities.os, "geteuid", lambda: 0)
    monkeypatch.setattr(identities, "_host_unused", lambda uid, gid: None)
    project = tmp_path / "project"
    project.mkdir()
    grant = identities.provision(project, "portal", first_uid=27000, last_uid=27001)
    import pwd
    monkeypatch.setattr(pwd, "getpwuid", lambda uid: (_ for _ in ()).throw(AssertionError("host passwd not permitted")))
    chowns = []
    monkeypatch.setattr(identities.os, "chown", lambda *args: chowns.append(args))
    base = project / "state/mounts/persistent" / ("a" * 32)
    raw = dict(application_name="portal", execution_binding=grant,
               persistent_storage_id="a" * 32,
               user="27000", group="27000", bind_paths=[[str(base / "data"), "/data"]])
    BusctlSystemdBackend._persistent_directories(project, raw)
    assert chowns == [(base / "data", 27000, 27000)]
    # Existing mode and ownership are intentionally not repaired or reassigned.
    with pytest.raises(SystemdBackendError, match="ownership"):
        BusctlSystemdBackend._persistent_directories(project, raw)



def test_issued_grant_requires_explicit_nss_activation(tmp_path, monkeypatch):
    _registry(tmp_path, monkeypatch)
    monkeypatch.setattr(identities.os, "geteuid", lambda: 0)
    monkeypatch.setattr(identities, "_host_unused", lambda uid, gid: None)
    project = tmp_path / "project"
    project.mkdir()
    grant = identities.provision(project, "portal", first_uid=29000, last_uid=29000)
    # Disallow silently falling back to numeric service IDs without NSS support.
    monkeypatch.setattr(identities, "_checked_nss",
                        lambda grant: (_ for _ in ()).throw(
                            ExecutionIdentityError("execution grant needs host NSS activation")))
    with pytest.raises(ExecutionIdentityError, match="activation"):
        identities.resolve(project, "portal")
    # Provisioning is idempotent even if NSS has not been activated yet.
    assert identities.provision(project, "portal", first_uid=29000, last_uid=29000) == grant


def test_host_nss_activation_is_idempotent_and_confined_to_grant(tmp_path, monkeypatch):
    real_validator = identities._checked_nss
    _registry(tmp_path, monkeypatch)
    monkeypatch.setattr(identities.os, "geteuid", lambda: 0)
    monkeypatch.setattr(identities, "_host_unused", lambda uid, gid: None)
    # Exercise actual verification, but simulated host NSS administration.
    monkeypatch.setattr(identities, "_checked_nss", real_validator)
    accounts, groups, commands = {}, {}, []
    from zog.root_control.identities import pwd, grp
    def passwd(name):
        if name not in accounts:
            raise KeyError(name)
        return accounts[name]
    def group(name):
        if name not in groups:
            raise KeyError(name)
        return groups[name]
    monkeypatch.setattr(pwd, "getpwnam", passwd)
    def by_uid(uid):
        for value in accounts.values():
            if value.pw_uid == uid:
                return value
        raise KeyError(uid)
    def by_gid(gid):
        for value in groups.values():
            if value.gr_gid == gid:
                return value
        raise KeyError(gid)
    monkeypatch.setattr(pwd, "getpwuid", by_uid)
    monkeypatch.setattr(grp, "getgrnam", group)
    monkeypatch.setattr(grp, "getgrgid", by_gid)
    monkeypatch.setattr(identities, "_shadow_password_locked", lambda name: True)
    monkeypatch.setattr(identities.os, "getgrouplist", lambda name, gid: [gid])
    monkeypatch.setattr(identities.Path, "is_file", lambda p: True)
    def tool(*args):
        commands.append(args)
        name = args[-1]
        if args[0].endswith("groupadd"):
            groups[name] = SimpleNamespace(gr_name=name, gr_gid=int(args[2]), gr_mem=[])
        else:
            accounts[name] = SimpleNamespace(
                pw_name=name, pw_uid=int(args[args.index("--uid") + 1]),
                pw_gid=int(args[args.index("--gid") + 1]),
                pw_dir="/nonexistent", pw_shell=args[args.index("--shell") + 1],
            )
    monkeypatch.setattr(identities, "_run_identity_tool", tool)
    project = tmp_path / "project"
    project.mkdir()
    grant = identities.provision(project, "portal", first_uid=29001, last_uid=29001)
    assert identities.activate(project, "portal") == grant
    assert identities.resolve(project, "portal") == grant
    assert identities.activate(project, "portal") == grant
    assert len(commands) == 2
    assert identities.principal_name(grant).startswith("zog-app-")
    assert grant["uid"] == 29001
    monkeypatch.setattr(identities.os, "getgrouplist", lambda name, gid: [gid, 0])
    with pytest.raises(ExecutionIdentityError, match="supplementary groups"):
        identities.resolve(project, "portal")
    monkeypatch.setattr(identities.os, "getgrouplist", lambda name, gid: [gid])
    monkeypatch.setattr(identities, "_shadow_password_locked", lambda name: False)
    with pytest.raises(ExecutionIdentityError, match="locked password"):
        identities.resolve(project, "portal")


def test_activation_refuses_foreign_nss_identity(tmp_path, monkeypatch):
    _registry(tmp_path, monkeypatch)
    monkeypatch.setattr(identities.os, "geteuid", lambda: 0)
    monkeypatch.setattr(identities, "_host_unused", lambda uid, gid: None)
    project = tmp_path / "project"
    project.mkdir()
    grant = identities.provision(project, "portal", first_uid=29010, last_uid=29010)
    from zog.root_control.identities import pwd, grp
    monkeypatch.setattr(pwd, "getpwnam", lambda name: (_ for _ in ()).throw(KeyError(name)))
    monkeypatch.setattr(pwd, "getpwuid",
                        lambda uid: SimpleNamespace(pw_name="some-other-user", pw_uid=uid))
    monkeypatch.setattr(grp, "getgrnam", lambda name: (_ for _ in ()).throw(KeyError(name)))
    monkeypatch.setattr(grp, "getgrgid", lambda gid: (_ for _ in ()).throw(KeyError(gid)))
    monkeypatch.setattr(identities, "_run_identity_tool",
                        lambda *args: pytest.fail("foreign collision must not mutate host NSS"))
    with pytest.raises(ExecutionIdentityError, match="collides"):
        identities.activate(project, "portal")
