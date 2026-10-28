"""Source-only effective sshd key-to-UID attestation regressions."""
import base64
import hashlib
import os
import pytest
from zog.root_control import issuer_cross_host_ssh_admission as ssh
from zog.root_control.issuer_cross_host import CrossHostDenied

COMMAND = "/usr/bin/python3 -I -m zog.root_control.issuer_cross_host ssh-bridge"
PATH = "/etc/zog/issuer-credentials/bridge_authorized_keys"


def fixture():
    blob = b"\x00\x00\x00\x0bssh-ed25519" + b"\x00\x00\x00\x20" + b"K"*32
    key = base64.b64encode(blob).decode()
    fingerprint = "SHA256:" + base64.b64encode(
        hashlib.sha256(blob).digest()).decode().rstrip("=")
    values = dict(pubkeyauthentication="yes",
                  authenticationmethods="publickey",
                  authorizedkeysfile=PATH, authorizedkeyscommand="none",
                  forcecommand=COMMAND, permitopen="none",
                  permitlisten="none")
    for k in ssh._DISABLED:
        values[k]="no"
    config="".join(k+" "+v+"\n" for k,v in values.items()).encode()
    keys=(ssh.OPTIONS+" ssh-ed25519 "+key+"\n").encode()
    args=dict(account="issuer_bridge",uid=29001,gid=29002,
              fingerprint=fingerprint,authorized_keys_path=PATH,
              forced_command=COMMAND)
    return config,keys,args


def test_exact_single_key_effective_mapping_and_uid():
    cfg,keys,args=fixture()
    result=ssh.verify(cfg,keys,**args)
    assert result["status"]=="verified-static-ssh-admission"
    assert result["authorized_keys_count"]==1
    assert result["installed_module_attested"] is False
    assert result["ssh_connection_tested"] is False


@pytest.mark.parametrize("field, wrong",[
    ("authenticationmethods","any"),
    ("forcecommand","/bin/sh"),
    ("authorizedkeyscommand","/usr/local/bin/key-provider"),
    ("authorizedkeysfile","/home/issuer_bridge/.ssh/authorized_keys"),
    ("passwordauthentication","yes"),
    ("kbdinteractiveauthentication","yes"),
    ("allowtcpforwarding","yes"),
    ("allowagentforwarding","yes"),
    ("permittty","yes"),
    ("permittunnel","yes"),
    ("allowstreamlocalforwarding","yes"),
    ("permitopen","127.0.0.1:80"),
    ("pubkeyauthentication","no"),
])
def test_effective_sshd_escape_or_other_login_method_rejected(field,wrong):
    cfg,keys,args=fixture()
    text=cfg.decode().replace(field+" "+(
        dict(line.partition(" ")[::2] for line in cfg.decode().splitlines()).get(field,"")
    ),field+" "+wrong)
    with pytest.raises(CrossHostDenied):
        ssh.verify(text.encode(),keys,**args)


def test_missing_effective_setting_or_duplicate_key_is_rejected():
    cfg,keys,args=fixture()
    cfg=cfg.replace(b"passwordauthentication no\n",b"")
    with pytest.raises(CrossHostDenied):
        ssh.verify(cfg,keys,**args)
    cfg,keys,args=fixture()
    with pytest.raises(CrossHostDenied):
        ssh.verify(cfg,keys+keys,**args)
    with pytest.raises(CrossHostDenied):
        ssh.verify(cfg,keys.replace(b'restrict,command="issuer-cloudflare-read-v1"',
                                    b'command="issuer-cloudflare-read-v1"'),**args)


def test_foreign_ssh_identity_uid_gid_or_path_rejected():
    cfg,keys,args=fixture()
    for changes in (
        dict(fingerprint="SHA256:"+"B"*43),
        dict(uid=0),dict(gid=0),
        dict(authorized_keys_path="/tmp/authorized_keys"),
        dict(forced_command="/bin/sh"),
    ):
        with pytest.raises(CrossHostDenied):
            ssh.verify(cfg,keys,**dict(args,**changes))


def test_disabled_extra_authentication_must_not_be_ignored():
    cfg,keys,args=fixture()
    cfg=cfg.replace(b"authenticationmethods publickey\n",
                    b"authenticationmethods publickey,password\n")
    with pytest.raises(CrossHostDenied):
        ssh.verify(cfg,keys,**args)
