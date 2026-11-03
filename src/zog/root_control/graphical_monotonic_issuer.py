"""Source-only independently administered graphical monotonic checkpoint issuer.

Not a network service or permission to run one. The ledger directory, signing
key and rollback-resistant storage must be separately installed and audited.
The synthetic file backend demonstrates compare-and-advance durability only;
a coherent rollback of THIS storage remains detectable only with an actual
independently operated, non-rollbackable backend.
"""
from __future__ import annotations
import base64
import fcntl
import hashlib
import json
import os
import re
import secrets
import stat
from contextlib import contextmanager
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

SCHEMA="zog-host-install-graphical-external-monotonic-checkpoint-v1"
STATE_SCHEMA="zog-root-control-graphical-monotonic-state-v1"
DOMAIN=b"zog-graphical-external-checkpoint-v1\x00"
LOCK=".graphical-monotonic.lock"
HEX64=re.compile(r"[0-9a-f]{64}\Z")
NONCE=re.compile(r"[0-9a-f]{48}\Z")
IDENTITY=re.compile(r"[a-zA-Z0-9-]{1,128}\Z")
OPID=re.compile(r"[A-Za-z0-9-]{1,96}\Z")

class CheckpointDenied(RuntimeError):
    pass

def deny():
    raise CheckpointDenied("independent checkpoint unavailable or conflicted") from None

def canonical(x):
    return json.dumps(x,sort_keys=True,separators=(",",":"),
                      ensure_ascii=True,allow_nan=False).encode("ascii")

def strict(raw):
    try:
        if type(raw) is not bytes or not 0<len(raw)<=8192:deny()
        def unique(pairs):
            result={}
            for k,v in pairs:
                if k in result:deny()
                result[k]=v
            return result
        row=json.loads(raw,object_pairs_hook=unique,
                       parse_constant=lambda _:deny())
        if type(row) is not dict or canonical(row)!=raw:deny()
        return row
    except (ValueError,TypeError,UnicodeError,OverflowError):
        deny()

def sha(x):
    return hashlib.sha256(x).hexdigest()

def _key(host, installation):
    if (type(host) is not str or type(installation) is not str
            or not IDENTITY.fullmatch(host)
            or not IDENTITY.fullmatch(installation)):
        deny()
    return sha(canonical({"host":host,"installation":installation}))

class Issuer:
    """Only a source fixture. No socket/CLI/live installer exists.

    The separately operated native issuer must bind actual client identity
    to Host/installation and ensure an independently pinned public key.
    """
    def __init__(self, dirfd, *, signer, owner_uid=None):
        if type(dirfd) is not int or not isinstance(signer,Ed25519PrivateKey):
            deny()
        self.fd=dirfd
        self.uid=os.geteuid() if owner_uid is None else owner_uid
        st=os.fstat(dirfd)
        if (not stat.S_ISDIR(st.st_mode) or st.st_uid!=self.uid
                or stat.S_IMODE(st.st_mode)!=0o700):
            deny()
        self.signer=signer
        self.public_key=signer.public_key().public_bytes(
            serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        self.public_sha256=sha(self.public_key)
        self._open_lock()

    def _open_lock(self):
        try:
            fd=os.open(LOCK,os.O_RDWR|os.O_CREAT|os.O_EXCL|
                       os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=self.fd)
            os.fchmod(fd,0o600)
            os.fsync(fd)
            os.fsync(self.fd)
        except FileExistsError:
            fd=os.open(LOCK,os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=self.fd)
        inode=self._regular(fd)
        self._lock_identity=(inode.st_dev,inode.st_ino)
        os.close(fd)

    def _regular(self,fd):
        st=os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_nlink!=1
                or st.st_uid!=self.uid or stat.S_IMODE(st.st_mode)!=0o600):
            deny()
        return st

    @contextmanager
    def _locked(self):
        fd=os.open(LOCK,os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=self.fd)
        try:
            st=self._regular(fd)
            fcntl.flock(fd,fcntl.LOCK_EX)
            path=os.stat(LOCK,dir_fd=self.fd,follow_symlinks=False)
            if ((path.st_dev,path.st_ino)!=(st.st_dev,st.st_ino)
                    or (st.st_dev,st.st_ino)!=self._lock_identity):deny()
            yield
        finally:
            fcntl.flock(fd,fcntl.LOCK_UN)
            os.close(fd)

    def _read(self,name):
        try:
            fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=self.fd)
        except FileNotFoundError:
            return None
        try:
            st=self._regular(fd)
            if not 0<st.st_size<=8192:deny()
            raw=os.read(fd,8193)
            if len(raw)!=st.st_size:deny()
            return strict(raw)
        finally:
            os.close(fd)

    def _write(self,name,row):
        b=canonical(row)
        if len(b)>8192:deny()
        temp=".monotonic-staged-"+secrets.token_hex(16)
        fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|
                   os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=self.fd)
        try:
            os.fchmod(fd,0o600)
            if os.write(fd,b)!=len(b):deny()
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temp,name,src_dir_fd=self.fd,dst_dir_fd=self.fd)
        os.fsync(self.fd)

    def _state(self,host,installation):
        name=_key(host,installation)+".json"
        row=self._read(name)
        if row is None:
            return name,{"schema":STATE_SCHEMA,"host_id":host,
                         "installation_id":installation,"epoch":0,
                         "sequence":1,"pin_sha256":None,
                         "approval_sha256":None,"operation_id":None}
        if (set(row)!={"schema","host_id","installation_id","epoch",
                       "sequence","pin_sha256","approval_sha256","operation_id"}
                or row["schema"]!=STATE_SCHEMA
                or row["host_id"]!=host or row["installation_id"]!=installation
                or type(row["epoch"]) is not int or row["epoch"]<1
                or type(row["sequence"]) is not int or row["sequence"]<2
                or any(type(row[k]) is not str or not HEX64.fullmatch(row[k])
                       for k in ("pin_sha256","approval_sha256"))
                or type(row["operation_id"]) is not str
                or not OPID.fullmatch(row["operation_id"])):
            deny()
        return name,row

    def read_signed(self,*,host_id,installation_id,nonce):
        if type(nonce) is not str or not NONCE.fullmatch(nonce):deny()
        with self._locked():
            _,row=self._state(host_id,installation_id)
            body={k:row[k] for k in ("host_id","installation_id","epoch",
                    "sequence","pin_sha256","approval_sha256")}
            body.update({"schema":SCHEMA,"nonce":nonce})
            signature=self.signer.sign(DOMAIN+canonical(body))
            return canonical({**body,"signature_ed25519":
                base64.b64encode(signature).decode("ascii")})

    def compare_and_advance(self,*,host_id,installation_id,expected_epoch,
                            expected_sequence,expected_pin_sha256,next_epoch,
                            next_pin_sha256,next_approval_sha256,operation_id):
        if (type(operation_id) is not str or not OPID.fullmatch(operation_id)
                or type(next_epoch) is not int or next_epoch<1
                or type(next_pin_sha256) is not str
                or type(next_approval_sha256) is not str
                or not HEX64.fullmatch(next_pin_sha256)
                or not HEX64.fullmatch(next_approval_sha256)):
            deny()
        with self._locked():
            name,row=self._state(host_id,installation_id)
            if (row["epoch"]==next_epoch
                    and row["pin_sha256"]==next_pin_sha256
                    and row["approval_sha256"]==next_approval_sha256
                    and row["operation_id"]==operation_id):
                # Lost acknowledgement of this exact durable CAS; never
                # increments a second time and never allows key replacement.
                return dict(row)
            if (row["epoch"]!=expected_epoch or
                    row["sequence"]!=expected_sequence or
                    row["pin_sha256"]!=expected_pin_sha256 or
                    next_epoch!=row["epoch"]+1):
                deny()
            new={**row,"epoch":next_epoch,"sequence":row["sequence"]+1,
                 "pin_sha256":next_pin_sha256,
                 "approval_sha256":next_approval_sha256,
                 "operation_id":operation_id}
            self._write(name,new)
            return dict(new)
