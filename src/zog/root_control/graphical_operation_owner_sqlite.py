"""Installed-candidate protected graphical owner ledger.

Source-level implementation of a persistent one-way claim fence. A native
installer MUST provision an independently protected directory/database and
externally monotonic checkpoint; this module never initializes storage or
grants SSM authority. SQLite disk durability alone is NOT rollback resistance.
"""
from __future__ import annotations
import fcntl
import json
import os
from pathlib import Path
import sqlite3
import stat
import time

from . import graphical_operation_owner_source as contract

SCHEMA = "zog-graphical-owner-sqlite-ledger-v1"

class OwnerStorageHold(contract.OperationDenied):
    pass

def hold():
    raise OwnerStorageHold("independent graphical operation owner ledger unavailable")

def _require_private(path, mode, directory=False):
    p = Path(path)
    if p.is_symlink(): hold()
    try: s=p.lstat()
    except OSError: hold()
    if ((not stat.S_ISDIR(s.st_mode) if directory else not stat.S_ISREG(s.st_mode))
            or s.st_uid!=os.geteuid() or stat.S_IMODE(s.st_mode)!=mode
            or (not directory and s.st_nlink!=1)):
        hold()
    return p

class ExistingOwnerLedger:
    """Open only externally provisioned state; never create/truncate/rebase."""
    def __init__(self, directory, *, approved_scope, external_checkpoint):
        self.directory=_require_private(directory,0o700,directory=True)
        self.lock_path=_require_private(self.directory/"owner.lock",0o600)
        self.database_path=_require_private(self.directory/"owner.sqlite3",0o600)
        if type(external_checkpoint) is not dict or set(external_checkpoint)!={
            "schema","storage_id","minimum_sequence","scope_sha256"} or (
            external_checkpoint["schema"]!="zog-graphical-owner-independent-highwater-v1"
            or type(external_checkpoint["storage_id"]) is not str
            or len(external_checkpoint["storage_id"])!=64
            or type(external_checkpoint["minimum_sequence"]) is not int
            or external_checkpoint["minimum_sequence"]<0
            or external_checkpoint["scope_sha256"]!=contract.digest(approved_scope)):
            hold()
        self.scope=approved_scope
        self.checkpoint=external_checkpoint

    def _locked(self):
        # Opening via O_NOFOLLOW and verifying the open inode prevents a
        # replaced path from silently becoming a new lock domain.
        fd=os.open(self.lock_path,os.O_RDWR|os.O_CLOEXEC|os.O_NOFOLLOW)
        a=os.fstat(fd);b=os.lstat(self.lock_path)
        if (a.st_ino,a.st_dev)!=(b.st_ino,b.st_dev) or a.st_uid!=os.geteuid() or stat.S_IMODE(a.st_mode)!=0o600:
            os.close(fd);hold()
        fcntl.flock(fd,fcntl.LOCK_EX)
        return fd

    def _open(self):
        _require_private(self.database_path,0o600)
        # SQLite immutable? no: requires durable transaction. URI mode=rw
        # prohibits accidental initialization of a missing database.
        db=sqlite3.connect("file:"+str(self.database_path)+"?mode=rw",
                           uri=True,timeout=5,isolation_level=None)
        db.execute("PRAGMA busy_timeout=5000")
        db.execute("PRAGMA journal_mode=DELETE")
        db.execute("PRAGMA synchronous=FULL")
        required={"metadata","approved","claims"}
        if not required.issubset({r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}):
            db.close();hold()
        metadata=dict(db.execute("SELECT key,value FROM metadata"))
        if (metadata.get("schema")!=SCHEMA
                or metadata.get("storage_id")!=self.checkpoint["storage_id"]
                or metadata.get("scope_sha256")!=self.checkpoint["scope_sha256"]
                or int(metadata.get("sequence","-1"))<self.checkpoint["minimum_sequence"]
                or metadata.get("revoked") not in ("0","1")):
            db.close();hold()
        return db

    def _run(self, operation):
        lock=self._locked()
        try:
            db=self._open()
            try:
                return operation(db)
            finally:db.close()
        finally:
            fcntl.flock(lock,fcntl.LOCK_UN)
            os.close(lock)

    def claim_and_send(self, request, *, sender):
        """Send once with same exclusive mutex as revoke, never replay.

        `sender` injection is for source testing; native entrypoints MUST
        use one root-installed fixed sender, not accept it from RPC.
        """
        req=contract.validate_request(request)
        if contract.scope_from_request(req)!=self.scope:hold()
        if not callable(sender):hold()
        def operation(db):
            db.execute("BEGIN IMMEDIATE")
            try:
                row=db.execute("SELECT digest FROM approved WHERE operation_id=?",
                               (req["operation_id"],)).fetchone()
                if row is None or row[0]!=contract.digest(req):hold()
                metadata=dict(db.execute("SELECT key,value FROM metadata"))
                if metadata["revoked"]!="0":hold()
                if db.execute("SELECT 1 FROM claims WHERE operation_id=?",
                              (req["operation_id"],)).fetchone():hold()
                sequence=int(metadata["sequence"])+1
                db.execute("INSERT INTO claims(operation_id,request_sha256,sequence,outcome,command_id) VALUES(?,?,?,?,NULL)",
                    (req["operation_id"],contract.digest(req),sequence,"CLAIMED_UNCERTAIN"))
                db.execute("UPDATE metadata SET value=? WHERE key='sequence'",(str(sequence),))
                db.execute("COMMIT")
            except BaseException:
                if db.in_transaction:db.execute("ROLLBACK")
                raise
            # The irreversible row and SQLite full fsync are committed
            # before any external call; a crash / lost ACK never retries.
            command_id=sender(req)
            if type(command_id) is not str or not 1<=len(command_id)<=128:hold()
            db.execute("BEGIN IMMEDIATE")
            db.execute("UPDATE claims SET outcome='SENT_ORIGINAL',command_id=? WHERE operation_id=? AND outcome='CLAIMED_UNCERTAIN'",
                       (command_id,req["operation_id"]))
            db.execute("COMMIT")
            return {"outcome":"SENT_ORIGINAL","command_id":command_id,"sequence":sequence}
        return self._run(operation)

    def revoke(self, approved_scope):
        if approved_scope!=self.scope:hold()
        def operation(db):
            db.execute("BEGIN IMMEDIATE")
            meta=dict(db.execute("SELECT key,value FROM metadata"))
            sequence=int(meta["sequence"])
            if meta["revoked"]=="0":
                sequence+=1
                db.execute("UPDATE metadata SET value='1' WHERE key='revoked'")
                db.execute("UPDATE metadata SET value=? WHERE key='sequence'",(str(sequence),))
            db.execute("COMMIT")
            return sequence
        return self._run(operation)

    def inspect(self, operation_id):
        def operation(db):
            row=db.execute("SELECT request_sha256,sequence,outcome,command_id FROM claims WHERE operation_id=?",(operation_id,)).fetchone()
            if row is None:hold()
            return {"operation_id":operation_id,"request_sha256":row[0],
                    "sequence":row[1],"outcome":row[2],"command_id":row[3]}
        return self._run(operation)

def provision_synthetic_fixture(directory, *, scope, operations, storage_id):
    """TEST-ONLY explicit provisioning; not called by service or installer."""
    directory=Path(directory)
    directory.mkdir(mode=0o700)
    (directory/"owner.lock").write_bytes(b"")
    os.chmod(directory/"owner.lock",0o600)
    path=directory/"owner.sqlite3"
    db=sqlite3.connect(path)
    db.executescript("""
      CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
      CREATE TABLE approved(operation_id TEXT PRIMARY KEY,digest TEXT NOT NULL);
      CREATE TABLE claims(operation_id TEXT PRIMARY KEY,request_sha256 TEXT NOT NULL,
                          sequence INTEGER NOT NULL UNIQUE,outcome TEXT NOT NULL,
                          command_id TEXT);
    """)
    db.executemany("INSERT INTO metadata VALUES (?,?)",[
        ("schema",SCHEMA),("storage_id",storage_id),
        ("scope_sha256",contract.digest(scope)),("sequence","0"),("revoked","0")])
    db.executemany("INSERT INTO approved VALUES (?,?)",operations.items())
    db.commit();db.close()
    os.chmod(path,0o600)
