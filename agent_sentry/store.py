"""SQLite authorization ledger. Every reservation is one BEGIN IMMEDIATE transaction."""

import json
import secrets
import sqlite3
import time
import uuid
from contextlib import contextmanager

from .policy import (
    canonical,
    digest,
    identifier,
    integer,
    scope_reason,
    validate_policy,
)


class Conflict(ValueError):
    """An idempotency key was reused with different inputs."""


class Store:
    def __init__(self, path, clock=time.time):
        self.path = str(path)
        self.clock = clock
        if self.path == ":memory:":
            raise ValueError(
                "Use a file database; each transaction opens its own connection"
            )
        with self.connection() as db:
            db.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY, policy TEXT NOT NULL,
                    calls INTEGER NOT NULL DEFAULT 0 CHECK(calls >= 0),
                    units INTEGER NOT NULL DEFAULT 0 CHECK(units >= 0));
                CREATE TABLE IF NOT EXISTS approvals (
                    token_hash TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES sessions(id),
                    binding TEXT NOT NULL, expires REAL NOT NULL, used INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS requests (
                    session_id TEXT NOT NULL REFERENCES sessions(id), request_id TEXT NOT NULL,
                    fingerprint TEXT NOT NULL, response TEXT NOT NULL,
                    PRIMARY KEY(session_id, request_id));
                CREATE TABLE IF NOT EXISTS events (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT, payload TEXT NOT NULL,
                    previous_hash TEXT NOT NULL, event_hash TEXT NOT NULL);
            """)

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        try:
            yield db
        finally:
            db.close()

    @contextmanager
    def transaction(self):
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                yield db
                db.commit()
            except BaseException:
                db.rollback()
                raise

    def _event(self, db, data):
        last = db.execute(
            "SELECT event_hash FROM events ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        previous = last[0] if last else "0" * 64
        payload = canonical({"at": self.clock(), **data})
        checksum = digest({"previous": previous, "payload": payload})
        db.execute(
            "INSERT INTO events(payload, previous_hash, event_hash) VALUES (?,?,?)",
            (payload, previous, checksum),
        )

    def create_session(self, policy):
        policy = validate_policy(policy)
        session = uuid.uuid4().hex
        with self.transaction() as db:
            db.execute(
                "INSERT INTO sessions(id, policy) VALUES (?,?)",
                (session, canonical(policy)),
            )
            self._event(
                db,
                {
                    "kind": "session_created",
                    "session": session,
                    "policy_hash": digest(policy),
                },
            )
        return session

    def _session(self, db, session):
        identifier(session)
        row = db.execute("SELECT * FROM sessions WHERE id=?", (session,)).fetchone()
        if row is None:
            raise KeyError("Unknown session")
        return row

    def approve(self, session, tool, arguments, ttl=300):
        integer(ttl, "ttl", 1, 3600)
        # Only the trusted operator/CLI can issue approval. No public approval endpoint.
        with self.transaction() as db:
            row = self._session(db, session)
            policy = json.loads(row["policy"])
            rule = policy["tools"].get(tool)
            if rule is None or scope_reason(tool, arguments, rule):
                raise ValueError("Cannot approve an unknown or out-of-scope call")
            token = secrets.token_urlsafe(32)
            binding = digest({"tool": tool, "arguments": arguments})
            db.execute(
                "INSERT INTO approvals(token_hash, session_id, binding, expires) VALUES (?,?,?,?)",
                (digest(token), session, binding, self.clock() + ttl),
            )
            self._event(
                db,
                {
                    "kind": "approval_created",
                    "session": session,
                    "tool": tool,
                    "arguments_hash": digest(arguments),
                },
            )
        return token

    def authorize(self, session, request_id, tool, arguments, approval=None):
        identifier(request_id)
        if (
            not isinstance(tool, str)
            or len(tool) > 100
            or not isinstance(arguments, dict)
        ):
            raise ValueError("tool must be a string and arguments must be an object")
        if approval is not None and (
            not isinstance(approval, str) or len(approval) > 200
        ):
            raise ValueError("Invalid approval token")
        encoded = canonical(arguments)
        if len(encoded.encode()) > 32_768:
            raise ValueError("Arguments exceed 32 KiB")
        fingerprint = digest(
            {"tool": tool, "arguments": arguments, "approval": digest(approval)}
        )
        with self.transaction() as db:
            row = self._session(db, session)
            old = db.execute(
                "SELECT * FROM requests WHERE session_id=? AND request_id=?",
                (session, request_id),
            ).fetchone()
            if old:
                if old["fingerprint"] != fingerprint:
                    raise Conflict("request_id already belongs to a different call")
                return {**json.loads(old["response"]), "replayed": True}
            policy = json.loads(row["policy"])
            rule = policy["tools"].get(tool)
            reason = (
                "unknown_tool" if rule is None else scope_reason(tool, arguments, rule)
            )
            token_row = None
            if reason is None and rule["approval"]:
                if not approval:
                    reason = "approval_required"
                else:
                    token_row = db.execute(
                        "SELECT * FROM approvals WHERE token_hash=?",
                        (digest(approval),),
                    ).fetchone()
                    binding = digest({"tool": tool, "arguments": arguments})
                    if (
                        not token_row
                        or token_row["session_id"] != session
                        or token_row["binding"] != binding
                    ):
                        reason = "approval_mismatch"
                    elif token_row["used"]:
                        reason = "approval_used"
                    elif token_row["expires"] <= self.clock():
                        reason = "approval_expired"
            if reason is None and (
                row["calls"] >= policy["max_calls"]
                or row["units"] + rule["units"] > policy["max_units"]
            ):
                reason = "budget_exceeded"
            allowed = reason is None
            calls, units = row["calls"], row["units"]
            if allowed:
                calls += 1
                units += rule["units"]
                db.execute(
                    "UPDATE sessions SET calls=?, units=? WHERE id=?",
                    (calls, units, session),
                )
                if rule["approval"]:
                    db.execute(
                        "UPDATE approvals SET used=1 WHERE token_hash=?",
                        (digest(approval),),
                    )
            response = {
                "session": session,
                "request_id": request_id,
                "allowed": allowed,
                "reason": reason or "allowed",
                "calls": calls,
                "units": units,
                "policy_hash": digest(policy),
                "replayed": False,
            }
            db.execute(
                "INSERT INTO requests VALUES (?,?,?,?)",
                (session, request_id, fingerprint, canonical(response)),
            )
            self._event(
                db,
                {
                    "kind": "decision",
                    "session": session,
                    "request_id": request_id,
                    "tool": tool,
                    "arguments_hash": digest(arguments),
                    "allowed": allowed,
                    "reason": response["reason"],
                    "calls": calls,
                    "units": units,
                    "policy_hash": digest(policy),
                },
            )
            return response

    def sessions(self):
        with self.connection() as db:
            return [
                {
                    "id": r["id"],
                    "calls": r["calls"],
                    "units": r["units"],
                    "policy": json.loads(r["policy"]),
                }
                for r in db.execute("SELECT * FROM sessions ORDER BY rowid DESC")
            ]

    def events(self, after=0, limit=100):
        integer(after, "after", 0, 2**63 - 1)
        integer(limit, "limit", 1, 500)
        with self.connection() as db:
            return [
                {
                    "seq": r["seq"],
                    **json.loads(r["payload"]),
                    "previous_hash": r["previous_hash"],
                    "event_hash": r["event_hash"],
                }
                for r in db.execute(
                    "SELECT * FROM events WHERE seq>? ORDER BY seq LIMIT ?",
                    (after, limit),
                )
            ]

    def verify(self):
        previous = "0" * 64
        count = 0
        with self.connection() as db:
            for row in db.execute("SELECT * FROM events ORDER BY seq"):
                expected = digest({"previous": previous, "payload": row["payload"]})
                if row["previous_hash"] != previous or row["event_hash"] != expected:
                    return {"valid": False, "checked": count, "broken_at": row["seq"]}
                count += 1
                previous = expected
        return {"valid": True, "checked": count, "head": previous}
