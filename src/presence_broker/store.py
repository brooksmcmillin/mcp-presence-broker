"""The service-owned reference monitor. No client-supplied presence proofs.

Derived from the policy_store/totp_gate pattern in Brooks McMillin's infra broker.
Every stateful decision is serialized with SQLite BEGIN IMMEDIATE, including
factor consumption, grant minting and the protected operation itself.
"""

import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import stat
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pyotp

CAPABILITY = "counter.increment"
MAX_TTL = 300
MAX_FAILURES = 5
LOCKOUT_SECONDS = 60
SCHEMA_VERSION = 1


class Denied(Exception):
    """A stable, non-secret refusal reason."""


class Store:
    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.database = directory / "broker.sqlite3"
        self.seed_file = directory / "totp.seed"
        self._check_private(directory, directory=True)
        self._check_private(self.database)
        self._check_private(self.seed_file)
        self.secret = self.seed_file.read_text().strip()
        if not re.fullmatch(r"[A-Z2-7]{32}", self.secret):
            raise ValueError("invalid TOTP seed")
        with self.transaction() as conn:
            if conn.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION:
                raise ValueError("unsupported database version; refusing to modify it")

    @staticmethod
    def _check_private(path: Path, *, directory: bool = False) -> None:
        info = path.lstat()
        expected_type = stat.S_ISDIR if directory else stat.S_ISREG
        if not expected_type(info.st_mode) or info.st_uid != os.geteuid():
            raise ValueError(f"must be owned by the service user: {path}")
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise ValueError(f"must not be accessible to group/other: {path}")

    @classmethod
    def initialize(cls, directory: Path) -> "Store":
        # mkdir is exclusive: never overwrite an existing enrollment or database.
        directory.mkdir(mode=0o700, parents=True, exist_ok=False)
        seed = directory / "totp.seed"
        with open(seed, "x", opener=lambda p, f: os.open(p, f, 0o600)) as handle:
            handle.write(pyotp.random_base32() + "\n")
        database = directory / "broker.sqlite3"
        database.touch(mode=0o600, exist_ok=False)
        with sqlite3.connect(database) as conn:
            conn.executescript("""
                CREATE TABLE sessions (
                    id INTEGER PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE,
                    label TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE grants (
                    id INTEGER PRIMARY KEY, session_id INTEGER NOT NULL REFERENCES sessions(id),
                    capability TEXT NOT NULL, expires REAL NOT NULL,
                    revoked INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE factor (
                    id INTEGER PRIMARY KEY CHECK(id = 1), last_step INTEGER NOT NULL DEFAULT -1,
                    failures INTEGER NOT NULL DEFAULT 0, locked_until REAL NOT NULL DEFAULT 0
                );
                INSERT INTO factor (id) VALUES (1);
                CREATE TABLE counter (id INTEGER PRIMARY KEY CHECK(id = 1), value INTEGER NOT NULL);
                INSERT INTO counter VALUES (1, 0);
                CREATE TABLE audit (
                    id INTEGER PRIMARY KEY, timestamp REAL NOT NULL, session_id INTEGER,
                    event TEXT NOT NULL, detail TEXT NOT NULL
                );
                PRAGMA user_version = 1;
            """)
        return cls(directory)

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.database, timeout=10, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            conn.execute("BEGIN IMMEDIATE")
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

    @staticmethod
    def _audit(conn: sqlite3.Connection, session: int | None, event: str, **detail: object) -> None:
        conn.execute(
            "INSERT INTO audit (timestamp, session_id, event, detail) VALUES (?, ?, ?, ?)",
            (time.time(), session, event, json.dumps(detail, sort_keys=True)),
        )

    def create_session(self, label: str) -> str:
        if not 1 <= len(label) <= 80:
            raise ValueError("label must contain 1–80 characters")
        token = secrets.token_urlsafe(32)
        digest = hashlib.sha256(token.encode()).hexdigest()
        with self.transaction() as conn:
            result = conn.execute(
                "INSERT INTO sessions (token_hash, label) VALUES (?, ?)", (digest, label)
            )
            self._audit(conn, result.lastrowid, "session_created")
        return token

    @staticmethod
    def _session(conn: sqlite3.Connection, token: str) -> int:
        digest = hashlib.sha256(token.encode()).hexdigest()
        row = conn.execute(
            "SELECT id FROM sessions WHERE token_hash = ? AND revoked = 0", (digest,)
        ).fetchone()
        if row is None:
            raise Denied("invalid_session")
        return int(row["id"])

    def authenticate(self, token: str) -> None:
        with self.transaction() as conn:
            self._session(conn, token)

    def request_grant(
        self, token: str, code: str | None, capability: str = CAPABILITY, ttl: int = 60
    ) -> dict[str, object]:
        """The only grant insertion path verifies the factor inside the transaction.

        Refusals commit their counters/audit before raising. Lockout and replay
        state are global to the enrollment, not reset by creating another session.
        """
        reason: str | None = None
        result: dict[str, object] = {}
        with self.transaction() as conn:
            session = self._session(conn, token)
            now = time.time()
            state = conn.execute("SELECT * FROM factor WHERE id = 1").fetchone()
            if capability != CAPABILITY or not 1 <= ttl <= MAX_TTL:
                reason = "invalid_request"
            elif now < state["locked_until"]:
                reason = "locked_out"
            else:
                step = int(now // 30)
                matched = None
                if code is not None and re.fullmatch(r"[0-9]{6}", code):
                    totp = pyotp.TOTP(self.secret)
                    for candidate in (step - 1, step, step + 1):
                        if hmac.compare_digest(totp.at(candidate * 30), code):
                            matched = candidate
                            break
                if matched is None:
                    reason = "presence_check_failed"
                elif matched <= state["last_step"]:
                    reason = "replayed_code"
                if reason:
                    failures = state["failures"] + 1
                    locked_until = now + LOCKOUT_SECONDS if failures >= MAX_FAILURES else 0
                    conn.execute(
                        "UPDATE factor SET failures = ?, locked_until = ? WHERE id = 1",
                        (0 if locked_until else failures, locked_until),
                    )
                else:
                    conn.execute(
                        "UPDATE factor SET last_step = ?, failures = 0, locked_until = 0 "
                        "WHERE id = 1",
                        (matched,),
                    )
                    cursor = conn.execute(
                        "INSERT INTO grants (session_id, capability, expires) VALUES (?, ?, ?)",
                        (session, capability, now + ttl),
                    )
                    result = {
                        "grant_id": cursor.lastrowid,
                        "capability": capability,
                        "expires": now + ttl,
                    }
                    self._audit(conn, session, "grant_issued", **result, totp_verified=True)
            if reason:
                self._audit(conn, session, "approval_denied", reason=reason)
        if reason:
            raise Denied(reason)
        return result

    def grants(self, token: str) -> list[dict[str, object]]:
        with self.transaction() as conn:
            session = self._session(conn, token)
            return [
                dict(row)
                for row in conn.execute(
                    "SELECT id, capability, expires FROM grants "
                    "WHERE session_id = ? AND revoked = 0 AND expires > ?",
                    (session, time.time()),
                )
            ]

    def revoke(self, token: str) -> None:
        with self.transaction() as conn:
            session = self._session(conn, token)
            conn.execute("UPDATE grants SET revoked = 1 WHERE session_id = ?", (session,))
            self._audit(conn, session, "grants_revoked")

    def revoke_session(self, session: int) -> None:
        with self.transaction() as conn:
            if not conn.execute("SELECT 1 FROM sessions WHERE id = ?", (session,)).fetchone():
                raise ValueError("unknown session")
            conn.execute("UPDATE sessions SET revoked = 1 WHERE id = ?", (session,))
            conn.execute("UPDATE grants SET revoked = 1 WHERE session_id = ?", (session,))
            self._audit(conn, session, "session_revoked")

    def increment(self, token: str) -> int:
        denied = False
        value = 0
        with self.transaction() as conn:
            session = self._session(conn, token)
            grant = conn.execute(
                "SELECT id FROM grants WHERE session_id = ? AND capability = ? "
                "AND revoked = 0 AND expires > ? LIMIT 1",
                (session, CAPABILITY, time.time()),
            ).fetchone()
            if grant is None:
                denied = True
                self._audit(conn, session, "tool_denied", capability=CAPABILITY)
            else:
                conn.execute("UPDATE counter SET value = value + 1 WHERE id = 1")
                value = conn.execute("SELECT value FROM counter WHERE id = 1").fetchone()[0]
                self._audit(
                    conn,
                    session,
                    "tool_executed",
                    capability=CAPABILITY,
                    grant_id=grant["id"],
                    value=value,
                )
        if denied:
            raise Denied("capability_denied")
        return value

    def audit(self) -> list[dict[str, object]]:
        with self.transaction() as conn:
            return [dict(row) for row in conn.execute("SELECT * FROM audit ORDER BY id")]
