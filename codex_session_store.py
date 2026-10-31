"""Durable conversation, webhook and action records.

Use PostgreSQL (DATABASE_URL) for a Render deployment. SQLite is supported for
local development or an explicitly configured persistent disk; Render's normal
local filesystem is ephemeral. Call these synchronous methods in a worker thread
when using an async web server.

The store never claims that an uncertain outbound action failed: an interrupted
``pending`` action requires reconciliation before any new attempt.
"""

from __future__ import annotations

import asyncio
from concurrent.futures import Future
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path
import sqlite3
import threading
import time
from typing import Any, Iterator


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _digest(parts: list[str]) -> str:
    return hashlib.sha256(_json(parts).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class SessionKey:
    """Trusted caller-provided identifiers; case metadata must be validated upstream."""

    user_id: str
    case_id: str
    generation: str
    channel_id: str = ""

    def digest(self) -> str:
        if not all((self.user_id, self.case_id, self.generation)):
            raise ValueError("user_id, case_id and generation are required")
        return _digest([self.channel_id, self.user_id, self.case_id, self.generation])

    def routing_digest(self) -> str:
        """Stable caller identity for locating a case on later turns."""
        if not all((self.user_id, self.generation)):
            raise ValueError("user_id and generation are required")
        return _digest([self.channel_id, self.user_id, self.generation])


@dataclass(frozen=True)
class StoredSession:
    version: int
    data: dict[str, Any]


@dataclass(frozen=True)
class EventRecord:
    status: str
    response: Any | None = None
    delivered: bool = False


@dataclass(frozen=True)
class ActionRecord:
    status: str
    request: Any
    result: Any | None = None


class VersionConflict(RuntimeError):
    """A concurrent worker changed the session; reload before retrying."""


class StateConflict(RuntimeError):
    """An event/action identifier was reused for different work or state."""


class SessionStore:
    """Small transactional store with CAS session writes and idempotency records.

    ``location`` is a PostgreSQL URL or an SQLite file path. The caller must
    provide an authoritative event identifier, not hash just the user's message:
    identical text sent twice can represent different events. Generation must
    change after a practice data reset and between practice and real evaluation.
    """

    def __init__(self, location: str):
        if not location:
            raise ValueError("a database URL or SQLite file path is required")
        self._postgres = location.startswith(("postgres://", "postgresql://"))
        if "://" in location and not self._postgres:
            raise ValueError("only PostgreSQL URLs and SQLite file paths are supported")
        if location == ":memory:":
            raise ValueError("use a file-backed SQLite database for local testing")
        self._location = location
        if not self._postgres:
            Path(location).parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    @contextmanager
    def session_lock(self, key: SessionKey, timeout_seconds: float = 10.0) -> Iterator[None]:
        """Serialize a session across worker processes until the context exits.

        Hold this lock across load, processing, external actions and save. A CAS
        write by itself cannot prevent two different events from executing side
        effects at the same time. PostgreSQL uses a connection-owned advisory
        lock, SQLite a separate per-scope lock database. Neither expires while
        a worker is still running; process/connection death releases the lock.

        This synchronous context must run in a worker thread in async servers.
        Pending event/action records must still be reconciled after a crash.
        """
        if not isinstance(timeout_seconds, (int, float)) or not math.isfinite(timeout_seconds) or timeout_seconds < 0:
            raise ValueError("timeout_seconds must be a finite nonnegative number")
        scope = key.digest()
        if self._postgres:
            try:
                import psycopg
            except ImportError as exc:
                raise RuntimeError("PostgreSQL needs the psycopg package") from exc
            lock_id = int.from_bytes(bytes.fromhex(scope[:16]), "big", signed=True)
            deadline = time.monotonic() + timeout_seconds
            conn = psycopg.connect(self._location, connect_timeout=max(1, math.ceil(timeout_seconds)))
            acquired = False
            try:
                while True:
                    acquired = bool(conn.execute("SELECT pg_try_advisory_lock(%s)", (lock_id,)).fetchone()[0])
                    if acquired:
                        break
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("session lock timed out")
                    time.sleep(min(0.05, remaining))
                yield
            finally:
                conn.close()
        else:
            lock_dir = Path(str(Path(self._location).resolve()) + ".locks")
            lock_dir.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(str(lock_dir / f"{scope}.sqlite"), timeout=timeout_seconds)
            try:
                try:
                    conn.execute("BEGIN IMMEDIATE")
                except sqlite3.OperationalError as exc:
                    if "locked" in str(exc).lower():
                        raise TimeoutError("session lock timed out") from exc
                    raise
                yield
            finally:
                conn.close()

    @asynccontextmanager
    async def async_session_lock(self, key: SessionKey, timeout_seconds: float = 10.0):
        """Async wrapper that keeps acquisition and release in one worker.

        The worker releases its lock even if the coroutine is cancelled while
        waiting. Do not start another request for the same event before its
        pending action has been reconciled.
        """
        loop = asyncio.get_running_loop()
        acquired = loop.create_future()
        release = threading.Event()
        worker_done: Future[None] = Future()

        def report(error: BaseException | None = None) -> None:
            if not acquired.done():
                if error is None:
                    acquired.set_result(None)
                else:
                    acquired.set_exception(error)

        def worker() -> None:
            try:
                with self.session_lock(key, timeout_seconds):
                    loop.call_soon_threadsafe(report)
                    release.wait()
            except BaseException as exc:
                try:
                    loop.call_soon_threadsafe(report, exc)
                except RuntimeError:
                    pass
            finally:
                worker_done.set_result(None)

        threading.Thread(target=worker, name="session-lock", daemon=True).start()
        try:
            await acquired
            yield
        finally:
            release.set()
            await asyncio.shield(asyncio.wrap_future(worker_done))

    @contextmanager
    def _connection(self) -> Iterator[Any]:
        if self._postgres:
            try:
                import psycopg
            except ImportError as exc:
                raise RuntimeError("PostgreSQL needs the psycopg package") from exc
            # Do not let an unreachable database exhaust the whole chatbot
            # response budget before the turn-level deadline can react.
            conn = psycopg.connect(self._location, connect_timeout=5)
        else:
            conn = sqlite3.connect(self._location, timeout=10)
            conn.execute("PRAGMA busy_timeout = 10000")
        try:
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _execute(self, conn: Any, query: str, params: tuple[Any, ...] = ()) -> Any:
        if self._postgres:
            query = query.replace("?", "%s")
        return conn.execute(query, params)

    def _init_schema(self) -> None:
        with self._connection() as conn:
            self._execute(conn, """CREATE TABLE IF NOT EXISTS contest_sessions (
                scope TEXT PRIMARY KEY, version INTEGER NOT NULL, data TEXT NOT NULL,
                updated_at DOUBLE PRECISION NOT NULL)""")
            self._execute(conn, """CREATE TABLE IF NOT EXISTS contest_active_cases (
                routing_scope TEXT PRIMARY KEY, case_id TEXT NOT NULL,
                updated_at DOUBLE PRECISION NOT NULL)""")
            self._execute(conn, """CREATE TABLE IF NOT EXISTS contest_events (
                scope TEXT NOT NULL, event_id TEXT NOT NULL, payload_hash TEXT NOT NULL,
                status TEXT NOT NULL, response TEXT, delivered INTEGER NOT NULL DEFAULT 0,
                updated_at DOUBLE PRECISION NOT NULL, PRIMARY KEY(scope, event_id))""")
            self._execute(conn, """CREATE TABLE IF NOT EXISTS contest_actions (
                scope TEXT NOT NULL, action_key TEXT NOT NULL, request TEXT NOT NULL,
                status TEXT NOT NULL, result TEXT, updated_at DOUBLE PRECISION NOT NULL,
                PRIMARY KEY(scope, action_key))""")

    def bind_active_case(self, key: SessionKey, *, allow_replace: bool = False) -> None:
        """Bind a validated case to an identity for later messages."""
        key.digest()
        routing = key.routing_digest()
        with self._connection() as conn:
            if allow_replace:
                self._execute(conn, """INSERT INTO contest_active_cases (routing_scope, case_id, updated_at)
                    VALUES (?, ?, ?) ON CONFLICT(routing_scope) DO UPDATE SET
                    case_id = excluded.case_id, updated_at = excluded.updated_at""",
                    (routing, key.case_id, time.time()))
            else:
                self._execute(conn, """INSERT INTO contest_active_cases (routing_scope, case_id, updated_at)
                    VALUES (?, ?, ?) ON CONFLICT(routing_scope) DO NOTHING""",
                    (routing, key.case_id, time.time()))
                row = self._execute(conn, "SELECT case_id FROM contest_active_cases WHERE routing_scope = ?",
                                    (routing,)).fetchone()
                if row[0] != key.case_id:
                    raise StateConflict("another case is already bound to this conversation")

    def active_case(self, user_id: str, generation: str, channel_id: str = "") -> SessionKey | None:
        """Recover the bound case for a follow-up without trusting message text."""
        routing_key = SessionKey(user_id, "", generation, channel_id)
        with self._connection() as conn:
            row = self._execute(conn, "SELECT case_id FROM contest_active_cases WHERE routing_scope = ?",
                                (routing_key.routing_digest(),)).fetchone()
        return None if row is None else SessionKey(user_id, row[0], generation, channel_id)

    def load(self, key: SessionKey) -> StoredSession | None:
        with self._connection() as conn:
            row = self._execute(conn, "SELECT version, data FROM contest_sessions WHERE scope = ?", (key.digest(),)).fetchone()
        return None if row is None else StoredSession(row[0], json.loads(row[1]))

    def save(self, key: SessionKey, data: dict[str, Any], expected_version: int = 0) -> int:
        """Atomically create at version 0 or update the version just loaded."""
        if not isinstance(data, dict) or expected_version < 0:
            raise ValueError("data must be a dict and version must be nonnegative")
        scope, encoded, now = key.digest(), _json(data), time.time()
        with self._connection() as conn:
            if expected_version == 0:
                cur = self._execute(conn, """INSERT INTO contest_sessions(scope, version, data, updated_at)
                    VALUES (?, 1, ?, ?) ON CONFLICT(scope) DO NOTHING""", (scope, encoded, now))
            else:
                cur = self._execute(conn, """UPDATE contest_sessions SET version = version + 1, data = ?, updated_at = ?
                    WHERE scope = ? AND version = ?""", (encoded, now, scope, expected_version))
            if cur.rowcount != 1:
                raise VersionConflict("session changed concurrently")
        return expected_version + 1

    def claim_event(self, key: SessionKey, event_id: str, payload: Any) -> tuple[bool, EventRecord]:
        """Claim a webhook once. Existing events return their current record."""
        if not event_id:
            raise ValueError("event_id is required")
        scope, fingerprint = key.digest(), _digest([_json(payload)])
        with self._connection() as conn:
            cur = self._execute(conn, """INSERT INTO contest_events
                (scope, event_id, payload_hash, status, updated_at) VALUES (?, ?, ?, 'processing', ?)
                ON CONFLICT(scope, event_id) DO NOTHING""", (scope, event_id, fingerprint, time.time()))
            created = cur.rowcount == 1
            row = self._execute(conn, """SELECT payload_hash, status, response, delivered FROM contest_events
                WHERE scope = ? AND event_id = ?""", (scope, event_id)).fetchone()
            if row[0] != fingerprint:
                raise StateConflict("event ID reused with a different payload")
        return created, EventRecord(row[1], None if row[2] is None else json.loads(row[2]), bool(row[3]))

    def complete_event(self, key: SessionKey, event_id: str, response: Any) -> None:
        """Save a response as pending delivery before attempting the callback."""
        scope, encoded = key.digest(), _json(response)
        with self._connection() as conn:
            cur = self._execute(conn, """UPDATE contest_events SET status = 'completed', response = ?, updated_at = ?
                WHERE scope = ? AND event_id = ? AND status = 'processing'""", (encoded, time.time(), scope, event_id))
            if cur.rowcount != 1:
                row = self._execute(conn, "SELECT status, response FROM contest_events WHERE scope = ? AND event_id = ?", (scope, event_id)).fetchone()
                if row is None or row[0] != "completed" or row[1] != encoded:
                    raise StateConflict("event is missing or already has another response")

    def mark_delivered(self, key: SessionKey, event_id: str) -> None:
        with self._connection() as conn:
            cur = self._execute(conn, """UPDATE contest_events SET delivered = 1, updated_at = ?
                WHERE scope = ? AND event_id = ? AND status = 'completed'""", (time.time(), key.digest(), event_id))
            if cur.rowcount != 1:
                raise StateConflict("cannot deliver an incomplete event")

    def get_action(self, key: SessionKey, action_key: str) -> ActionRecord | None:
        """Read a previously reserved action, preserving its original request."""
        if not action_key:
            raise ValueError("action_key is required")
        with self._connection() as conn:
            row = self._execute(conn, "SELECT request, status, result FROM contest_actions WHERE scope = ? AND action_key = ?", (key.digest(), action_key)).fetchone()
        if row is None:
            return None
        return ActionRecord(row[1], json.loads(row[0]), None if row[2] is None else json.loads(row[2]))

    def reserve_action(self, key: SessionKey, action_key: str, request: Any) -> tuple[bool, ActionRecord]:
        """Reserve a logical business action, preserving the exact request body."""
        if not action_key:
            raise ValueError("action_key is required")
        scope, encoded = key.digest(), _json(request)
        with self._connection() as conn:
            cur = self._execute(conn, """INSERT INTO contest_actions
                (scope, action_key, request, status, updated_at) VALUES (?, ?, ?, 'pending', ?)
                ON CONFLICT(scope, action_key) DO NOTHING""", (scope, action_key, encoded, time.time()))
            created = cur.rowcount == 1
            row = self._execute(conn, "SELECT request, status, result FROM contest_actions WHERE scope = ? AND action_key = ?", (scope, action_key)).fetchone()
            if row[0] != encoded:
                raise StateConflict("action ID reused with a different request")
        return created, ActionRecord(row[1], json.loads(row[0]), None if row[2] is None else json.loads(row[2]))

    def release_unexecuted_action(self, key: SessionKey, action_key: str) -> None:
        """Release a pending action proven not to have reached the side effect."""
        if not action_key:
            raise ValueError("action_key is required")
        with self._connection() as conn:
            cur = self._execute(conn, """DELETE FROM contest_actions
                WHERE scope = ? AND action_key = ? AND status = 'pending'""",
                (key.digest(), action_key))
            if cur.rowcount != 1:
                raise StateConflict("cannot release a missing or completed action")

    def complete_action(self, key: SessionKey, action_key: str, result: Any) -> None:
        scope, encoded = key.digest(), _json(result)
        with self._connection() as conn:
            cur = self._execute(conn, """UPDATE contest_actions SET status = 'completed', result = ?, updated_at = ?
                WHERE scope = ? AND action_key = ? AND status = 'pending'""", (encoded, time.time(), scope, action_key))
            if cur.rowcount != 1:
                row = self._execute(conn, "SELECT status, result FROM contest_actions WHERE scope = ? AND action_key = ?", (scope, action_key)).fetchone()
                if row is None or row[0] != "completed" or row[1] != encoded:
                    raise StateConflict("action is missing or already has another result")
