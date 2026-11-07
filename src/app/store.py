"""Saves alerts, triage runs, trace events, tickets and decisions in SQLite.

One connection guarded by a lock, so background runs and requests can share it,
and so tests can use ":memory:".
"""
import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY,
    origin TEXT NOT NULL,
    data TEXT NOT NULL,
    added_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    alert_id TEXT NOT NULL,
    mode TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    duration_seconds REAL,
    ticket_id TEXT,
    error TEXT
);
CREATE INDEX IF NOT EXISTS runs_by_alert ON runs(alert_id);
CREATE TABLE IF NOT EXISTS events (
    run_id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    data TEXT NOT NULL,
    PRIMARY KEY (run_id, seq)
);
CREATE TABLE IF NOT EXISTS tickets (
    run_id TEXT PRIMARY KEY,
    ticket_id TEXT NOT NULL,
    alert_id TEXT NOT NULL,
    mode TEXT NOT NULL,
    data TEXT NOT NULL,
    saved_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS tickets_by_id ON tickets(ticket_id);
CREATE TABLE IF NOT EXISTS decisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    analyst TEXT NOT NULL,
    decision TEXT NOT NULL,
    outcome TEXT NOT NULL,
    reason TEXT NOT NULL,
    decided_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS decisions_by_ticket ON decisions(ticket_id);
CREATE TABLE IF NOT EXISTS correlations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    data TEXT NOT NULL,
    built_at TEXT NOT NULL
);
"""

RUN_FIELDS = ("run_id", "alert_id", "mode", "status", "started_at", "finished_at", "duration_seconds", "ticket_id", "error")
DECISION_FIELDS = ("id", "ticket_id", "run_id", "analyst", "decision", "outcome", "reason", "decided_at")


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _dumps(value):
    return json.dumps(value, ensure_ascii=False)


class Store:
    def __init__(self, path):
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        self._lock = threading.Lock()
        with self._lock:
            self._db.executescript(SCHEMA)
            self._db.commit()

    def _all(self, sql, args=()):
        with self._lock:
            return self._db.execute(sql, args).fetchall()

    def _one(self, sql, args=()):
        with self._lock:
            return self._db.execute(sql, args).fetchone()

    def _write(self, sql, args=()):
        with self._lock:
            cursor = self._db.execute(sql, args)
            self._db.commit()
            return cursor

    # Alerts

    def add_alerts(self, alerts, origin):
        """Adds alerts that aren't stored yet. Returns (added_ids, skipped_ids). Alerts are stored unchanged."""
        added, skipped = [], []
        at = now_iso()
        with self._lock:
            for alert in alerts:
                cursor = self._db.execute(
                    "INSERT OR IGNORE INTO alerts (alert_id, origin, data, added_at) VALUES (?, ?, ?, ?)",
                    (alert["alert_id"], origin, _dumps(alert), at),
                )
                (added if cursor.rowcount else skipped).append(alert["alert_id"])
            self._db.commit()
        return added, skipped

    def list_alerts(self):
        rows = self._all("SELECT data, origin FROM alerts ORDER BY rowid")
        return [{"alert": json.loads(data), "origin": origin} for data, origin in rows]

    def get_alert(self, alert_id):
        row = self._one("SELECT data, origin FROM alerts WHERE alert_id = ?", (alert_id,))
        return {"alert": json.loads(row[0]), "origin": row[1]} if row else None

    # Runs

    def create_run(self, run_id, alert_id, mode):
        self._write(
            "INSERT INTO runs (run_id, alert_id, mode, status, started_at) VALUES (?, ?, ?, 'running', ?)",
            (run_id, alert_id, mode, now_iso()),
        )
        return self.get_run(run_id)

    def finish_run(self, run_id, status, duration_seconds, ticket_id=None, error=None):
        self._write(
            "UPDATE runs SET status = ?, finished_at = ?, duration_seconds = ?, ticket_id = ?, error = ? WHERE run_id = ?",
            (status, now_iso(), duration_seconds, ticket_id, error, run_id),
        )

    def mark_interrupted_runs(self):
        """Runs left 'running' by a previous server process can never finish."""
        self._write(
            "UPDATE runs SET status = 'failed', finished_at = ?, error = ? WHERE status = 'running'",
            (now_iso(), "El servidor se reinició antes de que terminara el triaje."),
        )

    def get_run(self, run_id):
        row = self._one(f"SELECT {', '.join(RUN_FIELDS)} FROM runs WHERE run_id = ?", (run_id,))
        return dict(zip(RUN_FIELDS, row)) if row else None

    def runs_for_alert(self, alert_id, limit=10):
        rows = self._all(
            f"SELECT {', '.join(RUN_FIELDS)} FROM runs WHERE alert_id = ? ORDER BY rowid DESC LIMIT ?",
            (alert_id, limit),
        )
        return [dict(zip(RUN_FIELDS, row)) for row in rows]

    def active_run(self, alert_id):
        row = self._one(
            f"SELECT {', '.join(RUN_FIELDS)} FROM runs WHERE alert_id = ? AND status = 'running' ORDER BY rowid DESC LIMIT 1",
            (alert_id,),
        )
        return dict(zip(RUN_FIELDS, row)) if row else None

    def latest_runs(self):
        """The newest run of each alert, keyed by alert_id."""
        rows = self._all(
            f"SELECT {', '.join(RUN_FIELDS)} FROM runs WHERE rowid IN (SELECT MAX(rowid) FROM runs GROUP BY alert_id)"
        )
        return {row[1]: dict(zip(RUN_FIELDS, row)) for row in rows}

    # Events

    def add_event(self, run_id, event):
        """Stores the event with the next seq of its run, and returns it."""
        with self._lock:
            (last,) = self._db.execute("SELECT COALESCE(MAX(seq), 0) FROM events WHERE run_id = ?", (run_id,)).fetchone()
            event = {**event, "run_id": run_id, "seq": last + 1}
            self._db.execute("INSERT INTO events (run_id, seq, data) VALUES (?, ?, ?)", (run_id, last + 1, _dumps(event)))
            self._db.commit()
        return event

    def events_after(self, run_id, after_seq=0):
        rows = self._all("SELECT data FROM events WHERE run_id = ? AND seq > ? ORDER BY seq", (run_id, after_seq))
        return [json.loads(data) for (data,) in rows]

    # Tickets

    def save_ticket(self, ticket, run_id, alert_id, mode):
        self._write(
            "INSERT OR REPLACE INTO tickets (run_id, ticket_id, alert_id, mode, data, saved_at) VALUES (?, ?, ?, ?, ?, ?)",
            (run_id, str(ticket["ticket_id"]), alert_id, mode, _dumps(ticket), now_iso()),
        )

    def _ticket_row(self, row):
        if not row:
            return None
        run_id, ticket_id, alert_id, mode, data, saved_at = row
        return {"run_id": run_id, "ticket_id": ticket_id, "alert_id": alert_id, "mode": mode, "ticket": json.loads(data), "saved_at": saved_at}

    def get_ticket(self, ticket_id):
        """The newest version of a ticket. Triaging an alert again makes a new version."""
        return self._ticket_row(self._one(
            "SELECT run_id, ticket_id, alert_id, mode, data, saved_at FROM tickets WHERE ticket_id = ? ORDER BY rowid DESC LIMIT 1",
            (ticket_id,),
        ))

    def ticket_for_run(self, run_id):
        return self._ticket_row(self._one(
            "SELECT run_id, ticket_id, alert_id, mode, data, saved_at FROM tickets WHERE run_id = ?", (run_id,)
        ))

    def ticket_version(self, ticket_id, run_id):
        return self._ticket_row(self._one(
            "SELECT run_id, ticket_id, alert_id, mode, data, saved_at FROM tickets WHERE ticket_id = ? AND run_id = ?",
            (ticket_id, run_id),
        ))

    def list_tickets(self):
        rows = self._all(
            "SELECT run_id, ticket_id, alert_id, mode, data, saved_at FROM tickets "
            "WHERE rowid IN (SELECT MAX(rowid) FROM tickets GROUP BY ticket_id) ORDER BY rowid"
        )
        return [self._ticket_row(row) for row in rows]

    # Grouping into incidents (level 2). Each build is kept whole, reasons included.

    def save_correlation(self, result):
        built_at = now_iso()
        self._write("INSERT INTO correlations (data, built_at) VALUES (?, ?)", (_dumps(result), built_at))
        return built_at

    def latest_correlation(self):
        row = self._one("SELECT data, built_at FROM correlations ORDER BY id DESC LIMIT 1")
        return {**json.loads(row[0]), "built_at": row[1]} if row else None

    # Decisions

    def add_decision(self, ticket_id, run_id, analyst, decision, outcome, reason):
        cursor = self._write(
            "INSERT INTO decisions (ticket_id, run_id, analyst, decision, outcome, reason, decided_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (ticket_id, run_id, analyst, decision, outcome, reason, now_iso()),
        )
        row = self._one(f"SELECT {', '.join(DECISION_FIELDS)} FROM decisions WHERE id = ?", (cursor.lastrowid,))
        return dict(zip(DECISION_FIELDS, row))

    def decisions_for(self, ticket_id):
        rows = self._all(f"SELECT {', '.join(DECISION_FIELDS)} FROM decisions WHERE ticket_id = ? ORDER BY id DESC", (ticket_id,))
        return [dict(zip(DECISION_FIELDS, row)) for row in rows]

    def latest_decisions_by_run(self):
        """The newest decision on each ticket version, keyed by run_id."""
        rows = self._all(
            f"SELECT {', '.join(DECISION_FIELDS)} FROM decisions WHERE id IN (SELECT MAX(id) FROM decisions GROUP BY run_id)"
        )
        return {row[2]: dict(zip(DECISION_FIELDS, row)) for row in rows}
