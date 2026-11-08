"""Saves alerts, triage and investigation runs, trace events, tickets, reports and decisions in SQLite.

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
CREATE TABLE IF NOT EXISTS proposals (
    proposal_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    ticket_id TEXT NOT NULL,
    data TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS proposals_by_run ON proposals(run_id);
CREATE TABLE IF NOT EXISTS reports (
    run_id TEXT PRIMARY KEY,
    report_key TEXT NOT NULL,
    data TEXT NOT NULL,
    saved_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS reports_by_key ON reports(report_key);
CREATE TABLE IF NOT EXISTS correlations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    data TEXT NOT NULL,
    built_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS operations (key TEXT PRIMARY KEY, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, subject TEXT NOT NULL,
    revision TEXT NOT NULL, priority INTEGER NOT NULL, origin TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending', queued_at TEXT NOT NULL, started_at TEXT,
    finished_at TEXT, run_id TEXT, reason TEXT NOT NULL DEFAULT '',
    UNIQUE(kind, subject, revision)
);
CREATE TABLE IF NOT EXISTS dispositions (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ticket_id TEXT NOT NULL, run_id TEXT NOT NULL,
    revision TEXT NOT NULL, data TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS operation_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT, data TEXT NOT NULL
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

    def add_alerts(self, alerts, origin, enqueue_priorities=None):
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
                if cursor.rowcount and enqueue_priorities is not None:
                    self._db.execute("INSERT OR IGNORE INTO jobs(kind, subject, revision, priority, origin, queued_at) VALUES ('triage', ?, 'import', ?, ?, ?)",
                                     (alert["alert_id"], enqueue_priorities[alert["alert_id"]], origin, at))
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

    def latest_event(self, run_id):
        row = self._one("SELECT data FROM events WHERE run_id=? ORDER BY seq DESC LIMIT 1", (run_id,))
        return {k: v for k, v in json.loads(row[0]).items() if k != "ticket"} if row else None

    def containment_counts(self):
        counts = {}
        for (data,) in self._all("SELECT data FROM proposals"):
            state = json.loads(data).get("status", "unknown")
            counts[state] = counts.get(state, 0) + 1
        return counts

    def work_revision(self):
        """Cheap change marker for coalescing maintenance, including completed manual runs."""
        return self._one("SELECT (SELECT COUNT(*) FROM alerts), (SELECT COALESCE(MAX(rowid),0) FROM tickets), "
                         "(SELECT COALESCE(MAX(rowid),0) FROM runs), (SELECT COUNT(*) FROM runs WHERE status='running'), "
                         "(SELECT COUNT(*) FROM runs WHERE status='done'), (SELECT COALESCE(MAX(id),0) FROM jobs), "
                         "(SELECT COUNT(*) FROM jobs WHERE status='running'), (SELECT COUNT(*) FROM jobs WHERE status='pending')")

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

    def completed_tickets(self):
        rows = self._all("SELECT t.run_id,t.ticket_id,t.alert_id,t.mode,t.data,t.saved_at FROM tickets t "
                         "WHERE t.rowid IN (SELECT MAX(t2.rowid) FROM tickets t2 JOIN runs r ON r.run_id=t2.run_id "
                         "WHERE r.status='done' GROUP BY t2.alert_id)")
        return [self._ticket_row(row) for row in rows]

    def completed_ticket_for_alert(self, alert_id):
        return self._ticket_row(self._one("SELECT t.run_id,t.ticket_id,t.alert_id,t.mode,t.data,t.saved_at FROM tickets t "
                                         "JOIN runs r ON r.run_id=t.run_id WHERE t.alert_id=? AND r.status='done' ORDER BY t.rowid DESC LIMIT 1", (alert_id,)))

    # Grouping into incidents (level 2). Each build is kept whole, reasons included.

    def save_correlation(self, result):
        built_at = now_iso()
        self._write("INSERT INTO correlations (data, built_at) VALUES (?, ?)", (_dumps(result), built_at))
        return built_at

    def latest_correlation(self):
        row = self._one("SELECT data, built_at FROM correlations ORDER BY id DESC LIMIT 1")
        return {**json.loads(row[0]), "built_at": row[1]} if row else None

    # Containment proposals (level 4): their approvals, refusals and results.

    def save_proposal(self, proposal):
        self._write(
            "INSERT OR REPLACE INTO proposals (proposal_id, run_id, ticket_id, data, updated_at) VALUES (?, ?, ?, ?, ?)",
            (proposal["proposal_id"], proposal["run_id"], proposal["ticket_id"], _dumps(proposal), now_iso()),
        )

    def get_proposal(self, proposal_id):
        row = self._one("SELECT data FROM proposals WHERE proposal_id = ?", (proposal_id,))
        return json.loads(row[0]) if row else None

    def proposals_for_run(self, run_id):
        rows = self._all("SELECT data FROM proposals WHERE run_id = ? ORDER BY rowid", (run_id,))
        return {item["proposal_id"]: item for item in (json.loads(row[0]) for row in rows)}
    # Incident reports (level 3). The key is the incident or ticket investigated; each run keeps its own version.

    def save_report(self, report, run_id, key):
        self._write(
            "INSERT OR REPLACE INTO reports (run_id, report_key, data, saved_at) VALUES (?, ?, ?, ?)",
            (run_id, key, _dumps(report), now_iso()),
        )

    def _report_row(self, row):
        if not row:
            return None
        run_id, key, data, saved_at = row
        return {"run_id": run_id, "key": key, "report": json.loads(data), "saved_at": saved_at}

    def get_report(self, key):
        """The newest report for an incident or ticket."""
        return self._report_row(self._one(
            "SELECT run_id, report_key, data, saved_at FROM reports WHERE report_key = ? ORDER BY rowid DESC LIMIT 1", (key,)
        ))

    def latest_reports(self):
        """{key: {"run_id", "saved_at", "fallback"}} for the newest report of each key, without the reports themselves."""
        rows = self._all(
            "SELECT run_id, report_key, data, saved_at FROM reports WHERE rowid IN (SELECT MAX(rowid) FROM reports GROUP BY report_key)"
        )
        return {key: {"run_id": run_id, "saved_at": saved_at, "fallback": bool(json.loads(data).get("fallback"))}
                for run_id, key, data, saved_at in rows}

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

    # Durable work and operational state. All claims share the same SQLite transaction,
    # including manual starts. BEGIN IMMEDIATE also serialises separate connections.

    def operation(self, key, default=None):
        row = self._one("SELECT data FROM operations WHERE key = ?", (key,))
        return json.loads(row[0]) if row else default

    def set_operation(self, key, value):
        self._write("INSERT OR REPLACE INTO operations VALUES (?, ?)", (key, _dumps(value)))

    def edit_operation(self, key, edit, default):
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                row = self._db.execute("SELECT data FROM operations WHERE key=?", (key,)).fetchone()
                value = edit(json.loads(row[0]) if row else default.copy())
                self._db.execute("INSERT OR REPLACE INTO operations VALUES (?, ?)", (key, _dumps(value)))
                self._db.commit()
                return value
            except Exception:
                self._db.rollback()
                raise

    def audit(self, origin, reason, **result):
        self._write("INSERT INTO operation_audit(data) VALUES (?)", (_dumps({"at": now_iso(), "origin": origin, "reason": reason, **result}),))

    def audits(self, limit=100):
        return [json.loads(r[0]) for r in self._all("SELECT data FROM operation_audit ORDER BY id DESC LIMIT ?", (limit,))]

    def enqueue(self, kind, subject, revision, priority, origin):
        cursor = self._write("INSERT OR IGNORE INTO jobs(kind, subject, revision, priority, origin, queued_at) VALUES (?, ?, ?, ?, ?, ?)",
                             (kind, subject, revision, priority, origin, now_iso()))
        return bool(cursor.rowcount)

    def jobs(self, status=None):
        with self._lock:
            cursor = self._db.execute("SELECT * FROM jobs" + (" WHERE status = ?" if status else "") + " ORDER BY priority DESC, id", (status,) if status else ())
            fields = [d[0] for d in cursor.description]
            return [dict(zip(fields, row)) for row in cursor.fetchall()]

    def claim_run(self, run_id, subject, mode, job_id=None, enroll_priority=None):
        """Returns (run, claimed). A manual claim also consumes an existing pending job."""
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                active = self._db.execute(f"SELECT {', '.join(RUN_FIELDS)} FROM runs WHERE alert_id=? AND status='running' LIMIT 1", (subject,)).fetchone()
                if active:
                    self._db.commit()
                    return dict(zip(RUN_FIELDS, active)), False
                if job_id is not None:
                    job = self._db.execute("SELECT status FROM jobs WHERE id=?", (job_id,)).fetchone()
                    if not job or job[0] != "pending":
                        self._db.commit()
                        return None, False
                at = now_iso()
                self._db.execute("INSERT INTO runs(run_id, alert_id, mode, status, started_at) VALUES (?, ?, ?, 'running', ?)", (run_id, subject, mode, at))
                if job_id is None:
                    updated = self._db.execute("UPDATE jobs SET status='running', run_id=?, started_at=?, finished_at=NULL, reason='Reclamado' WHERE subject=? AND status='pending'", (run_id, at, subject))
                    if not updated.rowcount and enroll_priority is not None:
                        self._db.execute("INSERT INTO jobs(kind, subject, revision, priority, origin, status, queued_at, started_at, run_id) VALUES ('triage', ?, ?, ?, 'human', 'running', ?, ?, ?)",
                                         (subject, 'manual:' + run_id, enroll_priority, at, at, run_id))
                else:
                    self._db.execute("UPDATE jobs SET status='running', run_id=?, started_at=?, finished_at=NULL, reason='Reclamado' WHERE id=?", (run_id, at, job_id))
                self._db.commit()
            except Exception:
                self._db.rollback()
                raise
        return self.get_run(run_id), True

    def finish_jobs(self, run_id, status, reason=""):
        self._write("UPDATE jobs SET status=?, reason=?, finished_at=? WHERE run_id=? AND status='running'", (status, reason, now_iso(), run_id))

    def cancel_job(self, job_id, reason):
        self._write("UPDATE jobs SET status='superseded', reason=?, finished_at=? WHERE id=? AND status='pending'", (reason, now_iso(), job_id))

    def recover_jobs(self):
        self._write("UPDATE jobs SET status='pending', reason='Recuperado tras reinicio', run_id=NULL WHERE status='running'")

    def disposition_history(self, ticket_id):
        return [json.loads(r[0]) for r in self._all("SELECT data FROM dispositions WHERE ticket_id=? ORDER BY id DESC", (ticket_id,))]

    def disposition(self, ticket_id):
        history = self.disposition_history(ticket_id)
        return history[0] if history else None

    def add_disposition(self, ticket_id, run_id, revision, state, origin, reason, **details):
        value = {"ticket_id": ticket_id, "run_id": run_id, "revision": revision, "state": state,
                 "origin": origin, "reason": reason, "at": now_iso(), **details}
        self._write("INSERT INTO dispositions(ticket_id, run_id, revision, data) VALUES (?, ?, ?, ?)", (ticket_id, run_id, revision, _dumps(value)))
        return value
