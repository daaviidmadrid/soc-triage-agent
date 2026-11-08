"""Managed scheduler for the app's existing runners; no analysis or containment pipeline here.

Jobs and budget live in SQLite. One scheduler processes priority work, while manual starts
use the same atomic claim. Graceful shutdown drains runs; crash recovery requeues claimed jobs.
"""
import csv
import hashlib
import json
import os
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

from src.agent.batch import MAX_CALLS_PER_RUN, MAX_FAILURES_IN_A_ROW, PACE_SECONDS, _calls_used, _out_of_quota
from src.agent.llm import LLMQuotaExhausted, attempt_guard
from src.app.store import now_iso
from src.policy.severity import CRITICALITIES, LEVELS, resolve_criticality
from src.tools.alert_fields import normalise_alert


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False, default=str).encode()).hexdigest()


@dataclass
class Config:
    require_start: bool = True
    auto_triage: bool = True
    auto_investigate: bool = True
    auto_close: bool = False
    max_calls: int = MAX_CALLS_PER_RUN
    max_failures: int = MAX_FAILURES_IN_A_ROW
    pace_seconds: float = PACE_SECONDS
    sample_rate: float = .05

    @classmethod
    def from_env(cls):
        return cls(auto_triage=os.getenv("AUTO_TRIAGE", "1") == "1",
                   auto_investigate=os.getenv("AUTO_INVESTIGATE", "1") == "1",
                   auto_close=os.getenv("AUTO_CLOSE_LOW_RISK", "0") == "1",
                   max_calls=max(0, int(os.getenv("MAX_CALLS_PER_RUN", MAX_CALLS_PER_RUN))),
                   max_failures=max(1, int(os.getenv("MAX_FAILURES_IN_A_ROW", MAX_FAILURES_IN_A_ROW))),
                   pace_seconds=max(0, float(os.getenv("LLM_PACE_SECONDS", PACE_SECONDS))),
                   sample_rate=min(1, max(0, float(os.getenv("AUTO_CLOSE_REVIEW_SAMPLE", ".05")))))


class Priorities:
    """Reuse the severity module's criticality selection, with local inventory (no new queries)."""
    def __init__(self):
        root = Path(__file__).resolve().parents[2] / "data" / "02_inventario"
        def read(name):
            try:
                with (root / name).open(encoding="utf-8") as file:
                    return list(csv.DictReader(file))
            except OSError:
                return []
        self.assets, self.users = read("activos.csv"), read("usuarios.csv")

    def __call__(self, alert, ticket=None):
        alert = normalise_alert(alert)[0]
        entities = alert.get("entities") or {}
        names = {str(u.get("upn", "")).lower() for u in entities.get("users", []) if isinstance(u, dict)}
        context = {"entities": entities, "assets": self.assets, "users": [u for u in self.users if u.get("upn", "").lower() in names]}
        crit, _ = resolve_criticality(alert, context)
        sev = (ticket or {}).get("severity") or alert.get("severity")
        return (LEVELS.index(sev) if sev in LEVELS else 2) * 10 + (CRITICALITIES.index(crit) if crit in CRITICALITIES else 1)


def auto_close_eligible(ticket, *, correlation_current, incident_escalates):
    """Fail closed. Only the existing deterministic R1/R2 checks can justify disposition."""
    flags, checks, rule = ticket.get("policy_flags"), ticket.get("safety_checks"), ticket.get("closed_by_rule")
    mandatory = ("confirmed_malicious_execution", "credential_theft", "persistence", "personal_data_exposure", "economic_fraud")
    required = ("citations_valid", "authorisation_valid", "evidence_complete", "not_ot", "injection_review_clear", "deterministic_eligible")
    return bool(
        correlation_current and not incident_escalates
        and (ticket.get("escalation") or {}).get("escalate") is False
        and ticket.get("severity") in ("informational", "low")
        and ticket.get("verdict") in ("false_positive", "benign_true_positive", "true_positive")
        and ticket.get("analysis_origin") == "deterministic"
        and isinstance(rule, dict) and rule.get("rule_id") in ("R1", "R2") and rule.get("event_ids")
        and rule.get("conditions") and ticket.get("evidence") and not ticket.get("injection_flags")
        and isinstance(flags, dict) and all(flags.get(k) is False for k in mandatory)
        and isinstance(checks, dict) and all(checks.get(k) is True for k in required)
    )


class Automation:
    def __init__(self, store, config, process, maintain):
        self.store, self.config = store, config
        self.process, self.maintain = process, maintain
        self.stop_event, self.wake = threading.Event(), threading.Event()
        self.thread = None
        self._threads, self._lock = set(), threading.RLock()
        self._call_lock = threading.Lock()
        self._active = 0
        self._default_budget = {"epoch": uuid.uuid4().hex, "started_at": now_iso(), "used": 0, "failures": 0, "blocked": None, "last_attempt": 0}
        self.store.edit_operation("budget", lambda value: value, self._default_budget)

    def status(self):
        jobs = self.store.jobs()
        budget = self.store.operation("budget")
        last_error = budget.get("last_error")
        if not last_error and budget.get("failures"):
            for job in sorted(jobs, key=lambda j: j["id"], reverse=True):
                errors = [e for e in self.store.events_after(job["run_id"]) if e.get("type") == "error"] if job.get("run_id") else []
                if errors:
                    last_error = {"tool": errors[0].get("tool"), "kind": (errors[0].get("args") or {}).get("kind"), "message": errors[0].get("summary"), "run_id": job["run_id"]}
                    break
        closed = [d for r in self.store.list_tickets() for d in [self.store.disposition(r["ticket_id"]) ] if d and d["origin"] == "automation" and d["state"] == "closed"]
        active = self.store.operation("flow_active", not self.config.require_start)
        waiting = sum(j["status"] == "staged" for j in jobs)
        pending = sum(j["status"] == "pending" for j in jobs)
        running = sum(j["status"] == "running" for j in jobs)
        latest_jobs = {}
        for job in jobs:
            key = (job["kind"], job["subject"])
            if job["id"] > latest_jobs.get(key, {}).get("id", 0):
                latest_jobs[key] = job
        retryable = sum(j["status"] == "failed" for j in latest_jobs.values())
        reconciling = self.config.require_start and active and self.store.operation("flow_reconciled") != list(self.store.work_revision())
        state = "ready" if not active or (waiting and not pending and not running) else "running" if pending or running or reconciling else "finished"
        return {"flow": {"state": state, "active": active, "ready": waiting, "pending": pending, "running": running, "retryable": retryable},
                "last_error": last_error,
                "auto_triage": self.config.auto_triage, "auto_investigate": self.config.auto_investigate,
                "auto_close_low_risk": self.config.auto_close, "sample_rate": self.config.sample_rate,
                "paused": self.store.operation("paused", False), "budget": {**budget, "limit": self.config.max_calls},
                "jobs": jobs, "reason": self.blocked(), "audit": self.store.audits(30),
                "containment": self.store.containment_counts(),
                "closures_by_rule": {r: sum(d.get("rule") == r for d in closed) for r in ("R1", "R2")},
                "review_sample": [d for d in closed if d.get("sampled_for_review")]}

    def blocked(self):
        budget = self.store.operation("budget")
        if budget.get("blocked"):
            return budget["blocked"]
        if budget["used"] >= self.config.max_calls:
            return "Presupuesto de llamadas consumido. Inicia deliberadamente un nuevo presupuesto."
        return None

    def block(self, reason):
        self.store.edit_operation("budget", lambda b: {**b, "blocked": b.get("blocked") or reason}, self._default_budget)

    def control(self, action):
        with self._lock:
            if action == "reset_budget":
                if self._active:
                    raise ValueError("Espera a que terminen las ejecuciones antes de reiniciar el presupuesto.")
                self.store.set_operation("budget", {**self._default_budget, "epoch": uuid.uuid4().hex, "started_at": now_iso()})
            else:
                self.store.set_operation("paused", action == "pause")
            self.store.audit("human", action, result="recorded")
        self.wake.set()

    def before_attempt(self):
        # Serialise pacing and reserve durably *before* sending, so a crash cannot refund calls.
        with self._call_lock:
            reason = self.blocked()
            if reason:
                self.block(reason)
                raise LLMQuotaExhausted(reason, attempts=0)
            budget = self.store.operation("budget")
            delay = self.config.pace_seconds - (time.time() - budget.get("last_attempt", 0))
            if delay > 0:
                time.sleep(delay)
            def reserve(b):
                if b.get("blocked") or b["used"] >= self.config.max_calls:
                    raise LLMQuotaExhausted(b.get("blocked") or "Presupuesto consumido", attempts=0)
                return {**b, "used": b["used"] + 1, "last_attempt": time.time()}
            try:
                self.store.edit_operation("budget", reserve, self._default_budget)
            except LLMQuotaExhausted as error:
                self.block(str(error))
                raise

    @contextmanager
    def execution(self, run_id, real):
        with self._lock:
            self._active += 1
        guarded = 0
        def guard():
            nonlocal guarded
            self.before_attempt()
            guarded += 1
        try:
            with attempt_guard(guard if real else None):
                yield
        finally:
            events = self.store.events_after(run_id)
            shaped = [SimpleNamespace(type=e.get("type"), tool=e.get("tool"), args=e.get("args") or {}) for e in events]
            # Injected runners may emit attempts without using complete(); never double count real calls.
            extra = max(0, _calls_used(shaped) - guarded) if real else 0
            quota = real and _out_of_quota(shaped)
            failed = any(e.get("type") == "error" for e in events)
            failed = failed or (self.store.get_run(run_id) or {}).get("status") == "failed"
            errors = [e for e in events if e.get("type") == "error"]
            last_error = {"tool": errors[0].get("tool"), "kind": (errors[0].get("args") or {}).get("kind"), "message": errors[0].get("summary"), "run_id": run_id} if errors else None
            def finish(b):
                failures = (b["failures"] + 1 if failed else 0) if real else b["failures"]
                reason = b.get("blocked")
                if quota:
                    reason = reason or "Cuota del proveedor agotada. Reanudar no repone la cuota."
                if real and failures >= self.config.max_failures:
                    reason = reason or "Límite de fallos consecutivos alcanzado."
                if b["used"] + extra >= self.config.max_calls:
                    reason = reason or "Presupuesto de llamadas consumido."
                return {**b, "used": b["used"] + extra, "failures": failures, "blocked": reason,
                        "last_error": last_error if failed else None}
            budget = self.store.edit_operation("budget", finish, self._default_budget)
            self.store.finish_jobs(run_id, "pending" if failed and budget["blocked"] else "failed" if failed else "done", budget["blocked"] or ("Falló la ejecución; requiere reintento explícito" if failed else "Análisis terminado"))
            job = next((j for j in self.store.jobs() if j["run_id"] == run_id), None)
            self.store.audit(job["origin"] if job else "human", "execution", run_id=run_id, result="failed" if failed else "done")
            with self._lock:
                self._active -= 1
            self.wake.set()

    def launch(self, fn, *args):
        with self._lock:
            if self.stop_event.is_set():
                raise ValueError("El servidor se está deteniendo.")
            self._active += 1
        def task():
            try:
                fn(*args)
            finally:
                with self._lock:
                    self._active -= 1
                    self._threads.discard(threading.current_thread())
        thread = threading.Thread(target=task, name=str(args[0]), daemon=False)
        with self._lock:
            self._threads.add(thread)
        thread.start()

    def start(self):
        self.store.recover_jobs()
        self.stop_event.clear()
        self.thread = threading.Thread(target=self.loop, name="soc-worker", daemon=False)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        self.wake.set()
        if self.thread:
            self.thread.join()
        for thread in list(self._threads):
            thread.join()

    def loop(self):
        last_maintenance = 0
        while not self.stop_event.is_set():
            try:
                paused = self.store.operation("paused", False)
                active = self.store.operation("flow_active", not self.config.require_start)
                if not paused and active:
                    # Coalesce quick completions; a quiet queue is reconciled immediately.
                    pending = self.store.jobs("pending")
                    triages = [j for j in pending if j["kind"] == "triage"]
                    staged_only = not pending and any(j["status"] == "staged" for j in self.store.jobs())
                    if not staged_only and (not triages or time.monotonic() - last_maintenance >= 2):
                        self.maintain()
                        last_maintenance = time.monotonic()
                    if not self.blocked():
                        eligible = [j for j in self.store.jobs("pending") if not self.store.active_run(j["subject"]) and ((j["kind"] == "triage" and self.config.auto_triage) or (j["kind"] == "report" and self.config.auto_investigate))]
                        if self.config.require_start:
                            eligible.sort(key=lambda j: j["kind"] != "triage")  # Complete the displayed alert queue before level 3.
                        if any(self.process(job) for job in eligible):
                            continue
            except Exception as error:
                # Never spin on an internal error. Operator sees the type, without raw data/secrets.
                self.block(f"Worker detenido ({type(error).__name__}). Revisa el registro operativo.")
                self.store.set_operation("paused", True)
                self.store.audit("worker", "scheduler_error", result=type(error).__name__)
            self.wake.wait(.25)
            self.wake.clear()
