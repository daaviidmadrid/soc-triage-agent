"""Runs levels 1 to 3 in the background, one thing at a time, in priority order. Level 4 is never touched here.

It only chooses what to do next and when. Triage, grouping and reports go through the same functions as the routes a
person clicks, passed in by src/app/main.py. Nothing here calls the LLM, reads alert text or decides anything about a
ticket, and no text from the data reaches the order: it uses the rule's severity field, the CMDB's criticality, the
deadline and the order alerts arrived, never an ID number.

step() does one unit of work and says what it did, so tests can drive it with no thread. Stopping or pausing takes
effect between units, so no alert is ever left half-processed.
"""
import os
import threading
import time
from collections import deque
from types import SimpleNamespace

from src.agent.batch import (
    MAX_CALLS_PER_RUN,
    MAX_FAILURES_IN_A_ROW,
    PACE_SECONDS,
    _calls_used,
    _out_of_quota,
    _should_save,
)
from src.agent.rules import RULES
from src.agent.triage import MAX_LLM_CALLS
from src.policy import sla as sla_policy
from src.policy.severity import (
    CRITICALITIES,
    DEFAULT_CRITICALITY,
    LEVELS,
    resolve_criticality,
)
from src.tools import api_client
from src.tools.alert_fields import fill_from_catalogue
from src.tools.context import _parse_entities

DEFAULT_MAX_CALLS_PER_MINUTE = 30
GROUP_EVERY_SECONDS = 30
IDLE_SECONDS = 1.0


def switch(name):
    """Environment switches default to off. Only the exact value 1 turns one on."""
    return os.environ.get(name, "0").strip() == "1"


def number(name, default, kind=float):
    try:
        value = kind(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default
    return value if value >= 0 else default


class Settings:
    def __init__(self):
        self.enabled = switch("AUTO_TRIAGE")
        self.investigate = switch("AUTO_INVESTIGATE")
        self.pace_seconds = number("AUTO_TRIAGE_PACE_SECONDS", PACE_SECONDS)
        self.max_calls_per_run = number("AUTO_TRIAGE_MAX_CALLS_PER_RUN", MAX_CALLS_PER_RUN, int)
        self.max_calls_per_minute = number("AUTO_TRIAGE_MAX_CALLS_PER_MINUTE", DEFAULT_MAX_CALLS_PER_MINUTE, int)
        self.group_every_seconds = number("AUTO_GROUP_SECONDS", GROUP_EVERY_SECONDS)
        self.max_failures = number("AUTO_TRIAGE_MAX_FAILURES", MAX_FAILURES_IN_A_ROW, int)


def alert_criticality(alert, lookup_asset=None, lookup_user=None, memo=None):
    """The asset's criticality through resolve_criticality, with only the CMDB and directory lookups it needs.
    If they fail the alert keeps the default: it still runs, just not ahead of its severity."""
    lookup_asset = lookup_asset or api_client.get_asset
    lookup_user = lookup_user or api_client.get_user
    memo = {} if memo is None else memo

    def cached(kind, lookup, key):
        if (kind, key) not in memo:
            memo[kind, key] = lookup(key)
        return memo[kind, key]

    try:
        entities, assets, users = [], {}, []
        for kind, value, _ in _parse_entities(alert):
            if kind in ("host", "ip"):
                entities.append({"type": kind, "value": value})
                asset = cached("asset", lookup_asset, value)
                if asset:
                    assets[asset["hostname"]] = asset
            elif kind == "user":
                user = cached("user", lookup_user, value)
                if user:
                    users.append(user)
                    workstation = user.get("workstation")
                    asset = cached("asset", lookup_asset, workstation) if workstation else None
                    if asset:
                        assets[asset["hostname"]] = asset
        return resolve_criticality(fill_from_catalogue(alert)[0], {"entities": entities, "assets": list(assets.values()), "users": users})[0]
    except Exception:
        return DEFAULT_CRITICALITY


def order_key(alert, criticality, deadline, position):
    """Rule severity, then criticality, then the earliest deadline. A lower severity never overtakes a higher one."""
    severity = sla_policy.rule_severity(alert)[0]
    return (-LEVELS.index(severity), -CRITICALITIES.index(criticality), deadline or "9999", position)


class Worker:
    """triage_one, try_rules, group, report_candidates and report_one are the app's own functions. See main.py."""

    def __init__(self, store, settings, *, triage_one, try_rules, group, report_candidates, report_one, tick=None, criticality=None,
                 clock=time.monotonic):
        self.store = store
        self.settings = settings
        self.triage_one = triage_one
        self.try_rules = try_rules
        self.group = group
        self.report_candidates = report_candidates
        self.report_one = report_one
        self.tick = tick or (lambda: None)
        self.criticality = criticality or alert_criticality
        self.clock = clock
        self._memo = {}
        self._criticalities = {}
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._thread = None
        self.state = "stopped"
        self.stop_reason = None
        self._reset_run()

    def _reset_run(self):
        self.calls_used = 0
        self.failures_in_a_row = 0
        self.failures_total = 0
        self.triaged = 0
        self.reports = 0
        self._window = deque()
        self._next_llm_at = 0.0
        self._rules_checked = set()
        self._tried = set()
        self._reports_tried = set()
        self._tickets_grouped = None
        self._last_group_at = None
        self.current = None

    # Controls. Only routes a person calls, and the server start with AUTO_TRIAGE=1, get here.

    def start(self, background=True):
        with self._lock:
            if not self.settings.enabled:
                return False
            if self.state == "paused":
                self.state = "running"
                self._audit("worker_resumed", "Una persona reanudó el trabajador.")
                self._wake.set()
                return True
            if self.state in ("running", "stopping"):
                return True
            self._reset_run()
            self.state, self.stop_reason = "running", None
            self._audit("worker_started", "Arranque del trabajador automático.")
            if background:
                self._thread = threading.Thread(target=self._loop, daemon=True, name="auto-triage")
                self._thread.start()
        return True

    def pause(self):
        with self._lock:
            if self.state == "running":
                self.state = "paused"
                self._audit("worker_paused", "Una persona pausó el trabajador. La alerta en curso termina.")
        return self.state

    def stop(self, reason="person"):
        with self._lock:
            if self.state in ("running", "paused"):
                self.state = "stopping" if self.current or self._thread else "stopped"
                self.stop_reason = reason
                self._wake.set()
                self._audit("worker_stop_requested", "Una persona detuvo el trabajador. La alerta en curso termina.")
        return self.state

    def join(self, timeout=None):
        thread = self._thread
        if thread and thread is not threading.current_thread():
            thread.join(timeout)

    def _audit(self, action, reason, data=None):
        self.store.add_audit("code", "src/app/worker.py", action, "worker", reason, data)

    def _halt(self, reason, text):
        self.state, self.stop_reason = "stopped", reason
        self._audit("worker_stopped", text, {"reason": reason, "llm_calls": self.calls_used, "failures_in_a_row": self.failures_in_a_row})
        return "stopped"

    # The queue, in order.

    def _crit(self, alert):
        alert_id = alert["alert_id"]
        if alert_id not in self._criticalities:
            self._criticalities[alert_id] = self.criticality(alert, memo=self._memo)
        return self._criticalities[alert_id]

    def pending(self):
        """Alerts with no ticket and no run in progress, best first, as (alert, needs_rules). A failed alert gets one
        more try per start of the worker. A person-started run is left alone, whatever it is."""
        runs = self.store.latest_runs()
        records = self.store.all_sla()
        items = []
        for position, row in enumerate(self.store.list_alerts()):
            alert = row["alert"]
            alert_id = alert["alert_id"]
            run = runs.get(alert_id)
            if alert_id in self._tried or (run and run["status"] != "failed"):
                continue
            deadline = (records.get(alert_id) or {}).get("deadline")
            items.append((order_key(alert, self._crit(alert), deadline, position), alert))
        return [alert for _, alert in sorted(items, key=lambda item: item[0])]

    def _can_call(self, now):
        """(ok, why not) for one more alert that may call the LLM, with room for its largest number of calls."""
        if self.calls_used + MAX_LLM_CALLS > self.settings.max_calls_per_run:
            return False, "budget"
        while self._window and now - self._window[0][0] >= 60:
            self._window.popleft()
        used = sum(calls for _, calls in self._window)
        if used and used + MAX_LLM_CALLS > self.settings.max_calls_per_minute:
            return False, "minute"
        return (True, None) if now >= self._next_llm_at else (False, "pace")

    def _count(self, run_id, now, failed):
        """What one finished run used and whether it failed, by the same tests as src/agent/batch.py."""
        events = [SimpleNamespace(**{"tool": None, "type": None, "args": {}, **event}) for event in self.store.events_after(run_id)]
        run = self.store.get_run(run_id) or {}
        real = run.get("mode") in ("real", "report")  # example runs replay files and call nothing; reports always call the LLM
        calls = _calls_used(events) if real else 0
        self.calls_used += calls
        if calls:
            self._window.append((now, calls))
        problem = failed or run.get("status") == "failed" or (real and not _should_save(events))
        if problem:
            self.failures_in_a_row += 1
            self.failures_total += 1
        else:
            self.failures_in_a_row = 0
        return real and _out_of_quota(events)

    def _after_run(self, run_id, now):
        out_of_quota = self._count(run_id, now, False)
        if out_of_quota:
            return self._halt("quota", "El LLM agotó su cuota: el resto de alertas sigue en la cola para una persona.")
        if self.failures_in_a_row >= self.settings.max_failures:
            return self._halt("failures", f"{self.failures_in_a_row} fallos seguidos: el resto de alertas sigue en la cola para una persona.")
        return None

    def _maybe_group(self, now):
        """Grouping uses no LLM. At most once every N seconds, and only if there are new tickets."""
        tickets = self.store.count_tickets()
        if tickets == 0 or tickets == self._tickets_grouped:
            return False
        if self._last_group_at is not None and now - self._last_group_at < self.settings.group_every_seconds:
            return False
        self._tickets_grouped, self._last_group_at = tickets, now
        try:
            self.group()
        except Exception as error:  # incidents stay as they were, and triage carries on
            self._audit("auto_group_failed", f"La agrupación falló ({type(error).__name__}). Sigue el triaje.")
        return True

    def step(self):
        """One unit of work. Returns what it did: stopped, paused, rules, triage, group, report, wait or idle."""
        with self._lock:
            if self.state == "stopping":
                self.state = "stopped"
                self._audit("worker_stopped", "Detenido por una persona, sin dejar ninguna alerta a medias.", {"reason": self.stop_reason, "llm_calls": self.calls_used})
                return "stopped"
            if self.state in ("stopped", "paused"):
                return self.state
        self.tick()
        now = self.clock()
        pending = self.pending()

        # Fixed rules first: they use no LLM, so no limit applies.
        for alert in pending:
            alert_id = alert["alert_id"]
            if alert_id not in self._rules_checked and fill_from_catalogue(alert)[0].get("rule_id") in RULES:
                self._rules_checked.add(alert_id)
                self.current = alert_id
                try:
                    if self.try_rules(alert):
                        self._tried.add(alert_id)
                        self.triaged += 1
                finally:
                    self.current = None
                return "rules"

        if self._maybe_group(now):
            return "group"

        candidates = self.report_candidates() if self.settings.investigate else []
        candidates = [c for c in candidates if c["key"] not in self._reports_tried]
        next_alert = pending[0] if pending else None
        report = candidates[0] if candidates else None
        # A report goes first only if it is of a higher severity than the next alert, whose triage has a deadline.
        report_first = report and (next_alert is None or LEVELS.index(report["severity"]) > LEVELS.index(sla_policy.rule_severity(next_alert)[0]))
        if not next_alert and not report:
            return "idle"

        ok, why = self._can_call(now)
        if why == "budget":
            return self._halt("budget", "Límite de llamadas al LLM de esta ejecución: el resto de alertas sigue en la cola para una persona.")
        if not ok:
            return "wait"
        self._next_llm_at = now + self.settings.pace_seconds

        if report_first:
            self._reports_tried.add(report["key"])
            self.current = report["key"]
            try:
                run_id = self.report_one(report["key"])
            finally:
                self.current = None
            if not run_id:
                return "idle"
            self.reports += 1
            return self._after_run(run_id, self.clock()) or "report"

        alert_id = next_alert["alert_id"]
        self._tried.add(alert_id)
        self.current = alert_id
        try:
            run_id = self.triage_one(next_alert)
        finally:
            self.current = None
        if not run_id:  # a person started this one meanwhile
            return "idle"
        self.triaged += 1
        return self._after_run(run_id, self.clock()) or "triage"

    def _loop(self):
        while True:
            try:
                did = self.step()
            except Exception as error:  # one bad step must not leave the worker looking alive
                with self._lock:
                    self._halt("error", f"Error interno del trabajador ({type(error).__name__}).")
                return
            if did == "stopped":
                return
            if did in ("wait", "idle", "paused"):
                self._wake.wait(IDLE_SECONDS)
                self._wake.clear()

    def view(self):
        return {
            "enabled": self.settings.enabled, "investigate": self.settings.investigate, "state": self.state, "stop_reason": self.stop_reason,
            "current": self.current, "llm_calls_used": self.calls_used, "llm_calls_limit": self.settings.max_calls_per_run,
            "llm_calls_per_minute": self.settings.max_calls_per_minute, "pace_seconds": self.settings.pace_seconds,
            "failures_in_a_row": self.failures_in_a_row, "failures_total": self.failures_total, "max_failures": self.settings.max_failures,
            "triaged": self.triaged, "reports": self.reports, "group_every_seconds": self.settings.group_every_seconds,
        }
