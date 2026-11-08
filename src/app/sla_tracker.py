"""Keeps each alert's SLA record and its in-app notifications. Plain code only.

Severities and deadlines come from the alert's severity field and the ticket's final severity, both worked out by code,
through src/policy/sla.py. No text from an alert, a log or a ticket reaches a record or a notification: their reasons are
fixed texts. This never sends anything outside the app. A person reads and acknowledges notifications in the console.
"""
import threading
from functools import wraps

from src.policy import sla as policy

SEVERITY_NAME = {"critical": "crítica", "high": "alta", "medium": "media", "low": "baja", "informational": "informativa"}


def is_fallback(ticket, events):
    """A ticket code wrote because the triage couldn't finish. It isn't a triage, so it doesn't stop the clock.
    The same test as isFallback in ui/src/ticket/runState.js."""
    evidence = ticket.get("evidence") if isinstance(ticket, dict) else None
    return (ticket.get("verdict") == "needs_more_info" and not evidence
            and any(isinstance(event, dict) and event.get("type") == "error" for event in events))


def _locked(method):
    """Each change reads a record, works on it and writes it back, from requests and the worker at once. Without the
    lock, a refresh could write back an old copy over the ticket that just stopped the clock."""
    @wraps(method)
    def wrapper(self, *args, **kwargs):
        with self._lock:
            return method(self, *args, **kwargs)
    return wrapper


class SlaTracker:
    def __init__(self, store, now):
        self.store = store
        self.now = now
        self._lock = threading.RLock()

    def _audit(self, action, alert_id, reason, data=None):
        self.store.add_audit("code", "src/policy/sla.py", action, alert_id, reason, data)

    def _notify(self, record, kind, reason):
        severity = record["severity"]
        for role in policy.TARGETS[severity]["notify"]:
            data = {"role": role, "severity": severity, "kind": kind, "ticket_id": record.get("ticket_id"), "mode": record.get("mode"),
                    "deadline": record.get("deadline"), "at": self.now(), "reason": reason}
            added = self.store.add_notification(f"{record['alert_id']}|{role}|{severity}|{kind}", record["alert_id"], data)
            if added:
                self._audit("notification_created", record["alert_id"], reason, {"role": role, "severity": severity, "kind": kind, "notification_id": added})

    def _new_record(self, alert_id, alert, started_at):
        severity, assumed = policy.rule_severity(alert)
        return {
            "alert_id": alert_id, "started_at": started_at, "rule_severity": severity, "severity_assumed": assumed,
            "severity": severity, "severity_source": "rule", "deadline_severity": severity,
            "target_seconds": policy.TARGETS[severity]["seconds"], "deadline": policy.deadline_for(started_at, severity),
            "stopped_at": None, "stopped_by": None, "status": "open", "breached_at": None,
            "ticket_id": None, "run_id": None, "mode": None, "changes": [], "escalation_confirmation": None,
        }

    @_locked
    def open_new(self):
        """A record for every alert that has none, from when it entered the store, with its tickets if it has any."""
        known = self.store.all_sla()
        entered = self.store.alert_entry_times()
        missing = [alert_id for alert_id in entered if alert_id not in known]
        for alert_id in missing:
            row = self.store.get_alert(alert_id)
            record = self._new_record(alert_id, row["alert"], entered[alert_id])
            self.store.save_sla(alert_id, record)
            self._audit("sla_started", alert_id, "El reloj empieza cuando la alerta entra en el sistema.",
                        {"started_at": record["started_at"], "deadline": record["deadline"], "severity": record["severity"]})
            self._notify(record, "severity", f"Severidad {SEVERITY_NAME[record['severity']]} según la regla (política, apartado 3).")
            ticket_row = self.store.latest_ticket_for_alert(alert_id)
            if ticket_row:  # a database from before SLA tracking
                self.on_ticket(alert_id, ticket_row["ticket"], ticket_row["run_id"], ticket_row["mode"], self.store.events_after(ticket_row["run_id"]), at=ticket_row["saved_at"])
        return len(missing)

    @_locked
    def on_ticket(self, alert_id, ticket, run_id, mode, events, at=None):
        """A ticket was created. Severity becomes the final one, a higher one recalculates the deadline from the same
        start, and a real triage stops the clock. A fallback ticket keeps it running: nothing was triaged."""
        record = self.store.get_sla(alert_id)
        if not record:
            self.open_new()
            record = self.store.get_sla(alert_id)
            if not record:
                return None
        at = at or self.now()
        record.update(ticket_id=ticket.get("ticket_id"), run_id=run_id, mode=mode)
        final = ticket.get("severity")
        if final in policy.TARGETS and final != record["severity"]:
            change = {"at": at, "from": record["severity"], "to": final, "deadline_before": record["deadline"]}
            record.update(severity=final, severity_source="final")
            if policy.is_higher(final, record["deadline_severity"]):
                record.update(deadline_severity=final, target_seconds=policy.TARGETS[final]["seconds"],
                              deadline=policy.deadline_for(record["started_at"], final), breached_at=None)
            change["deadline_after"] = record["deadline"]
            record["changes"].append(change)
            self._audit("sla_severity_changed", alert_id, "La severidad final sustituye a la de la regla. Si es mayor, el plazo se recalcula desde el mismo inicio.", change)
        elif final in policy.TARGETS:
            record["severity_source"] = "final"
        if record["stopped_at"] is None and not is_fallback(ticket, events):
            record.update(stopped_at=at, stopped_by="ticket")
        self._settle(record)
        self.store.save_sla(alert_id, record)
        self._notify(record, "severity", f"Severidad {SEVERITY_NAME[record['severity']]} tras el triaje (política, apartado 3).")
        return record

    @_locked
    def on_decision(self, alert_id, at=None):
        """A person decided on a fallback ticket: the triage that never finished ended there."""
        record = self.store.get_sla(alert_id)
        if record and record["stopped_at"] is None:
            record.update(stopped_at=at or self.now(), stopped_by="person")
            self._settle(record)
            self.store.save_sla(alert_id, record)

    def _settle(self, record):
        """Records met or breached once the clock has stopped."""
        if record["stopped_at"] is None:
            return
        before = record["status"]
        record["status"] = policy.outcome(record["stopped_at"], record["deadline"])
        if record["status"] == "breached":
            record["breached_at"] = record["breached_at"] or record["deadline"]
            if before != "breached":
                self._record_breach(record)
        else:
            record["breached_at"] = None
        self._audit("sla_stopped", record["alert_id"], f"Reloj detenido: {record['status']}.",
                    {"stopped_at": record["stopped_at"], "deadline": record["deadline"], "status": record["status"], "by": record["stopped_by"]})

    def _record_breach(self, record):
        self._audit("sla_breached", record["alert_id"], "Se superó el plazo de la política.", {"deadline": record["deadline"], "severity": record["severity"]})
        self._notify(record, "breach", f"Plazo incumplido para severidad {SEVERITY_NAME[record['severity']]}.")

    @_locked
    def refresh(self):
        """Records breaches of clocks still running. The time recorded is the deadline itself, so it's exact
        even if nobody was looking when it passed."""
        self.open_new()
        now = self.now()
        for alert_id, record in self.store.all_sla().items():
            if record["status"] == "open" and record["deadline"] and policy.live_status(record["deadline"], record["target_seconds"], now) == "breached":
                record.update(status="breached", breached_at=record["deadline"])
                self.store.save_sla(alert_id, record)
                self._record_breach(record)

    def view(self, record, worker_stopped=False, now=None):
        """A record plus its status right now: on_track, at_risk, breached, batch, met. If the worker that should triage
        an open alert isn't running, the alert can't be triaged in time and shows as at risk. Never closed for it."""
        if not record:
            return None
        now = now or self.now()
        if record["stopped_at"] is not None:
            state, why = record["status"], None
        elif record["status"] == "breached":
            state, why = "breached", None
        else:
            state = policy.live_status(record["deadline"], record["target_seconds"], now)
            why = "time" if state == "at_risk" else None
            if state == "on_track" and worker_stopped:
                state, why = "at_risk", "worker"
        return {**record, "state": state, "at_risk_reason": why, "required_action": policy.required_action(record["severity"])}

    @_locked
    def confirm_escalation(self, alert_id, analyst, kind, note):
        """A person says they made the N2 call or handover. The system calls nobody."""
        record = self.store.get_sla(alert_id)
        if not record:
            return None
        record["escalation_confirmation"] = {"kind": kind, "by": analyst, "at": self.now(), "note": note}
        self.store.save_sla(alert_id, record)
        self.store.add_audit("person", analyst, "escalation_confirmed", alert_id, note or "Confirmación sin nota.", {"kind": kind})
        return record
