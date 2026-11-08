"""Backend for the UI. Local only: run it with `uvicorn src.app.main:app --port 8001` (binds 127.0.0.1).

Alert and ticket text may be written by attackers. It is stored and returned as plain data,
and nothing here acts on it. The LLM never approves or runs containment. The containment
routes build proposals with plain code (src/policy/containment.py), from a ticket's suggestions
or an incident report's proposed steps, record each person's approval, and call the mock only
when a person clicks run after every required role has approved. A person's decision on a ticket
is only recorded.
"""
import asyncio
import json
import os
import random
import threading
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from src.app import runner
from src.app.import_alerts import MAX_BYTES, ImportProblem, load_alerts, parse_alerts
from src.app.sla_tracker import SlaTracker, is_fallback
from src.app.store import Store, now_iso
from src.app.worker import Settings, Worker
from src.agent.correlate import correlate
from src.agent.rules import RULES
from src.policy import auto_close as auto_close_policy
from src.policy import sla as sla_policy
from src.policy.containment import ApprovalProblem, approve, approver_record, proposals_from_steps, propose, ready_to_run
from src.tools import api_client
from src.tools.alert_fields import fill_from_catalogue
from src.tools.context import _source_of
from src.tools.logs import search_logs
from contracts.models import ActionProposal

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DB = ROOT / "runs" / "app.sqlite3"
DEFAULT_SAMPLE = ROOT / "data" / "03_alertas" / "alertas_muestra_desarrollo.jsonl"

LOCAL_HOSTS = {"127.0.0.1", "::1", "localhost", "testclient", "testserver"}
UI_HEADER = "x-tarvia-ui"
SEVERITIES = ("informational", "low", "medium", "high", "critical")
POLL_SECONDS = 0.3
KEEPALIVE_SECONDS = 15
DEFAULT_SAMPLE_PERCENT = 5.0


def _hostname(value):
    """'localhost:5173' -> 'localhost', '[::1]:8001' -> '::1', 'http://127.0.0.1:5173' -> '127.0.0.1'."""
    value = (value or "").strip().lower()
    if "://" in value:
        value = value.split("://", 1)[1].split("/", 1)[0]
    if value.startswith("["):
        return value[1:].split("]", 1)[0]
    return value.rsplit(":", 1)[0] if value.count(":") == 1 else value


def _text(value):
    return value if isinstance(value, str) and value else None


def _severity(value):
    return value if value in SEVERITIES else None


class ApproveIn(BaseModel):
    role: str = Field(min_length=1, max_length=200)
    approver: str = Field(min_length=1, max_length=100)


class RejectIn(BaseModel):
    approver: str = Field(min_length=1, max_length=100)
    reason: str = Field(default="", max_length=1000)


class DecisionIn(BaseModel):
    analyst: str = Field(min_length=1, max_length=100)
    decision: Literal["accept", "close", "escalate"]
    reason: str = Field(default="", max_length=2000)
    run_id: str | None = Field(default=None, max_length=100)


class PersonIn(BaseModel):
    analyst: str = Field(min_length=1, max_length=100)
    reason: str = Field(default="", max_length=2000)


class EscalationIn(BaseModel):
    analyst: str = Field(min_length=1, max_length=100)
    kind: Literal["call", "handover"]
    note: str = Field(default="", max_length=1000)


def sample_rate():
    """The share of auto-closed tickets shown for review, from AUTO_CLOSE_SAMPLE_PERCENT."""
    try:
        percent = float(os.environ.get("AUTO_CLOSE_SAMPLE_PERCENT", DEFAULT_SAMPLE_PERCENT))
    except ValueError:
        percent = DEFAULT_SAMPLE_PERCENT
    return min(max(percent, 0.0), 100.0) / 100


def create_app(db_path=None, sample_path=None, run_fn=None, report_fn=None, rules_fn=None, settings=None, lookup_asset=None, pick=random.random):
    """The arguments are there so tests can use a temporary database, fake runs and fixed settings."""
    store = Store(db_path or os.environ.get("APP_DB_PATH") or DEFAULT_DB)
    store.mark_interrupted_runs()
    run_fn = run_fn or runner.run_triage
    report_fn = report_fn or runner.run_investigation
    rules_fn = rules_fn or runner.run_rules
    lookup_asset = lookup_asset or api_client.get_asset
    settings = settings or Settings()
    tracker = SlaTracker(store, now_iso)
    # APP_SAMPLE=none starts with an empty queue, so it holds only the alerts you import.
    sample_setting = sample_path or os.environ.get("APP_SAMPLE") or DEFAULT_SAMPLE
    if str(sample_setting).lower() == "none":
        sample = {"path": None, "loaded": 0, "error": None}
    else:
        sample_path = Path(sample_setting)
        sample = {"path": sample_path.name, "loaded": 0, "error": None}
        try:
            alerts, errors = load_alerts(sample_path)
            store.add_alerts(alerts, "sample")
            sample["loaded"] = len(alerts)
            if errors:
                sample["error"] = f"{len(errors)} fila(s) de la muestra no se pudieron leer."
        except FileNotFoundError:
            sample["error"] = "No se encontró la muestra de alertas en data/03_alertas/."
        except (OSError, ImportProblem) as error:
            sample["error"] = f"No se pudo leer la muestra de alertas ({type(error).__name__})."

    tracker.open_new()

    @asynccontextmanager
    async def lifespan(_app):
        if settings.enabled:  # AUTO_TRIAGE=1 starts it with the server. With 0 nothing here runs.
            worker.start()
        yield
        worker.stop("server")
        worker.join(5)

    app = FastAPI(title="Tarvia triage", lifespan=lifespan)
    app.state.store = store

    @app.middleware("http")
    async def local_only(request: Request, call_next):
        client = request.client.host if request.client else ""
        if client not in LOCAL_HOSTS or _hostname(request.headers.get("host")) not in LOCAL_HOSTS:
            return JSONResponse({"detail": "Solo se permite el acceso local."}, status_code=403)
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            origin = request.headers.get("origin")
            if origin and _hostname(origin) not in LOCAL_HOSTS:
                return JSONResponse({"detail": "Origen no permitido."}, status_code=403)
            if request.headers.get(UI_HEADER) != "1":
                return JSONResponse({"detail": "Falta la cabecera X-Tarvia-UI."}, status_code=403)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        return response

    def ticket_summary(row, run):
        if not row:
            return None
        ticket = row["ticket"] if isinstance(row["ticket"], dict) else {}
        escalation = ticket.get("escalation") if isinstance(ticket.get("escalation"), dict) else {}
        escalate = escalation.get("escalate")
        return {
            "ticket_id": row["ticket_id"],
            "run_id": row["run_id"],
            "mode": row["mode"],
            "verdict": _text(ticket.get("verdict")),
            "severity": _severity(ticket.get("severity")),
            "proposed": "escalate" if escalate is True else "close" if escalate is False else None,
            "injection_flags": len(ticket.get("injection_flags") or []) if isinstance(ticket.get("injection_flags"), list) else 0,
            # The fixed rule that closed it without the LLM (src/agent/rules.py), or None.
            "closed_by_rule": _text(ticket["closed_by_rule"].get("rule_id")) if isinstance(ticket.get("closed_by_rule"), dict) else None,
            "triage_seconds": run.get("duration_seconds") if run else None,
            "auto_closed": ticket.get("auto_closed") is True,
            "auto_close": ticket.get("auto_close") if isinstance(ticket.get("auto_close"), dict) else None,
            # The triage couldn't finish, so a person must look at it and its SLA clock is still running.
            "fallback": is_fallback(ticket, store.events_after(row["run_id"])) if ticket.get("verdict") == "needs_more_info" else False,
        }

    def run_view(run):
        if not run:
            return None
        return {key: run[key] for key in ("run_id", "mode", "status", "started_at", "finished_at", "duration_seconds", "ticket_id", "error")}

    def triaged_pairs():
        """(alert, latest ticket) for every alert whose newest run produced a ticket."""
        runs = store.latest_runs()
        pairs = []
        for row in store.list_alerts():
            run = runs.get(row["alert"]["alert_id"])
            ticket_row = store.ticket_for_run(run["run_id"]) if run else None
            if ticket_row and isinstance(ticket_row["ticket"], dict):
                pairs.append((row["alert"], ticket_row["ticket"]))
        return pairs

    def memberships():
        latest = store.latest_correlation()
        return latest.get("memberships", {}) if latest else {}

    def latest_ticket(alert_id, runs=None):
        runs = store.latest_runs() if runs is None else runs
        run = runs.get(alert_id)
        return store.ticket_for_run(run["run_id"]) if run else None

    def is_escalated(ticket):
        escalation = ticket.get("escalation") if isinstance(ticket, dict) and isinstance(ticket.get("escalation"), dict) else {}
        return escalation.get("escalate") is True

    def report_subject(key):
        """What a report key names: an incident from the latest grouping, or one ticket. None if neither.
        Only tickets from the real agent go to the investigation as leads; example tickets are made up."""
        latest = store.latest_correlation() or {}
        incident = next((i for i in latest.get("incidents", []) if i.get("incident_id") == key), None)
        if incident:
            runs = store.latest_runs()
            alert_ids = [m["alert_id"] for m in incident.get("members", [])]
            rows = [latest_ticket(alert_id, runs) for alert_id in alert_ids]
            ticket = incident.get("ticket") or {}
            return {"key": key, "kind": "incident", "incident_id": key, "title": _text(ticket.get("title")),
                    "alert_ids": alert_ids, "escalated": is_escalated(ticket),
                    "tickets": [r["ticket"] for r in rows if r and r["mode"] == "real"]}
        row = store.get_ticket(key)
        if not row:
            return None
        return {"key": key, "kind": "ticket", "incident_id": None, "title": _text(row["ticket"].get("title")),
                "alert_ids": [row["alert_id"]], "escalated": is_escalated(row["ticket"]),
                "tickets": [row["ticket"]] if row["mode"] == "real" else []}

    def report_key_for(alert_id, ticket_row):
        """Where the report of an alert lives: its incident if level 2 grouped it, otherwise its own escalated ticket."""
        incident_id = memberships().get(alert_id)
        if incident_id:
            return incident_id
        if ticket_row and is_escalated(ticket_row["ticket"]):
            return ticket_row["ticket_id"]
        return None

    def worker_blocked():
        """The worker should be triaging but isn't, so open alerts can't count on it. Never true with AUTO_TRIAGE=0."""
        return settings.enabled and worker.state != "running"

    @app.get("/api/queue")
    def queue():
        tracker.refresh()
        runs = store.latest_runs()
        decisions = store.latest_decisions_by_run()
        incident_of = memberships()
        records = store.all_sla()
        blocked = worker_blocked()
        now = now_iso()
        containment_runs = store.runs_with_containment_activity()
        items = []
        for row in store.list_alerts():
            alert = row["alert"]
            shown = fill_from_catalogue(alert)[0]
            run = runs.get(alert["alert_id"])
            ticket = ticket_summary(store.ticket_for_run(run["run_id"]), run) if run else None
            running = bool(run and run["status"] == "running")
            items.append({
                "alert_id": alert["alert_id"],
                "created_at": _text(alert.get("created_at")),
                "source_product": _text(shown.get("source_product")),
                "rule_id": _text(shown.get("rule_id")),
                "rule_name": _text(shown.get("rule_name")),
                "rule_severity": _text(alert.get("severity")),
                "origin": row["origin"],
                "run": run_view(run),
                "ticket": ticket,
                "decision": decisions.get(run["run_id"]) if run else None,
                "incident_id": incident_of.get(alert["alert_id"]),
                "sla": tracker.view(records.get(alert["alert_id"]), blocked, now),
                # For the pipeline view: structured facts about where the alert is, never its text.
                "has_fixed_rule": shown.get("rule_id") in RULES,
                "llm_started": running and any(e.get("tool") == "llm" for e in store.events_after(run["run_id"])),
                "containment_active": bool(run and run["run_id"] in containment_runs),
            })
        return {
            "mode": runner.current_mode(),
            "sample": sample,
            "alerts": items,
            "example_results": sum(1 for item in items if item["run"] and item["run"]["mode"] == "example"),
            "now": now,
            "worker": {"enabled": settings.enabled, "state": worker.state},
        }

    @app.get("/api/alerts/{alert_id}")
    def alert_detail(alert_id: str):
        row = store.get_alert(alert_id)
        if not row:
            raise HTTPException(404, "Alerta no encontrada.")
        runs = store.runs_for_alert(alert_id)
        latest = runs[0] if runs else None
        ticket_row = store.ticket_for_run(latest["run_id"]) if latest else None
        shown = fill_from_catalogue(row["alert"])[0]
        return {
            "mode": runner.current_mode(),
            "alert": row["alert"],
            # For the page's header only. The alert above stays exactly as it arrived.
            "shown": {key: _text(shown.get(key)) for key in ("rule_id", "rule_name", "source_product")},
            "origin": row["origin"],
            "runs": [run_view(run) for run in runs],
            "latest_run": run_view(latest),
            "ticket": ticket_row,
            "decisions": store.decisions_for(ticket_row["ticket_id"]) if ticket_row else [],
            "incident_id": memberships().get(alert_id),
            "report_key": report_key_for(alert_id, ticket_row),
            "sla": tracker.view(store.get_sla(alert_id), worker_blocked()),
            "now": now_iso(),
        }

    # Containment (level 4). The LLM's suggestions become proposals by plain code. Only these routes, called by a
    # person's click in the UI, ever reach the mock's /approvals and /containment, and only after every role approved.
    containment_lock = threading.Lock()

    def mock_problem(error):
        if isinstance(error, api_client.APIError):
            return f"La API simulada respondió {error.status}: {error.detail}"
        return f"La API simulada no responde ({type(error).__name__})."

    def load_proposal(proposal_id):
        stored = store.get_proposal(proposal_id)
        if not stored:
            raise HTTPException(404, "Propuesta no encontrada.")
        return ActionProposal.model_validate(stored)

    @app.get("/api/tickets/{ticket_id}/containment")
    def containment(ticket_id: str, run_id: str | None = None):
        row = store.ticket_version(ticket_id, run_id) if run_id else store.get_ticket(ticket_id)
        if not row:
            raise HTTPException(404, "Ticket no encontrado.")
        alert_row = store.get_alert(row["alert_id"])
        try:
            built, not_proposed = propose(row["ticket"], alert_row["alert"] if alert_row else {}, api_client.get_asset, api_client.get_user, run_id=row["run_id"])
        except Exception as error:  # the mock API is down or answered oddly
            raise HTTPException(503, mock_problem(error)) from None
        with containment_lock:
            saved = store.proposals_for_run(row["run_id"])
            proposals = []
            for proposal in built:
                if proposal.proposal_id not in saved:
                    store.save_proposal(proposal.model_dump(mode="json"))
                proposals.append(saved.get(proposal.proposal_id) or proposal.model_dump(mode="json"))
        return {"ticket_id": ticket_id, "run_id": row["run_id"], "proposals": proposals, "not_proposed": not_proposed}

    @app.post("/api/containment/{proposal_id}/approve")
    def approve_proposal(proposal_id: str, body: ApproveIn):
        with containment_lock:
            proposal = load_proposal(proposal_id)
            try:
                approve(proposal, body.role, body.approver, now_iso())
            except ApprovalProblem as problem:
                raise HTTPException(400, str(problem)) from None
            store.save_proposal(proposal.model_dump(mode="json"))
        return proposal.model_dump(mode="json")

    @app.post("/api/containment/{proposal_id}/reject")
    def reject_proposal(proposal_id: str, body: RejectIn):
        with containment_lock:
            proposal = load_proposal(proposal_id)
            if proposal.status == "executed":
                raise HTTPException(409, "Esta acción ya se ejecutó.")
            proposal.status, proposal.decided_by, proposal.error = "rejected", body.approver.strip(), body.reason.strip()
            store.save_proposal(proposal.model_dump(mode="json"))
        return proposal.model_dump(mode="json")

    @app.post("/api/containment/{proposal_id}/execute")
    def execute_proposal(proposal_id: str):
        """Runs one approved action against the mock, once. The lock stops two clicks from running it twice."""
        with containment_lock:
            proposal = load_proposal(proposal_id)
            try:
                ready_to_run(proposal)
            except ApprovalProblem as problem:
                raise HTTPException(409, str(problem)) from None
            reason = proposal.justification or proposal.suggestion
            try:
                approval = api_client.request_approval(proposal.action, proposal.target, approver_record(proposal), reason)
                record = api_client.run_containment(proposal.action, proposal.target, reason, approval["approval_token"], proposal.ticket_id)
            except api_client.ContainmentRefused as refused:
                proposal.status, proposal.error = "refused", str(refused)
            except Exception as error:
                proposal.status, proposal.error = "refused", mock_problem(error)
            else:
                proposal.status, proposal.result = "executed", record
            store.save_proposal(proposal.model_dump(mode="json"))
        if proposal.status != "executed":
            raise HTTPException(409, f"La acción no se ejecutó: {proposal.error}")
        return proposal.model_dump(mode="json")

    @app.get("/api/containment/log")
    def containment_log():
        try:
            return {"entries": api_client.get_containment_log()}
        except Exception as error:
            raise HTTPException(503, mock_problem(error)) from None

    def group_now():
        pairs = triaged_pairs()
        result = correlate(pairs)
        built_at = store.save_correlation(result)
        return result, built_at

    @app.post("/api/incidents/build")
    def build_incidents():
        """Level 2: groups the latest tickets into incidents with plain code, and keeps the result with its reasons."""
        result, built_at = group_now()
        return {"built_at": built_at, "alerts": result["alerts"], "incidents": len(result["incidents"]),
                "grouped_alerts": len(result["memberships"])}

    @app.get("/api/incidents")
    def incidents():
        latest = store.latest_correlation()
        triaged = len(triaged_pairs())
        reports = store.latest_reports()
        if not latest:
            return {"built_at": None, "incidents": [], "noise": [], "memberships": {}, "alerts": 0, "triaged_now": triaged,
                    "stale": triaged > 0, "reports": reports}
        return {**latest, "triaged_now": triaged, "stale": triaged != latest.get("alerts"), "reports": reports}

    @app.post("/api/alerts/import")
    async def import_alerts(request: Request):
        declared = request.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > MAX_BYTES:
            raise HTTPException(413, f"El fichero supera el máximo de {MAX_BYTES // 1000} KB.")
        body = bytearray()
        async for chunk in request.stream():
            body += chunk
            if len(body) > MAX_BYTES:
                raise HTTPException(413, f"El fichero supera el máximo de {MAX_BYTES // 1000} KB.")
        try:
            result = parse_alerts(bytes(body))
        except ImportProblem as error:
            raise HTTPException(400, str(error)) from None
        added, skipped = store.add_alerts(result["alerts"], "imported")
        tracker.open_new()
        return {
            "format": result["format"],
            "rows": result["rows"],
            "imported": added,
            "skipped": [{"alert_id": alert_id, "reason": "Ya estaba en la cola."} for alert_id in skipped],
            "errors": result["errors"],
        }

    def apply_auto_close(ticket, alert, mode, run_id):
        """Only changes who must look at the result. The close or escalate decision is the ticket's own, and stays."""
        eligible, failed = auto_close_policy.assess(ticket, fill_from_catalogue(alert)[0], mode, lookup_asset)
        if not eligible:
            store.add_audit("code", "src/policy/auto_close.py", "auto_close_refused", alert["alert_id"], "Sigue en la cola para una persona.",
                            {"ticket_id": ticket["ticket_id"], "run_id": run_id, "failed": failed})
            return ticket
        rule = ticket["closed_by_rule"].get("rule_id") if isinstance(ticket.get("closed_by_rule"), dict) else None
        model = next((e["args"]["model"] for e in reversed(store.events_after(run_id))
                      if e.get("tool") == "llm" and isinstance(e.get("args"), dict) and e["args"].get("model")), None)
        reason = auto_close_policy.closure_reason(ticket)
        detail = {"reason": reason, "by_rule": rule, "by_model": model, "at": now_iso(), "sampled": pick() < sample_rate(),
                  "detection_rule": fill_from_catalogue(alert)[0].get("rule_id"), "reviewed_by": None, "reopened_by": None}
        store.add_audit("code" if rule else "model", rule or model or "desconocido", "auto_closed", alert["alert_id"], reason,
                        {"ticket_id": ticket["ticket_id"], "run_id": run_id, "sampled": detail["sampled"]})
        return {**ticket, "auto_closed": True, "auto_close": detail}

    def work(run_id, alert, mode, source=None, by_worker=False):
        started = time.monotonic()
        ticket_id = None
        error = None
        try:
            for raw in (run_fn(alert, mode=mode) if source is None else source):
                event = raw if isinstance(raw, dict) else {}
                event = {
                    **event,
                    "at": _text(event.get("at")) or now_iso(),
                    "type": _text(event.get("type")) or "note",
                    "args": event.get("args") if isinstance(event.get("args"), dict) else {},
                    "summary": event.get("summary") if isinstance(event.get("summary"), str) else "",
                    "event_ids": [str(i) for i in event.get("event_ids") or [] if isinstance(i, (str, int))]
                    if isinstance(event.get("event_ids"), list) else [],
                    "truncated": bool(event.get("truncated")),
                }
                store.add_event(run_id, event)
                ticket = event.get("ticket")
                if event["type"] == "ticket_ready" and isinstance(ticket, dict):
                    ticket = {**ticket, "ticket_id": str(ticket.get("ticket_id") or f"TKT-{alert['alert_id']}")}
                    if by_worker:
                        ticket = apply_auto_close(ticket, alert, mode, run_id)
                    store.save_ticket(ticket, run_id, alert["alert_id"], mode)
                    tracker.on_ticket(alert["alert_id"], ticket, run_id, mode, store.events_after(run_id))
                    ticket_id = ticket["ticket_id"]
            if not ticket_id:
                error = "El triaje terminó sin ticket."
        except runner.TriageUnavailable as problem:
            error = str(problem)
        except Exception as problem:  # the run must always end, whatever the agent does
            error = f"Error interno durante el triaje ({type(problem).__name__})."
        if error:
            store.add_event(run_id, {"at": now_iso(), "type": "error", "tool": "app", "args": {"kind": "runner"},
                                     "summary": error, "event_ids": [], "truncated": False})
        store.finish_run(run_id, "failed" if error else "done", round(time.monotonic() - started, 2), ticket_id, error)

    # One lock around "is one running? then create one", so a click and the worker can't both start the same alert.
    claim_lock = threading.Lock()

    def claim_run(key, mode):
        """A new run for this alert or report, or (None, the one already running)."""
        with claim_lock:
            active = store.active_run(key)
            if active:
                return None, active
            run_id = f"RUN-{uuid.uuid4().hex[:12]}"
            store.create_run(run_id, key, mode)
            return run_id, None

    @app.post("/api/triage/{alert_id}", status_code=202)
    def run_triage(alert_id: str):
        row = store.get_alert(alert_id)
        if not row:
            raise HTTPException(404, "Alerta no encontrada.")
        mode = runner.current_mode()
        run_id, active = claim_run(alert_id, mode)
        if active:
            return {"run_id": active["run_id"], "mode": active["mode"], "status": "running", "already_running": True}
        threading.Thread(target=work, args=(run_id, row["alert"], mode), daemon=True, name=run_id).start()
        return {"run_id": run_id, "mode": mode, "status": "running", "already_running": False}

    def work_report(run_id, subject):
        started = time.monotonic()
        saved = False
        error = None
        try:
            alerts = [row["alert"] for row in (store.get_alert(a) for a in subject["alert_ids"]) if row]
            if not alerts:
                raise runner.TriageUnavailable("Las alertas de este incidente ya no están en la cola.")
            others = [row["alert"] for row in store.list_alerts() if row["alert"]["alert_id"] not in subject["alert_ids"]]
            for raw in report_fn(alerts, tickets=subject["tickets"], incident_id=subject["incident_id"], others=others,
                                 memberships=memberships()):
                event = raw if isinstance(raw, dict) else {}
                report = event.get("report")
                event = {
                    **{k: v for k, v in event.items() if k != "report"},
                    "at": _text(event.get("at")) or now_iso(),
                    "type": _text(event.get("type")) or "note",
                    "args": event.get("args") if isinstance(event.get("args"), dict) else {},
                    "summary": event.get("summary") if isinstance(event.get("summary"), str) else "",
                    "event_ids": [str(i) for i in event.get("event_ids") or [] if isinstance(i, (str, int))]
                    if isinstance(event.get("event_ids"), list) else [],
                    "truncated": bool(event.get("truncated")),
                }
                store.add_event(run_id, event)
                if event["type"] == "report_ready" and isinstance(report, dict):
                    store.save_report(report, run_id, subject["key"])
                    saved = True
            if not saved:
                error = "La investigación terminó sin informe."
        except runner.TriageUnavailable as problem:
            error = str(problem)
        except Exception as problem:  # the run must always end, whatever the agent does
            error = f"Error interno durante la investigación ({type(problem).__name__})."
        if error:
            store.add_event(run_id, {"at": now_iso(), "type": "error", "tool": "app", "args": {"kind": "runner"},
                                     "summary": error, "event_ids": [], "truncated": False})
        store.finish_run(run_id, "failed" if error else "done", round(time.monotonic() - started, 2), subject["key"] if saved else None, error)

    @app.post("/api/reports/{key}", status_code=202)
    def start_report(key: str):
        """Level 3: investigates an escalated incident or ticket. The report only proposes containment."""
        subject = report_subject(key)
        if not subject:
            raise HTTPException(404, "No hay ningún incidente ni ticket con ese identificador.")
        if not subject["escalated"]:
            raise HTTPException(409, "Solo se investigan incidentes o tickets escalados.")
        run_id, active = claim_run(key, "report")
        if active:
            return {"run_id": active["run_id"], "status": "running", "already_running": True}
        threading.Thread(target=work_report, args=(run_id, subject), daemon=True, name=run_id).start()
        return {"run_id": run_id, "status": "running", "already_running": False}

    @app.get("/api/reports/{key}")
    def get_report(key: str):
        subject = report_subject(key)
        row = store.get_report(key)
        if not subject and not row:
            raise HTTPException(404, "No hay ningún incidente ni ticket con ese identificador.")
        runs = store.runs_for_alert(key)
        shown = {k: v for k, v in (subject or {}).items() if k != "tickets"}
        if subject:
            shown["leads"] = len(subject["tickets"])
        return {"subject": shown or None, "report": row, "latest_run": run_view(runs[0] if runs else None),
                "runs": [run_view(r) for r in runs]}

    @app.get("/api/reports/{key}/containment")
    def report_containment(key: str):
        """Level 3 to 4: the newest report's proposed steps become ActionProposals, checked again by the same rules as
        a ticket's. They go through the same approve, reject and execute routes; ticket_id holds the report's key."""
        row = store.get_report(key)
        if not row:
            raise HTTPException(404, "Este incidente aún no tiene informe.")
        steps = (row["report"] or {}).get("containment_plan") or []
        try:
            built, not_proposed = proposals_from_steps(steps, key, row["run_id"], api_client.get_asset, api_client.get_user)
        except Exception as error:  # the mock API is down or answered oddly
            raise HTTPException(503, mock_problem(error)) from None
        with containment_lock:
            saved = store.proposals_for_run(row["run_id"])
            proposals = []
            for proposal in built:
                if proposal.proposal_id not in saved:
                    store.save_proposal(proposal.model_dump(mode="json"))
                proposals.append(saved.get(proposal.proposal_id) or proposal.model_dump(mode="json"))
        return {"ticket_id": key, "run_id": row["run_id"], "proposals": proposals, "not_proposed": not_proposed}

    @app.get("/api/runs/{run_id}/events")
    async def run_events(run_id: str, request: Request, after: int = 0):
        """Server-sent events. Replays every stored event after `after` (or Last-Event-ID), then follows the run."""
        if not store.get_run(run_id):
            raise HTTPException(404, "Ejecución no encontrada.")
        last = request.headers.get("last-event-id", "")
        start = max(after, int(last) if last.isdigit() else 0)

        async def stream():
            sent = start
            quiet = 0.0
            yield "retry: 2000\n\n"
            while True:
                run = store.get_run(run_id)  # read the status before the events, so none are missed
                events = store.events_after(run_id, sent)
                for event in events:
                    sent = event["seq"]
                    yield f"id: {sent}\nevent: trace\ndata: {json.dumps(event, ensure_ascii=False)}\n\n"
                if run["status"] != "running":
                    end = {key: run[key] for key in ("status", "error", "ticket_id", "duration_seconds")}
                    yield f"event: end\ndata: {json.dumps(end, ensure_ascii=False)}\n\n"
                    return
                if await request.is_disconnected():
                    return
                quiet = 0.0 if events else quiet + POLL_SECONDS
                if quiet >= KEEPALIVE_SECONDS:
                    quiet = 0.0
                    yield ": ping\n\n"
                await asyncio.sleep(POLL_SECONDS)

        return StreamingResponse(stream(), media_type="text/event-stream", headers={"X-Accel-Buffering": "no"})

    @app.get("/api/tickets/{ticket_id}")
    def ticket(ticket_id: str):
        row = store.get_ticket(ticket_id)
        if not row:
            raise HTTPException(404, "Ticket no encontrado.")
        return {**row, "run": run_view(store.get_run(row["run_id"])), "decisions": store.decisions_for(ticket_id)}

    @app.post("/api/tickets/{ticket_id}/decision", status_code=201)
    def decide(ticket_id: str, body: DecisionIn):
        analyst = body.analyst.strip()
        reason = body.reason.strip()
        if not analyst:
            raise HTTPException(422, "Indica el nombre de la persona que decide.")
        if body.decision != "accept" and not reason:
            raise HTTPException(422, "Para cambiar la propuesta hay que dar un motivo.")
        row = store.ticket_version(ticket_id, body.run_id) if body.run_id else store.get_ticket(ticket_id)
        if not row:
            if body.run_id and store.get_ticket(ticket_id):
                raise HTTPException(409, "Esa versión del ticket no existe.")
            raise HTTPException(404, "Ticket no encontrado.")
        if body.decision == "accept":
            escalation = row["ticket"].get("escalation") if isinstance(row["ticket"].get("escalation"), dict) else {}
            if not isinstance(escalation.get("escalate"), bool):
                raise HTTPException(422, "El ticket no tiene propuesta de cerrar o escalar: elige cerrar o escalar con un motivo.")
            outcome = "escalate" if escalation["escalate"] else "close"
        else:
            outcome = body.decision
        saved = store.add_decision(ticket_id, row["run_id"], analyst, body.decision, outcome, reason)
        tracker.on_decision(row["alert_id"])
        return saved

    # Automation: everything below only runs because a person called it, or because the worker chose what comes next.

    def worker_triage(alert):
        """Level 1, by the same work() as the route. Returns the run, or None if one is already running."""
        mode = runner.current_mode()
        run_id, active = claim_run(alert["alert_id"], mode)
        if active:
            return None
        store.add_audit("code", "src/app/worker.py", "auto_triage_started", alert["alert_id"], "Siguiente alerta por prioridad.", {"run_id": run_id})
        work(run_id, alert, mode, by_worker=True)
        return run_id

    def worker_rules(alert):
        """The fixed rules alone. If none closed the alert no run is stored, so it goes on to the LLM as usual."""
        mode = runner.current_mode()
        events = list(rules_fn(alert, mode=mode))
        if not any(isinstance(e, dict) and e.get("type") == "ticket_ready" for e in events):
            return False
        run_id, active = claim_run(alert["alert_id"], mode)
        if active:
            return False
        store.add_audit("code", "src/app/worker.py", "auto_rules_applied", alert["alert_id"], "Regla fija, sin LLM.", {"run_id": run_id})
        work(run_id, alert, mode, source=events, by_worker=True)
        return True

    def reopen_ticket(row, actor_kind, actor, reason):
        ticket = row["ticket"]
        detail = {**(ticket.get("auto_close") or {}), "reopened_by": actor, "reopened_at": now_iso(), "reopen_reason": reason}
        store.update_ticket(row["run_id"], {**ticket, "auto_closed": False, "auto_close": detail})
        store.add_audit(actor_kind, actor, "auto_close_reopened", row["alert_id"], reason, {"ticket_id": row["ticket_id"], "run_id": row["run_id"]})

    def worker_group():
        """Level 2, by the same code as the route. An auto-closed alert that joined an escalated incident goes back to
        a person: the policy escalates a chain even if each alert alone is low."""
        result, built_at = group_now()
        store.add_audit("code", "src/agent/correlate.py", "auto_grouped", "worker", "Hay tickets nuevos desde la última agrupación.",
                        {"built_at": built_at, "alerts": result["alerts"], "incidents": len(result["incidents"])})
        runs = store.latest_runs()
        for incident in result["incidents"]:
            if not is_escalated(incident["ticket"]):
                continue
            for member in incident["members"]:
                row = latest_ticket(member["alert_id"], runs)
                if row and row["ticket"].get("auto_closed") is True:
                    reopen_ticket(row, "code", "src/agent/correlate.py", "Forma parte de un incidente escalado: debe verlo una persona.")

    def report_candidates():
        """Escalated incidents and tickets with no report or run yet, critical first. A ticket waits for the grouping
        after it, so it isn't investigated alone just before it joins an incident. Fallback tickets stay out: nothing
        was triaged, so a person looks at them first."""
        latest = store.latest_correlation()
        # Example tickets are made up, and a report always calls the real LLM, so they never start one.
        if not latest or runner.current_mode() != "real":
            return []
        reports = store.latest_reports()
        found = []
        for incident in latest.get("incidents", []):
            ticket = incident.get("ticket") or {}
            key = incident.get("incident_id")
            if is_escalated(ticket) and key not in reports and not store.active_run(key):
                found.append({"key": key, "severity": ticket.get("severity") if ticket.get("severity") in SEVERITIES else "medium"})
        grouped = latest.get("memberships", {})
        runs = store.latest_runs()
        for row in store.list_tickets():
            run = runs.get(row["alert_id"])
            ticket = row["ticket"]
            if (run and run["run_id"] == row["run_id"] and row["mode"] == "real" and is_escalated(ticket) and row["alert_id"] not in grouped
                    and row["saved_at"] <= latest["built_at"] and row["ticket_id"] not in reports and not store.active_run(row["ticket_id"])
                    and not is_fallback(ticket, store.events_after(row["run_id"]))):
                found.append({"key": row["ticket_id"], "severity": ticket.get("severity") if ticket.get("severity") in SEVERITIES else "medium"})
        return sorted(found, key=lambda item: -SEVERITIES.index(item["severity"]))

    def worker_report(key):
        """Level 3, by the same work_report() as the route. The report only proposes containment."""
        subject = report_subject(key)
        if not subject or not subject["escalated"]:
            return None
        run_id, active = claim_run(key, "report")
        if active:
            return None
        store.add_audit("code", "src/app/worker.py", "auto_investigation_started", key, "Escalado sin informe: primero los críticos.", {"run_id": run_id})
        work_report(run_id, subject)
        return run_id

    worker = Worker(store, settings, triage_one=worker_triage, try_rules=worker_rules, group=worker_group,
                    report_candidates=report_candidates, report_one=worker_report, tick=tracker.refresh)
    app.state.worker = worker
    app.state.tracker = tracker

    def require_enabled():
        if not settings.enabled:
            raise HTTPException(409, "El trabajador está desactivado. Arranca el servidor con AUTO_TRIAGE=1 para usarlo.")

    @app.post("/api/worker/start")
    def worker_start():
        require_enabled()
        worker.start()
        return worker.view()

    @app.post("/api/worker/pause")
    def worker_pause():
        require_enabled()
        worker.pause()
        return worker.view()

    @app.post("/api/worker/stop")
    def worker_stop():
        require_enabled()
        worker.stop()
        return worker.view()

    def auto_close_counts():
        """Per fixed rule, and per detection rule for the LLM's closes, so a rule that's too broad is visible.
        Reopened tickets still count: a rule that closed wrongly must not disappear from its own count."""
        counts = {}
        samples = []
        for row in store.list_tickets():
            detail = row["ticket"].get("auto_close")
            if not isinstance(detail, dict):
                continue
            by_rule = detail.get("by_rule")
            key = (by_rule or "LLM", detail.get("detection_rule"))
            entry = counts.setdefault(key, {"closed_by": by_rule or "LLM", "kind": "rule" if by_rule else "llm", "detection_rule": detail.get("detection_rule"), "count": 0, "reopened": 0})
            entry["count"] += 1
            entry["reopened"] += 1 if detail.get("reopened_by") else 0
            if detail.get("sampled"):
                samples.append({"alert_id": row["alert_id"], "ticket_id": row["ticket_id"], "severity": row["ticket"].get("severity"), "verdict": row["ticket"].get("verdict"),
                                 "closed_by": by_rule or "LLM", "reviewed_by": detail.get("reviewed_by"), "reopened_by": detail.get("reopened_by"), "at": detail.get("at")})
        return sorted(counts.values(), key=lambda entry: -entry["count"]), samples

    @app.get("/api/status")
    def status():
        tracker.refresh()
        worker_view = worker.view()
        blocked = worker_blocked()
        now = now_iso()
        records = store.all_sla()
        runs = store.latest_runs()
        pending = {severity: 0 for severity in SEVERITIES}
        sla_counts = {severity: {"on_track": 0, "at_risk": 0, "breached": 0, "met": 0, "batch": 0} for severity in SEVERITIES}
        for alert_id, record in records.items():
            view = tracker.view(record, blocked, now)
            sla_counts[view["severity"]][view["state"]] += 1
            run = runs.get(alert_id)
            if not run or run["status"] == "failed":
                pending[view["rule_severity"]] += 1
        per_rule, samples = auto_close_counts()
        return {
            "now": now, "worker": worker_view, "pending_by_priority": pending, "sla": sla_counts, "sla_targets": sla_policy.TARGETS,
            "notifications_unacknowledged": store.count_unacknowledged(), "auto_closed": per_rule, "samples": samples,
            "sample_percent": round(sample_rate() * 100, 2), "at_risk_fraction": sla_policy.AT_RISK_FRACTION,
        }

    @app.get("/api/sla/targets")
    def sla_targets():
        return {"targets": sla_policy.TARGETS, "at_risk_fraction": sla_policy.AT_RISK_FRACTION}

    @app.get("/api/notifications")
    def notifications():
        tracker.refresh()
        return {"notifications": store.list_notifications(), "unacknowledged": store.count_unacknowledged()}

    @app.post("/api/notifications/{notification_id}/acknowledge")
    def acknowledge(notification_id: int, body: PersonIn):
        analyst = body.analyst.strip()
        if not analyst:
            raise HTTPException(422, "Indica el nombre de la persona.")
        found = store.get_notification(notification_id)
        if not found:
            raise HTTPException(404, "Notificación no encontrada.")
        if store.acknowledge_notification(notification_id, analyst):
            store.add_audit("person", analyst, "notification_acknowledged", found["alert_id"], body.reason.strip() or "Enterado.", {"notification_id": notification_id, "role": found["role"]})
        return store.get_notification(notification_id)

    @app.post("/api/alerts/{alert_id}/escalation")
    def confirm_escalation(alert_id: str, body: EscalationIn):
        """A person says the N2 call or handover happened. Nothing here calls anyone."""
        analyst = body.analyst.strip()
        if not analyst:
            raise HTTPException(422, "Indica el nombre de la persona.")
        record = store.get_sla(alert_id)
        if not record:
            raise HTTPException(404, "Alerta no encontrada.")
        if not sla_policy.required_action(record["severity"]):
            raise HTTPException(409, "La política solo exige confirmar el escalado en severidad alta o crítica.")
        return tracker.view(tracker.confirm_escalation(alert_id, analyst, body.kind, body.note.strip()), worker_blocked())

    def auto_closed_row(ticket_id):
        row = store.get_ticket(ticket_id)
        if not row:
            raise HTTPException(404, "Ticket no encontrado.")
        return row

    @app.post("/api/tickets/{ticket_id}/reopen")
    def reopen(ticket_id: str, body: PersonIn):
        """A person sends an auto-closed ticket back to the human queue. The SLA and the close proposal don't change."""
        analyst, reason = body.analyst.strip(), body.reason.strip()
        if not analyst or not reason:
            raise HTTPException(422, "Para reabrir hay que indicar el nombre y el motivo.")
        row = auto_closed_row(ticket_id)
        if row["ticket"].get("auto_closed") is not True:
            raise HTTPException(409, "Este ticket no está cerrado automáticamente.")
        reopen_ticket(row, "person", analyst, reason)
        return {"ticket_id": ticket_id, "auto_closed": False}

    @app.post("/api/tickets/{ticket_id}/sample-review")
    def sample_review(ticket_id: str, body: PersonIn):
        analyst = body.analyst.strip()
        if not analyst:
            raise HTTPException(422, "Indica el nombre de la persona.")
        row = auto_closed_row(ticket_id)
        detail = row["ticket"].get("auto_close")
        if not isinstance(detail, dict) or not detail.get("sampled"):
            raise HTTPException(409, "Este ticket no está en la muestra de revisión.")
        store.update_ticket(row["run_id"], {**row["ticket"], "auto_close": {**detail, "reviewed_by": analyst, "reviewed_at": now_iso()}})
        store.add_audit("person", analyst, "auto_close_sample_reviewed", row["alert_id"], body.reason.strip() or "Revisada, sin cambios.", {"ticket_id": ticket_id})
        return {"ticket_id": ticket_id, "reviewed_by": analyst}

    @app.get("/api/audit")
    def audit(subject: str | None = None, limit: int = 200):
        return {"entries": store.audit_entries(subject, max(1, min(limit, 1000)))}

    @app.get("/api/events/{event_id}")
    def event_row(event_id: str):
        """One log row, for a person checking an event a ticket cites. It comes back as data, to be shown as plain text."""
        source = _source_of(event_id)
        if not source:
            raise HTTPException(404, "No se reconoce la fuente de este evento.")
        try:
            rows = search_logs(source, value=event_id)["items"]
        except Exception as error:  # the mock API is down or answered oddly
            raise HTTPException(503, mock_problem(error)) from None
        for row in rows:
            if row.get("event_id") == event_id:
                return {"event_id": event_id, "source": source, "row": row}
        raise HTTPException(404, "El log no tiene ese evento.")

    return app


app = create_app()
