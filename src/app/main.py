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
import threading
import time
import uuid
import secrets
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from src.app import runner
from src.app.import_alerts import MAX_BYTES, ImportProblem, load_alerts, parse_alerts
from src.agent.correlate import correlate
from src.app.store import Store, now_iso
from src.app.automation import Automation, Config, Priorities, auto_close_eligible, fingerprint
from src.agent.llm import LLMQuotaExhausted
from src.policy.containment import ApprovalProblem, approve, approver_record, proposals_from_steps, propose, ready_to_run
from src.tools import api_client
from src.tools.alert_fields import fill_from_catalogue
from contracts.models import ActionProposal

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DB = ROOT / "runs" / "app.sqlite3"
DEFAULT_SAMPLE = ROOT / "data" / "03_alertas" / "alertas_muestra_desarrollo.jsonl"

LOCAL_HOSTS = {"127.0.0.1", "::1", "localhost", "testclient", "testserver"}
UI_HEADER = "x-tarvia-ui"
SEVERITIES = ("informational", "low", "medium", "high", "critical")
POLL_SECONDS = 0.3
KEEPALIVE_SECONDS = 15


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
    decision: Literal["accept", "close", "escalate", "reopen"]
    reason: str = Field(default="", max_length=2000)
    run_id: str | None = Field(default=None, max_length=100)


class ControlIn(BaseModel):
    action: Literal["pause", "resume", "reset_budget"]


class EnqueueIn(BaseModel):
    alert_ids: list[str] = Field(min_length=1, max_length=2000)


def create_app(db_path=None, sample_path=None, run_fn=None, report_fn=None, automation_config=None):
    """db_path, sample_path, run_fn and report_fn are arguments so tests can use a temporary database and fake runs."""
    store = Store(db_path or os.environ.get("APP_DB_PATH") or DEFAULT_DB)
    store.mark_interrupted_runs()
    run_fn = run_fn or runner.run_triage
    report_fn = report_fn or runner.run_investigation
    config = automation_config or Config.from_env()
    priority = Priorities()
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

    @asynccontextmanager
    async def lifespan(app):
        automation.start()
        try:
            yield
        finally:
            await asyncio.to_thread(automation.stop)

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
            "affected": ticket.get("affected"),
            "attention_reason": escalation.get("reason") or (ticket.get("open_questions") or [None])[0],
            "evidence_incomplete": (ticket.get("safety_checks") or {}).get("evidence_complete") is not True,
        }

    def run_view(run):
        if not run:
            return None
        return {key: run[key] for key in ("run_id", "mode", "status", "started_at", "finished_at", "duration_seconds", "ticket_id", "error")}

    def triaged_pairs():
        """(alert, latest ticket) for every alert whose newest run produced a ticket."""
        tickets = {r["alert_id"]: r for r in store.completed_tickets()}
        pairs = []
        for row in store.list_alerts():
            ticket_row = tickets.get(row["alert"]["alert_id"])
            if ticket_row and isinstance(ticket_row["ticket"], dict) and store.get_run(ticket_row["run_id"])["status"] == "done":
                pairs.append((row["alert"], ticket_row["ticket"]))
        return pairs

    def memberships():
        latest = store.latest_correlation()
        return latest.get("memberships", {}) if latest else {}

    def latest_ticket(alert_id, runs=None):
        return store.completed_ticket_for_alert(alert_id)

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

    maintenance_lock = threading.RLock()

    def correlation_revision():
        return fingerprint(triaged_pairs())

    def case_revision(row, latest=None):
        latest = latest if latest is not None else store.latest_correlation() or {}
        inc = next((i for i in latest.get("incidents", []) if any(m["alert_id"] == row["alert_id"] for m in i["members"])), None)
        return fingerprint({"run": row["run_id"], "ticket": row["ticket"], "incident": inc})

    def report_revision(subject, corpus_revision=None, triage_revision=None):
        # Global corpus matters: a new alert can add a relation or make a shared identifier too common.
        return fingerprint({"subject": subject, "alerts": corpus_revision or fingerprint(store.list_alerts()), "correlation": triage_revision or correlation_revision()})

    def report_state(key):
        row = store.get_report(key)
        subject = report_subject(key)
        revision = report_revision(subject) if subject else None
        stale = bool(row and store.operation("report-input:" + row["run_id"]) != revision)
        active = store.active_run(key)
        pending = any(j["kind"] == "report" and j["subject"] == key and j["status"] == "pending" and j["revision"] == revision for j in store.jobs())
        return {"status": "running" if active else "pending" if pending else "stale" if stale else "ready" if row else "not_required" if subject and not subject["escalated"] else "needed",
                "stale": stale, "run_id": row["run_id"] if row else None}

    def disposition_view(row, latest=None):
        if not row:
            return None
        saved = store.disposition(row["ticket_id"])
        if saved and saved["revision"] != case_revision(row, latest):
            return {**saved, "state": "review", "previous_state": saved["state"], "reason": "La evidencia o correlación cambió; requiere nueva revisión."}
        return saved

    @app.get("/api/queue")
    def queue():
        runs = store.latest_runs()
        decisions = store.latest_decisions_by_run()
        incident_of = memberships()
        correlation = store.latest_correlation() or {}
        correlation_pending = store.operation("correlation-input") != correlation_revision()
        jobs_by_alert = {}
        for job in store.jobs():
            if job["kind"] == "triage" and job["id"] > jobs_by_alert.get(job["subject"], {}).get("id", 0):
                jobs_by_alert[job["subject"]] = job
        report_states = {}
        items = []
        for row in store.list_alerts():
            alert = row["alert"]
            shown = fill_from_catalogue(alert)[0]
            run = runs.get(alert["alert_id"])
            ticket = ticket_summary(store.ticket_for_run(run["run_id"]), run) if run else None
            ticket_row = store.ticket_for_run(run["run_id"]) if run else None
            key = report_key_for(alert["alert_id"], ticket_row)
            if key and key not in report_states:
                report_states[key] = report_state(key)
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
                "job": jobs_by_alert.get(alert["alert_id"]),
                "disposition": disposition_view(ticket_row, correlation),
                "report_key": key,
                "report_state": report_states.get(key),
                "correlation_pending": bool(ticket_row and correlation_pending and config.auto_triage),
                "processing": store.latest_event(run["run_id"]) if run and run["status"] == "running" else None,
            })
        return {
            "mode": runner.current_mode(),
            "sample": sample,
            "alerts": items,
            "example_results": sum(1 for item in items if item["run"] and item["run"]["mode"] == "example"),
            "automation": automation.status(),
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
            "disposition": disposition_view(ticket_row),
            "disposition_history": store.disposition_history(ticket_row["ticket_id"]) if ticket_row else [],
            "job": next((j for j in store.jobs() if j["subject"] == alert_id and j["status"] in ("pending", "running")), None),
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

    @app.post("/api/incidents/build")
    def build_incidents():
        """Level 2: groups the latest tickets into incidents with plain code, and keeps the result with its reasons."""
        with maintenance_lock:
            pairs = triaged_pairs()
            result = correlate(pairs)
            built_at = store.save_correlation(result)
            store.set_operation("correlation-input", fingerprint(pairs))
            store.audit("code", "correlation", alerts=len(pairs), result=len(result["incidents"]))
        return {"built_at": built_at, "alerts": result["alerts"], "incidents": len(result["incidents"]),
                "grouped_alerts": len(result["memberships"])}

    @app.get("/api/incidents")
    def incidents():
        latest = store.latest_correlation()
        triaged = len(triaged_pairs())
        reports = {key: {**value, **report_state(key)} for key, value in store.latest_reports().items()}
        if not latest:
            return {"built_at": None, "incidents": [], "noise": [], "memberships": {}, "alerts": 0, "triaged_now": triaged,
                    "stale": triaged > 0, "reports": reports}
        return {**latest, "triaged_now": triaged, "stale": store.operation("correlation-input") != correlation_revision(), "reports": reports}

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
        priorities = {a["alert_id"]: priority(a) for a in result["alerts"]} if config.auto_triage else None
        added, skipped = store.add_alerts(result["alerts"], "imported", enqueue_priorities=priorities)
        store.audit("human", "import", imported=len(added), skipped=len(skipped), enqueued=len(added) if config.auto_triage else 0)
        automation.wake.set()
        return {
            "format": result["format"],
            "rows": result["rows"],
            "imported": added,
            "skipped": [{"alert_id": alert_id, "reason": "Ya estaba en la cola."} for alert_id in skipped],
            "errors": result["errors"],
        }

    def work(run_id, alert, mode):
        with automation.execution(run_id, real=mode == "real"):
            _work(run_id, alert, mode)

    def _work(run_id, alert, mode):
        started = time.monotonic()
        ticket_id = None
        error = None
        try:
            for raw in run_fn(alert, mode=mode):
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
                    with maintenance_lock:
                        store.save_ticket(ticket, run_id, alert["alert_id"], mode)
                    ticket_id = ticket["ticket_id"]
            if not ticket_id:
                error = "El triaje terminó sin ticket."
        except LLMQuotaExhausted as problem:
            automation.block(str(problem))
            store.add_event(run_id, {"at": now_iso(), "type": "error", "tool": "llm", "args": {"kind": "quota", "attempts": problem.attempts}, "summary": str(problem), "event_ids": [], "truncated": False})
            error = str(problem)
        except runner.TriageUnavailable as problem:
            error = str(problem)
        except Exception as problem:  # the run must always end, whatever the agent does
            error = f"Error interno durante el triaje ({type(problem).__name__})."
        if error:
            store.add_event(run_id, {"at": now_iso(), "type": "error", "tool": "app", "args": {"kind": "runner"},
                                     "summary": error, "event_ids": [], "truncated": False})
        with maintenance_lock:
            store.finish_run(run_id, "failed" if error else "done", round(time.monotonic() - started, 2), ticket_id, error)

    @app.post("/api/triage/{alert_id}", status_code=202)
    def run_triage(alert_id: str):
        row = store.get_alert(alert_id)
        if not row:
            raise HTTPException(404, "Alerta no encontrada.")
        mode = runner.current_mode()
        run_id = f"RUN-{uuid.uuid4().hex[:12]}"
        with automation._lock:
            active = store.active_run(alert_id)
            if not active and automation.blocked():
                raise HTTPException(409, automation.blocked())
            claimed, started = store.claim_run(run_id, alert_id, mode, enroll_priority=priority(row["alert"]) if (config.auto_triage or config.auto_investigate or config.auto_close) else None)
            if started:
                automation.launch(work, run_id, row["alert"], mode)
        return {"run_id": claimed["run_id"], "mode": claimed["mode"], "status": "running", "already_running": not started}

    def work_report(run_id, subject):
        with automation.execution(run_id, real=True):
            _work_report(run_id, subject)

    def _work_report(run_id, subject):
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
        except LLMQuotaExhausted as problem:
            automation.block(str(problem))
            store.add_event(run_id, {"at": now_iso(), "type": "error", "tool": "llm", "args": {"kind": "quota", "attempts": problem.attempts}, "summary": str(problem), "event_ids": [], "truncated": False})
            error = str(problem)
        except runner.TriageUnavailable as problem:
            error = str(problem)
        except Exception as problem:  # the run must always end, whatever the agent does
            error = f"Error interno durante la investigación ({type(problem).__name__})."
        if error:
            store.add_event(run_id, {"at": now_iso(), "type": "error", "tool": "app", "args": {"kind": "runner"},
                                     "summary": error, "event_ids": [], "truncated": False})
        store.finish_run(run_id, "failed" if error else "done", round(time.monotonic() - started, 2), subject["key"] if saved else None, error)

    @app.post("/api/reports/{key}", status_code=202)
    def start_report(key: str, repeat: bool = False):
        """Level 3: investigates an escalated incident or ticket. The report only proposes containment."""
        subject = report_subject(key)
        if not subject:
            raise HTTPException(404, "No hay ningún incidente ni ticket con ese identificador.")
        if not subject["escalated"]:
            raise HTTPException(409, "Solo se investigan incidentes o tickets escalados.")
        run_id = f"RUN-{uuid.uuid4().hex[:12]}"
        revision = report_revision(subject)
        with automation._lock:
            active = store.active_run(key)
            saved = store.get_report(key)
            if not active and not repeat and saved and not saved["report"].get("fallback") and store.operation("report-input:" + saved["run_id"]) == revision and not any(e["type"] == "error" for e in store.events_after(saved["run_id"])):
                return {"run_id": saved["run_id"], "status": "done", "already_running": False, "already_done": True}
            if not active and automation.blocked():
                raise HTTPException(409, automation.blocked())
            store.enqueue("report", key, revision, subject_priority(subject), "human")
            claimed, started = store.claim_run(run_id, key, "report")
            if started:
                if repeat:
                    store.audit("human", "repeat_report", run_id=run_id, result="started")
                store.set_operation("report-input:" + run_id, revision)
                automation.launch(work_report, run_id, subject)
        return {"run_id": claimed["run_id"], "status": "running", "already_running": not started}

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
        return {"subject": shown or None, "report": row, "state": report_state(key), "latest_run": run_view(runs[0] if runs else None),
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
        return {**row, "run": run_view(store.get_run(row["run_id"])), "decisions": store.decisions_for(ticket_id),
                "disposition": disposition_view(row), "disposition_history": store.disposition_history(ticket_id)}

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
        with maintenance_lock:
            saved = store.add_decision(ticket_id, row["run_id"], analyst, body.decision, outcome, reason)
            store.add_disposition(ticket_id, row["run_id"], case_revision(row), "review" if outcome == "reopen" else "closed" if outcome == "close" else "escalated",
                                  "human", reason or "Propuesta aceptada por una persona", analyst=analyst, decision_id=saved["id"])
        return saved

    def subject_priority(subject):
        rows = [r for r in store.list_tickets() if r["alert_id"] in subject["alert_ids"]]
        return max((priority(store.get_alert(r["alert_id"])["alert"], r["ticket"]) for r in rows), default=20)

    last_maintenance_input = None

    def maintain():
        nonlocal last_maintenance_input
        marker = store.work_revision()
        if marker == last_maintenance_input:
            return
        # Startup does not enrol historical data. Only explicitly queued work unlocks maintenance.
        enrolled = {j["subject"] for j in store.jobs() if j["kind"] == "triage"}
        if not enrolled:
            return
        with maintenance_lock:
            revision = correlation_revision()
            if store.operation("correlation-input") != revision:
                build_incidents()
            latest = store.latest_correlation() or {}
            rows = store.list_tickets()
            corpus_revision = fingerprint(store.list_alerts())
            active_triages = {j["subject"] for j in store.jobs() if j["kind"] == "triage" and j["status"] in ("pending", "running")}
            report_candidates = {}
            for row in rows:
                if store.get_run(row["run_id"])["status"] != "done":
                    continue
                if row["alert_id"] not in enrolled:
                    # Historical closures still reopen when a newly imported chain includes them.
                    if not store.disposition(row["ticket_id"]):
                        continue
                ticket = row["ticket"]
                inc = next((i for i in latest.get("incidents", []) if row["alert_id"] in i["ticket"]["alert_ids"]), None)
                escalates = is_escalated(inc["ticket"]) if inc else False
                current_revision = case_revision(row)
                saved = store.disposition(row["ticket_id"])
                if saved and saved["revision"] != current_revision:
                    store.add_disposition(row["ticket_id"], row["run_id"], current_revision, "review", "code",
                                          "Nueva evidencia o correlación; se conserva la decisión anterior.", previous=saved)
                elif not saved and row["alert_id"] not in active_triages and config.auto_close and row["mode"] == "real" and not any(e["type"] == "error" for e in store.events_after(row["run_id"])) and auto_close_eligible(ticket, correlation_current=True, incident_escalates=escalates):
                    sampled = secrets.randbelow(1_000_000) < config.sample_rate * 1_000_000
                    store.add_disposition(row["ticket_id"], row["run_id"], current_revision, "closed", "automation",
                                          "Condiciones deterministas y política validadas tras correlación.", rule=ticket["closed_by_rule"]["rule_id"],
                                          evidence=ticket["closed_by_rule"]["event_ids"], sampled_for_review=sampled)
                    store.audit("automation", "auto_close", ticket_id=row["ticket_id"], rule=ticket["closed_by_rule"]["rule_id"], sampled_for_review=sampled, result="closed")
                if not config.auto_investigate or row["alert_id"] not in enrolled:
                    continue
                key = report_key_for(row["alert_id"], row)
                if key in report_candidates:
                    continue
                subject = report_subject(key) if key else None
                if not subject or not subject["escalated"]:
                    continue
                if row["mode"] == "example" and report_fn is runner.run_investigation:
                    continue  # Examples must never silently cause real LLM calls.
                rev = report_revision(subject, corpus_revision, revision)
                store.enqueue("report", key, rev, subject_priority(subject), "automation")
                report_candidates[key] = True
            last_maintenance_input = marker

    def process(job):
        if automation.stop_event.is_set():
            return False
        key = job["subject"]
        if job["kind"] == "report":
            subject = report_subject(key)
            if not subject or not subject["escalated"]:
                store.cancel_job(job["id"], "Los datos de entrada cambiaron.")
                return True
            current_revision = report_revision(subject)
            if current_revision != job["revision"]:
                store.cancel_job(job["id"], "Los datos de entrada cambiaron.")
                store.enqueue("report", key, current_revision, subject_priority(subject), job["origin"])
                return True
            if any(store.active_run(a) for a in subject["alert_ids"]):
                return False
            mode = "report"
        else:
            row = store.get_alert(key)
            if not row:
                store.cancel_job(job["id"], "Alerta no disponible.")
                return True
            mode = runner.current_mode()
        run_id = f"RUN-{uuid.uuid4().hex[:12]}"
        with automation._lock:
            if automation.stop_event.is_set() or store.operation("paused", False) or automation.blocked():
                return False
            claimed, started = store.claim_run(run_id, key, mode, job["id"])
            if started:
                automation._active += 1
        if not started:
            return False
        try:
            if job["kind"] == "report":
                store.set_operation("report-input:" + run_id, job["revision"])
                work_report(run_id, subject)
            else:
                work(run_id, row["alert"], mode)
        finally:
            with automation._lock:
                automation._active -= 1
        return True

    automation = Automation(store, config, process, maintain)
    app.state.automation = automation

    @app.get("/api/automation")
    def automation_status():
        result = automation.status()
        closed = [d for r in store.list_tickets() for d in [store.disposition(r["ticket_id"])] if d and d["origin"] == "automation" and d["state"] == "closed"]
        result["closures_by_rule"] = {rule: sum(d.get("rule") == rule for d in closed) for rule in ("R1", "R2")}
        result["review_sample"] = [d for d in closed if d.get("sampled_for_review")]
        return result

    @app.post("/api/automation/control")
    def automation_control(body: ControlIn):
        try:
            automation.control(body.action)
        except ValueError as error:
            raise HTTPException(409, str(error)) from None
        return automation_status()

    @app.post("/api/automation/enqueue", status_code=202)
    def enqueue_batch(body: EnqueueIn):
        unknown = [a for a in body.alert_ids if not store.get_alert(a)]
        if unknown:
            raise HTTPException(404, "El lote contiene alertas no almacenadas.")
        count = 0
        for alert_id in dict.fromkeys(body.alert_ids):
            row = store.get_alert(alert_id)
            # Explicit batch retry is deliberate; already pending/running jobs are left intact.
            jobs = [j for j in store.jobs() if j["subject"] == alert_id and j["kind"] == "triage"]
            if any(j["status"] in ("pending", "running") for j in jobs):
                continue
            count += store.enqueue("triage", alert_id, "batch:" + uuid.uuid4().hex, priority(row["alert"]), "human")
        store.audit("human", "enqueue_batch", result=count)
        automation.wake.set()
        return {"enqueued": count, "automation_enabled": config.auto_triage}

    return app


app = create_app()
