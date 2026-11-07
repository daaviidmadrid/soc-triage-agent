"""Backend for the UI. Local only: run it with `uvicorn src.app.main:app --port 8001` (binds 127.0.0.1).

Alert and ticket text may be written by attackers. It is stored and returned as plain data,
and nothing here acts on it. The LLM never approves or runs containment. The containment
routes build proposals with plain code (src/policy/containment.py), record each person's
approval, and call the mock only when a person clicks run after every required role has
approved. A person's decision on a ticket is only recorded.
"""
import asyncio
import json
import os
import threading
import time
import uuid
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from src.app import runner
from src.app.import_alerts import MAX_BYTES, ImportProblem, load_alerts, parse_alerts
from src.agent.correlate import correlate
from src.app.store import Store, now_iso
from src.policy.containment import ApprovalProblem, approve, approver_record, propose, ready_to_run
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
    decision: Literal["accept", "close", "escalate"]
    reason: str = Field(default="", max_length=2000)
    run_id: str | None = Field(default=None, max_length=100)


def create_app(db_path=None, sample_path=None, run_fn=None):
    """db_path, sample_path and run_fn are arguments so tests can use a temporary database and fake runs."""
    store = Store(db_path or os.environ.get("APP_DB_PATH") or DEFAULT_DB)
    store.mark_interrupted_runs()
    run_fn = run_fn or runner.run_triage
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

    app = FastAPI(title="Tarvia triage")
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

    @app.get("/api/queue")
    def queue():
        runs = store.latest_runs()
        decisions = store.latest_decisions_by_run()
        incident_of = memberships()
        items = []
        for row in store.list_alerts():
            alert = row["alert"]
            shown = fill_from_catalogue(alert)[0]
            run = runs.get(alert["alert_id"])
            ticket = ticket_summary(store.ticket_for_run(run["run_id"]), run) if run else None
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
            })
        return {
            "mode": runner.current_mode(),
            "sample": sample,
            "alerts": items,
            "example_results": sum(1 for item in items if item["run"] and item["run"]["mode"] == "example"),
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
        pairs = triaged_pairs()
        result = correlate(pairs)
        built_at = store.save_correlation(result)
        return {"built_at": built_at, "alerts": result["alerts"], "incidents": len(result["incidents"]),
                "grouped_alerts": len(result["memberships"])}

    @app.get("/api/incidents")
    def incidents():
        latest = store.latest_correlation()
        triaged = len(triaged_pairs())
        if not latest:
            return {"built_at": None, "incidents": [], "noise": [], "memberships": {}, "alerts": 0, "triaged_now": triaged, "stale": triaged > 0}
        return {**latest, "triaged_now": triaged, "stale": triaged != latest.get("alerts")}

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
        return {
            "format": result["format"],
            "rows": result["rows"],
            "imported": added,
            "skipped": [{"alert_id": alert_id, "reason": "Ya estaba en la cola."} for alert_id in skipped],
            "errors": result["errors"],
        }

    def work(run_id, alert, mode):
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
                    store.save_ticket(ticket, run_id, alert["alert_id"], mode)
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

    @app.post("/api/triage/{alert_id}", status_code=202)
    def run_triage(alert_id: str):
        row = store.get_alert(alert_id)
        if not row:
            raise HTTPException(404, "Alerta no encontrada.")
        active = store.active_run(alert_id)
        if active:
            return {"run_id": active["run_id"], "mode": active["mode"], "status": "running", "already_running": True}
        mode = runner.current_mode()
        run_id = f"RUN-{uuid.uuid4().hex[:12]}"
        store.create_run(run_id, alert_id, mode)
        threading.Thread(target=work, args=(run_id, row["alert"], mode), daemon=True, name=run_id).start()
        return {"run_id": run_id, "mode": mode, "status": "running", "already_running": False}

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
        return store.add_decision(ticket_id, row["run_id"], analyst, body.decision, outcome, reason)

    return app


app = create_app()
