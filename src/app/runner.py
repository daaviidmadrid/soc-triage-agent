"""The one place where the app gets trace events for an alert.

TRIAGE_MODE=example (the default) replays hand-written example events from
contracts/examples/ with short delays, so the live steps can be seen working.
TRIAGE_MODE=real calls the agent in src/agent/triage.py.

Every event is a dict in the TraceEvent format of contracts/models.py:
run_id, seq, at, type, tool, args, summary, event_ids, truncated, ticket.
The app overwrites run_id and seq with its own when it stores them.
"""
import copy
import hashlib
import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / "contracts" / "examples"
SCENARIOS = ("escalated", "closed_authorised", "needs_more_info", "injection")
DEFAULT_STEP_SECONDS = 0.7
MAX_QUOTA_PAUSE_SECONDS = 4


class TriageUnavailable(RuntimeError):
    """The triage can't run at all. The message is shown to the person as it is."""


def current_mode():
    return (os.environ.get("TRIAGE_MODE") or "example").strip().lower()


def run_triage(alert, mode=None):
    """Takes an alert dict and yields trace events as dicts."""
    mode = mode or current_mode()
    if mode == "example":
        yield from example_events(alert)
    elif mode == "real":
        yield from real_events(alert)
    else:
        raise TriageUnavailable("TRIAGE_MODE no válido. Usa 'example' o 'real'.")


def real_events(alert):
    # Imported here so example mode keeps working when the agent can't be imported.
    try:
        from src.agent.triage import triage
    except ImportError as error:
        raise TriageUnavailable(
            "El agente real no está disponible: no se pudo importar src.agent.triage.triage "
            f"({type(error).__name__}). Arranca sin TRIAGE_MODE para usar los datos de ejemplo."
        ) from None
    calls = []
    try:
        for event in triage(alert, call_log=calls):
            yield _to_dict(event)
    except NotImplementedError:
        raise TriageUnavailable(
            "El agente real aún no está implementado en esta rama: src.agent.triage.triage lanza NotImplementedError. "
            "Arranca sin TRIAGE_MODE para usar los datos de ejemplo."
        ) from None
    finally:
        _write_call_log(alert, calls)


def run_rules(alert, mode=None):
    """Only the fixed rules of src/agent/rules.py, with no LLM. Yields the events of the run if a rule closed the
    alert, and nothing otherwise, so an alert a rule refuses goes on to the LLM with no trace of this pass.
    Example mode has no real rules, so it yields nothing."""
    if (mode or current_mode()) != "real":
        return
    from src.agent.rules import RULES
    from src.agent.triage import triage
    from src.tools.alert_fields import normalise_alert

    if normalise_alert(alert if isinstance(alert, dict) else {})[0].get("rule_id") not in RULES:
        return
    calls = []
    events = [_to_dict(event) for event in triage(alert, call_log=calls, rules_only=True)]
    if events and events[-1].get("type") == "ticket_ready":
        _write_call_log(alert, calls)
        yield from events


def run_investigation(alerts, tickets=(), incident_id=None, others=(), memberships=None):
    """Level 3: yields the trace events of one investigation as dicts. It always uses the real data and LLM,
    because there is no example report: if the LLM fails, the agent still returns a report for a person."""
    try:
        from src.agent.investigate import investigate
    except ImportError as error:
        raise TriageUnavailable(f"La investigación no está disponible: no se pudo importar src.agent.investigate ({type(error).__name__}).") from None
    from src.policy.containment import step_checker
    from src.tools import api_client

    calls = []
    check = step_checker(api_client.get_asset, api_client.get_user)
    try:
        for event in investigate(alerts, tickets=tickets, incident_id=incident_id, others=others, memberships=memberships,
                                 call_log=calls, check_containment=check):
            yield _to_dict(event)
    finally:
        _write_call_log({"alert_id": f"report_{incident_id or 'incidente'}"}, calls)


def call_log_dir():
    return Path(os.environ.get("APP_CALL_LOG_DIR") or ROOT / "runs" / "app_calls")


def _write_call_log(alert, calls):
    """One file per run of the real agent: each prompt, raw answer and reasoning, and what code did with them.
    It never stops a triage: if the file can't be written, the run carries on without it."""
    if not calls:
        return
    alert_id = str(alert.get("alert_id") or "desconocida") if isinstance(alert, dict) else "desconocida"
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    path = call_log_dir() / f"{re.sub(r'[^A-Za-z0-9_-]', '_', alert_id)[:100]}_{stamp}.json"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"alert_id": alert_id, "calls": calls}, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    except OSError:
        pass


def _to_dict(event):
    if hasattr(event, "model_dump"):
        return event.model_dump(mode="json")
    if isinstance(event, dict):
        return event
    raise TypeError("the agent yielded something that isn't a trace event")


def pick_scenario(alert):
    """Chooses an example by a hash of the alert ID, so nothing in the alert's content picks it."""
    alert_id = str(alert.get("alert_id") or "") if isinstance(alert, dict) else ""
    return SCENARIOS[hashlib.sha256(alert_id.encode()).digest()[0] % len(SCENARIOS)]


def load_example(scenario):
    trace = json.loads((EXAMPLES / f"{scenario}.trace.json").read_text(encoding="utf-8"))
    ticket = json.loads((EXAMPLES / f"{scenario}.ticket.json").read_text(encoding="utf-8"))
    return trace, ticket


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def example_events(alert, step_seconds=None, scenario=None):
    """Replays an example run. The example ticket keeps its own fictional alert_ids:
    it is not an analysis of the queued alert."""
    if step_seconds is None:
        step_seconds = float(os.environ.get("EXAMPLE_STEP_SECONDS", DEFAULT_STEP_SECONDS))
    scenario = scenario or pick_scenario(alert)
    trace, ticket = load_example(scenario)
    alert_id = str(alert.get("alert_id") or "desconocida") if isinstance(alert, dict) else "desconocida"
    for seq, template in enumerate(trace["events"], 1):
        time.sleep(step_seconds)
        event = copy.deepcopy(template)
        event.update(run_id="EXAMPLE-RUN", seq=seq, at=_now())
        if event.get("type") == "ticket_ready":
            event["ticket"] = {**copy.deepcopy(ticket), "ticket_id": f"{ticket['ticket_id']}--{alert_id}"}
        yield event
        args = event.get("args") or {}
        if args.get("kind") == "rate_limited" and step_seconds:
            # Lets the "waiting for quota" state be seen in the UI.
            time.sleep(min(float(args.get("wait_seconds") or 0), MAX_QUOTA_PAUSE_SECONDS))
