"""Turns one alert into a ticket. The final event carries the ticket. Branch: agent/triage

The LLM only proposes. Plain code here checks the answer, computes the final severity,
applies the mandatory escalation rules and decides whether a ticket can close.
"""
import json
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Iterator, Literal

from pydantic import BaseModel, Field, ValidationError

from contracts.models import (
    Adjustment,
    Affected,
    AuthorisedBy,
    Enrichment,
    Escalation,
    Evidence,
    InjectionFlag,
    RecommendedAction,
    SeverityInputs,
    Ticket,
    TraceEvent,
    Verdict,
)
from src.agent.llm import LLMBlocked, LLMError, LLMQuotaExhausted, complete
from src.agent.prompts import LOG_SOURCES, PROMPT_VERSION, build_prompt_with_info, context_to_dict
from src.policy.severity import compute_severity as default_compute_severity
from src.tools.alert_fields import normalise_alert
from src.tools.context import build_context as default_build_context
from src.tools.logs import search_logs as default_search_logs

# One to answer, one for an extra log search and one to correct a rejected answer.
MAX_LLM_CALLS = 3

SEVERITIES = ("informational", "low", "medium", "high", "critical")
DEFAULT_RULE_SEVERITY = "medium"
DEFAULT_CRITICALITY = "Media"

# Analysis section 6: only the IBAN case in RB-01 states a severity for a rule. Other runbook severities describe outcomes.
RUNBOOK_FLOORS = {"UC-EML-004": "critical"}

# Analysis section 8: a change or flow that code matched, or a notified trip whose dates cover the event. Data only puts rows here that fit.
AUTHORISATION_SECTIONS = ("changes", "trips")

TRUNCATED_QUESTION = "Algunos resultados de log estaban truncados ({sources}): la evidencia puede estar incompleta."
# Analysis section 4: logs come oldest first, so a limit removes the later rows, and rows cut to fit a prompt are lost too.
# Incomplete evidence can't show that nothing happened afterwards, which the -1 requires. It can still support a +1.
NO_LOWERING_QUESTION = "No se aplicó el −1: la evidencia está incompleta y no descarta actividad posterior."

# Text in an alert can be written by an attacker, so it can't be the only basis for closing.
NO_DATA_QUESTION = "No se ha encontrado ningún log de esta alerta: no se puede cerrar como falso positivo sin datos."
UNSUPPORTED_QUESTION = "Falso positivo de severidad {severity} sin ningún evento citado: no se puede cerrar solo con el texto de la alerta."

# Sources that have no event ID, so evidence from them can leave event_id empty.
NO_EVENT_ID_SOURCES = {"alert", "users", "assets", "changes", "trips", "hr_events", "intel", "sandbox"}

# The model writes action names freely, for example "Cerrar alerta". Only code decides whether to close or escalate.
DECISION_ACTION = re.compile(r"\s*(close|closing|cerrar|cierre|escalate|escalation|escalar|escalado)\b", re.IGNORECASE)

# Section 5 of the policy. The chain-of-alerts rule needs grouping, so it can't apply until level 2.
MANDATORY_FLAGS = {
    "confirmed_malicious_execution": "Ejecución confirmada de código malicioso",
    "credential_theft": "Robo de credenciales",
    "persistence": "Persistencia",
    "personal_data_exposure": "Datos personales que han podido salir de la organización (implica al DPO)",
    "economic_fraud": "Fraude económico",
}


class PolicyFlags(BaseModel):
    confirmed_malicious_execution: bool = False
    credential_theft: bool = False
    persistence: bool = False
    personal_data_exposure: bool = False
    economic_fraud: bool = False


class ProposedAction(BaseModel):
    action: str = ""
    target: str = ""
    justification: str = ""


class TicketDraft(BaseModel):
    """What the LLM may write. Anything else it sends, such as severity or ticket_id, is ignored."""

    title: str = Field(min_length=1)
    verdict: Verdict
    confidence: float = Field(ge=0, le=1)
    summary: str = Field(min_length=1)
    evidence: list[Evidence] = Field(default_factory=list)
    enrichment: list[Enrichment] = Field(default_factory=list)
    mitre: list[str] = Field(default_factory=list)
    affected: Affected = Field(default_factory=Affected)
    severity_adjustments: list[Adjustment] = Field(default_factory=list)
    policy_flags: PolicyFlags = Field(default_factory=PolicyFlags)
    escalate: bool = False
    escalation_reason: str = ""
    authorised_by: AuthorisedBy | None = None
    injection_flags: list[InjectionFlag] = Field(default_factory=list)
    recommended_actions: list[ProposedAction] = Field(default_factory=list)
    open_questions: list[str] = Field(default_factory=list)


class SearchRequest(BaseModel):
    action: Literal["search_logs"]
    source: str
    user: str | None = None
    ip: str | None = None
    host: str | None = None
    value: str | None = None
    desde: str | None = None
    hasta: str | None = None
    reason: str = ""


def parse_answer(text, can_search):
    """Returns (TicketDraft or SearchRequest or None, errors). Errors never repeat values from the answer."""
    cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", text.strip())
    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError:
        return None, ["It wasn't valid JSON."]
    if not isinstance(data, dict):
        return None, ["It wasn't a JSON object."]
    try:
        if data.get("action") != "search_logs":
            return TicketDraft.model_validate(data), []
        request = SearchRequest.model_validate(data)
    except ValidationError as error:
        fields = sorted({str(item["loc"][0]) for item in error.errors() if item["loc"]})
        return None, [f"These fields were missing or invalid: {', '.join(fields)}."]
    if not can_search:
        return None, ["No more log searches are available."]
    if request.source not in LOG_SOURCES:
        return None, ["The log search named an unknown source."]
    if not any((request.user, request.ip, request.host, request.value)):
        return None, ["The log search had no user, ip, host or value."]
    return request, []


def retrieved_ids(context):
    """Every ID the system really retrieved: event IDs in the context, change IDs and the alert itself."""
    ids = set()

    def walk(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key == "event_id" and isinstance(item, str) and item:
                    ids.add(item)
                else:
                    walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(context)
    ids |= _authorising_ids(context)
    alert = context.get("alert")
    if isinstance(alert, dict) and alert.get("alert_id"):
        ids.add(alert["alert_id"])
    return ids


def check_evidence(draft, ids):
    errors = []
    if draft.verdict != "needs_more_info" and not draft.evidence:
        errors.append("This verdict needs evidence.")
    if any(item.event_id and item.event_id not in ids for item in draft.evidence):
        errors.append("It cited event IDs that aren't in the data.")
    if any(not item.event_id and item.source not in NO_EVENT_ID_SOURCES for item in draft.evidence):
        errors.append("It had log evidence with no event ID.")
    return errors


def check_authorisation(draft, context):
    """Gives the model a chance to correct a claim of authorisation that nothing backs up."""
    if draft.verdict != "benign_true_positive":
        return []
    if draft.authorised_by and draft.authorised_by.id in _authorising_ids(context):
        return []
    return ["benign_true_positive needs an authorised_by id copied from the changes or trips list, and this answer has none that is there. "
            "Harmless isn't authorised: choose true_positive, false_positive or needs_more_info instead."]


def _authorising_ids(context):
    ids = set()
    for section in AUTHORISATION_SECTIONS:
        for row in context.get(section) or []:
            if isinstance(row, dict) and row.get("id"):
                ids.add(str(row["id"]))
    return ids


def mandatory_escalation_reasons(verdict, severity, flags):
    reasons = []
    if verdict == "true_positive" and severity in ("high", "critical"):
        reasons.append(f"true_positive de severidad {severity}")
    reasons.extend(text for flag, text in MANDATORY_FLAGS.items() if getattr(flags, flag))
    return reasons


def _read_severity(result):
    """compute_severity lives on the data branch, so this accepts a string, a dict or an object."""
    if isinstance(result, str):
        return result, ""
    get = result.get if isinstance(result, dict) else lambda key: getattr(result, key, None)
    final = next((get(key) for key in ("final", "final_severity", "severity") if get(key)), None)
    if final not in SEVERITIES:
        raise ValueError("compute_severity returned no valid severity")
    return final, str(get("reason") or get("rationale") or "")


def _final_severity(compute, rule, criticality, adjustments, floor, authorised):
    """Returns (severity, note, problem). If compute_severity fails, the rule's severity stands, raised to any floor."""
    try:
        final, note = _read_severity(
            compute(rule, criticality, adjustments=[a.model_dump() for a in adjustments], runbook_floor=floor, authorised=authorised)
        )
        return final, note, None
    except Exception as error:
        problem = "no disponible" if isinstance(error, NotImplementedError) else f"falló ({type(error).__name__})"
        final = max(rule, floor or rule, key=SEVERITIES.index)
        return final, "", f"El cálculo de severidad {problem}: se mantiene la severidad de la regla."


def _rule_severity(alert):
    value = alert.get("severity")
    return value if value in SEVERITIES else DEFAULT_RULE_SEVERITY


def _escalation_target(verdict, severity):
    if severity == "critical":
        return "N2 de guardia (teléfono)"
    if verdict == "needs_more_info" and severity != "high":
        return "Analista SOC (revisión humana)"
    return "N2"


def _final_actions(proposed, escalate, target, reason):
    """Whether to close or escalate is decided here. The LLM's other suggestions stay as suggestions."""
    decision = (
        RecommendedAction(action="escalate", target=target, requires_approval=False, justification=reason)
        if escalate
        else RecommendedAction(action="close", target="ticket", requires_approval=False, justification=reason)
    )
    actions = [decision]
    for item in proposed:
        name = item.action.strip()
        if not name or DECISION_ACTION.match(name):
            continue
        actions.append(RecommendedAction(action=name, target=item.target or "ticket", requires_approval=True, justification=item.justification))
    return actions


def _has_log_rows(context):
    return any(_log_groups(context.get("logs")).values()) or bool(context.get("extra_logs"))


def build_ticket(alert, context, draft, compute, seconds, assumptions=()):
    """Returns (ticket, notes). This is where plain code overrides the LLM."""
    notes = []
    questions = [*assumptions, *draft.open_questions]
    verdict = draft.verdict
    authorised_by = None

    def override(question):
        questions.append(question)
        notes.append(question)
        return "needs_more_info"

    if verdict == "benign_true_positive":
        cited = draft.authorised_by.id if draft.authorised_by else ""
        if cited in _authorising_ids(context):
            authorised_by = draft.authorised_by
        else:
            verdict = override("Se propuso actividad autorizada sin un cambio aprobado que exista en el calendario de cambios.")
    if verdict == "false_positive" and not _has_log_rows(context):
        verdict = override(NO_DATA_QUESTION)

    # An unresolved ticket can't have its severity lowered by the LLM, and neither can incomplete evidence.
    incomplete = bool(context.get("truncated_sources") or context.get("trimmed_for_prompt"))
    rule_id = alert.get("rule_id")
    rule = _rule_severity(alert)
    criticality = context.get("criticality") or DEFAULT_CRITICALITY
    source = context.get("criticality_source") or "default"

    def severity_for(current):
        can_lower = current != "needs_more_info" and not incomplete
        kept = [a for a in draft.severity_adjustments if can_lower or a.delta > 0]
        floor = RUNBOOK_FLOORS.get(rule_id) if current in ("true_positive", "needs_more_info") else None
        return kept, floor, _final_severity(compute, rule, criticality, kept, floor, current == "benign_true_positive")

    adjustments, floor, (severity, severity_note, problem) = severity_for(verdict)
    if verdict == "false_positive" and severity in ("high", "critical") and not any(item.event_id for item in draft.evidence):
        verdict = override(UNSUPPORTED_QUESTION.format(severity=severity))
        adjustments, floor, (severity, severity_note, problem) = severity_for(verdict)
    authorised = verdict == "benign_true_positive"
    if incomplete and any(a.delta < 0 for a in draft.severity_adjustments):
        questions.append(NO_LOWERING_QUESTION)
        notes.append(NO_LOWERING_QUESTION)
    if problem:
        questions.append(problem)
        notes.append(problem)

    ids = retrieved_ids(context)
    flags = [
        InjectionFlag(event_id=item.event_id if item.event_id in ids else "", description=item.description[:300])
        for item in draft.injection_flags
        if item.description.strip()
    ]

    reasons = mandatory_escalation_reasons(verdict, severity, draft.policy_flags)
    if reasons and not draft.escalate:
        notes.append("Escalado obligatorio aplicado por la política: " + "; ".join(reasons))
    if verdict == "needs_more_info":
        reasons.append("Evidencia insuficiente: debe revisarlo una persona")
    if flags and verdict != "true_positive":
        reasons.append("Hay texto que intenta influir en el triaje: debe revisarlo una persona")
    escalate = draft.escalate or bool(reasons)
    reason = "; ".join(item for item in (draft.escalation_reason, *reasons) if item)

    truncated = context.get("truncated_sources")
    if truncated:
        questions.append(TRUNCATED_QUESTION.format(sources=", ".join(map(str, truncated))))
    if context.get("trimmed_for_prompt"):
        questions.append("Parte del contexto no cupo en el prompt: el modelo no vio toda la evidencia.")

    target = _escalation_target(verdict, severity) if escalate else ""
    rationale = f"Regla {rule} con criticidad {criticality} ({source}): resultado {severity}."
    if severity_note:
        rationale += f" {severity_note}"

    ticket = Ticket(
        ticket_id=_ticket_id(alert),
        alert_ids=[_alert_id(alert)],
        title=draft.title,
        verdict=verdict,
        confidence=draft.confidence,
        severity=severity,
        severity_rationale=rationale,
        affected=draft.affected,
        summary=draft.summary,
        evidence=draft.evidence,
        enrichment=[item for item in draft.enrichment if item.indicator],
        mitre=draft.mitre,
        recommended_actions=_final_actions(draft.recommended_actions, escalate, target, reason or draft.summary[:200]),
        executed_actions=[],
        escalation=Escalation(escalate=escalate, to=target, reason=reason),
        open_questions=questions,
        triage_seconds=seconds,
        severity_inputs=SeverityInputs(
            rule_severity=rule,
            criticality=criticality,
            criticality_source=source,
            adjustments=adjustments,
            runbook_floor=floor,
            authorised=authorised,
        ),
        injection_flags=flags,
        authorised_by=authorised_by,
    )
    return ticket, notes


def failsafe_ticket(alert, context, reason, compute, seconds, assumptions=()):
    """Used when the triage couldn't finish. It stays open for a person and can never close."""
    context = context or {}
    rule = _rule_severity(alert)
    criticality = context.get("criticality") or DEFAULT_CRITICALITY
    source = context.get("criticality_source") or "default"
    floor = RUNBOOK_FLOORS.get(alert.get("rule_id"))
    severity, _, problem = _final_severity(compute, rule, criticality, [], floor, False)
    target = _escalation_target("needs_more_info", severity)
    return Ticket(
        ticket_id=_ticket_id(alert),
        alert_ids=[_alert_id(alert)],
        title=f"Triaje automático sin completar: {alert.get('rule_name') or _alert_id(alert)}",
        verdict="needs_more_info",
        confidence=0.0,
        severity=severity,
        severity_rationale=f"Regla {rule} con criticidad {criticality} ({source}): resultado {severity}. Sin ajustes.",
        summary=f"El sistema no pudo completar el triaje: {reason} Debe revisarlo una persona.",
        evidence=[],
        recommended_actions=_final_actions([], True, target, reason),
        escalation=Escalation(escalate=True, to=target, reason=reason),
        open_questions=[item for item in (reason, problem, *assumptions) if item],
        triage_seconds=seconds,
        severity_inputs=SeverityInputs(rule_severity=rule, criticality=criticality, criticality_source=source, runbook_floor=floor),
    )


def _alert_id(alert):
    return str(alert.get("alert_id") or "desconocida")


def _ticket_id(alert):
    return f"TKT-{_alert_id(alert)}"


def _rows_from(result):
    """search_logs lives on the data branch, so this accepts a list, a dict or an object."""
    if isinstance(result, list):
        return result, False
    get = result.get if isinstance(result, dict) else lambda key, default=None: getattr(result, key, default)
    rows = next((get(key) for key in ("items", "rows", "logs") if get(key) is not None), [])
    return list(rows), bool(get("truncated", False))


def _row_ids(rows):
    return [row["event_id"] for row in rows if isinstance(row, dict) and row.get("event_id")]


def _log_groups(logs):
    if isinstance(logs, dict):
        return {str(key): value for key, value in logs.items() if isinstance(value, list)}
    groups = {}
    for row in logs or []:
        groups.setdefault(row.get("source", "logs") if isinstance(row, dict) else "logs", []).append(row)
    return groups


class _Trace:
    def __init__(self):
        self.run_id = f"RUN-{uuid.uuid4().hex[:8]}"
        self.seq = 0

    def __call__(self, type, **fields):
        self.seq += 1
        at = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        return TraceEvent(run_id=self.run_id, seq=self.seq, at=at, type=type, **fields)


def _gather(alert, build, emit):
    """One event per lookup, built from counts and IDs only, so no text from the data reaches the trace."""
    yield emit("tool_call", tool="build_context", args={"alert_id": _alert_id(alert)}, summary="Reuniendo el contexto de la alerta")
    context = context_to_dict(build(alert))
    context.setdefault("alert", alert)
    for section in ("users", "assets", "changes", "trips", "hr_events", "intel", "sandbox"):
        items = context.get(section)
        if items:
            yield emit("tool_result", tool=section, summary=f"{len(items)} resultado(s)")
    truncated = context.get("truncated_sources") or []
    for source, rows in _log_groups(context.get("logs")).items():
        yield emit(
            "tool_result",
            tool="search_logs",
            args={"source": source},
            summary=f"{len(rows)} fila(s) de {source}",
            event_ids=_row_ids(rows),
            truncated=source in truncated,
        )
    return context


def _extra_search(request, context, search, emit):
    args = request.model_dump(exclude={"action", "reason"}, exclude_none=True)
    yield emit("tool_call", tool="search_logs", args=args, summary="Búsqueda adicional pedida por el modelo")
    try:
        rows, truncated = _rows_from(search(**args))
    except Exception as error:
        context["extra_search"] = "not available"
        yield emit("tool_result", tool="search_logs", args=args, summary=f"La búsqueda no está disponible ({type(error).__name__})")
        return
    context.setdefault("extra_logs", []).extend(rows)
    context["extra_search"] = "done"
    if truncated:
        context["truncated_sources"] = [*(context.get("truncated_sources") or []), request.source]
    yield emit("tool_result", tool="search_logs", args=args, summary=f"{len(rows)} fila(s) de {request.source}", event_ids=_row_ids(rows), truncated=truncated)


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _record(call_log, **entry):
    if call_log is not None:
        call_log.append({"at": _now(), **entry})


def _ask_llm(context, llm, search, emit, max_calls, call_log=None):
    """Returns a checked draft, or None. The extra search and the retry share the same call limit.

    A claim of authorisation the model never corrects still comes back, and build_ticket turns it into needs_more_info.
    If call_log is a list, each call is added to it: the prompt, the raw answer, the reasoning and what code did with it."""
    calls = 0
    feedback = None
    unauthorised = None
    last_system = None
    while calls < max_calls:
        can_search = calls == 0 and max_calls > 1
        system, user, omitted = build_prompt_with_info(context, allow_search=can_search, feedback=feedback)
        if omitted and calls == 0:
            yield emit("note", args={"omitted": omitted}, summary="Parte del contexto no cabe en el prompt")
            context["trimmed_for_prompt"] = omitted
        calls += 1
        yield emit("tool_call", tool="llm", args={"call": calls}, summary="Consultando al modelo")
        started = time.monotonic()
        # The system prompt is the same on every call for an alert, so the log keeps it once.
        prompt = {"system": system if system != last_system else "(same as the previous call)", "user": user, "omitted": omitted or {}}
        last_system = system
        try:
            result = llm(system, user)
        except Exception as error:
            _record(call_log, kind="llm_call", call=calls, prompt_version=PROMPT_VERSION, **prompt, outcome="failed",
                    error=f"{type(error).__name__}: {str(error)[:300]}", seconds=round(time.monotonic() - started, 2))
            raise
        yield emit(
            "tool_result",
            tool="llm",
            args={
                "call": calls,
                "model": result.model,
                "prompt_tokens": result.prompt_tokens,
                "completion_tokens": result.completion_tokens,
                "attempts": result.attempts,
                "seconds": round(time.monotonic() - started, 2),
            },
            summary=f"Respuesta de {result.model}",
        )
        answer, errors = parse_answer(result.text, can_search)
        log_entry = dict(kind="llm_call", call=calls, prompt_version=PROMPT_VERSION, **prompt, model=result.model, attempts=result.attempts,
                         prompt_tokens=result.prompt_tokens, completion_tokens=result.completion_tokens,
                         seconds=round(time.monotonic() - started, 2), answer=result.text, reasoning=getattr(result, "reasoning", "") or "")
        if isinstance(answer, SearchRequest):
            _record(call_log, **log_entry, outcome="asked for a log search", errors=[])
            yield from _extra_search(answer, context, search, emit)
            feedback = None
            continue
        if not errors:
            errors = check_evidence(answer, retrieved_ids(context))
        if not errors:
            errors = check_authorisation(answer, context)
            unauthorised = answer if errors else unauthorised
        _record(call_log, **log_entry, outcome="rejected by code" if errors else "accepted", errors=errors)
        if not errors:
            return answer
        feedback = errors
        yield emit("note", tool="llm", args={"call": calls}, summary="La respuesta no pasó las comprobaciones: " + " ".join(errors))
    return unauthorised


def triage(alert: dict, *, build_context=None, compute_severity=None, search_logs=None, llm=None, max_llm_calls=MAX_LLM_CALLS, call_log=None) -> Iterator[TraceEvent]:
    """The data functions are arguments because the data branch may not be merged yet, and tests need fakes.

    call_log, if given, is a list that receives every model call and what code decided. It holds prompts and data
    text, so it is kept apart from the trace the UI shows, and nothing in it is ever sent back to the model."""
    build = build_context or default_build_context
    compute = compute_severity or default_compute_severity
    search = search_logs or default_search_logs
    ask = llm or complete
    alert, assumptions = normalise_alert(alert if isinstance(alert, dict) else {})
    emit = _Trace()
    started = time.monotonic()
    context = None

    def seconds():
        return round(time.monotonic() - started, 2)

    def finish(ticket):
        event_ids = [item.event_id for item in ticket.evidence if item.event_id]
        return emit("ticket_ready", summary=f"{ticket.verdict}, severidad {ticket.severity}", event_ids=event_ids, ticket=ticket)

    def fail(reason):
        ticket = failsafe_ticket(alert, context, reason, compute, seconds(), assumptions)
        _record(call_log, kind="result", outcome="triage failed and went to a person", reason=reason, verdict=ticket.verdict, severity=ticket.severity)
        return finish(ticket)

    yield emit("started", args={"alert_id": _alert_id(alert)}, summary=f"Triaje de {_alert_id(alert)}")
    for assumption in assumptions:
        yield emit("note", summary=assumption)
    try:
        context = yield from _gather(alert, build, emit)
        if assumptions:
            context["data_gaps"] = list(assumptions)
    except Exception as error:
        problem = "no está disponible" if isinstance(error, NotImplementedError) else f"falló ({type(error).__name__})"
        yield emit("error", tool="build_context", args={"kind": "context"}, summary=f"El contexto {problem}")
        yield fail(f"No se pudo reunir el contexto de la alerta: {problem}.")
        return
    try:
        draft = yield from _ask_llm(context, ask, search, emit, max_llm_calls, call_log)
    except LLMBlocked as error:
        yield emit("error", tool="llm", args={"kind": "blocked", "attempts": error.attempts}, summary=str(error))
        yield fail("El proveedor del LLM bloqueó la llamada.")
        return
    except LLMQuotaExhausted as error:
        yield emit("error", tool="llm", args={"kind": "quota", "attempts": error.attempts}, summary=str(error))
        yield fail("Se ha agotado el límite diario del LLM.")
        return
    except LLMError as error:
        yield emit("error", tool="llm", args={"kind": "unavailable", "attempts": error.attempts}, summary=str(error))
        yield fail("El LLM no está disponible.")
        return
    except Exception as error:
        yield emit("error", tool="llm", args={"kind": "internal"}, summary=f"Error interno ({type(error).__name__})")
        yield fail("Error interno durante el triaje.")
        return
    if draft is None:
        yield fail("El modelo no dio una respuesta que pasara las comprobaciones.")
        return
    ticket, notes = build_ticket(alert, context, draft, compute, seconds(), assumptions)
    _record(call_log, kind="result", outcome="ticket", model_verdict=draft.verdict, verdict=ticket.verdict, severity=ticket.severity,
            escalate=ticket.escalation.escalate, code_changes=notes, assumptions=list(assumptions))
    for note in notes:
        yield emit("note", summary=note)
    yield finish(ticket)


def run_triage(alert: dict, **options):
    """Runs the whole triage. Returns (ticket, events)."""
    events = list(triage(alert, **options))
    return events[-1].ticket, events
