import json
import sys
from pathlib import Path

import jsonschema
import pytest
from pydantic import ValidationError

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from contracts.models import (  # noqa: E402
    ContainmentStep,
    Context,
    IncidentReport,
    Ticket,
    TimelineEvent,
    TraceEvent,
)

CONTEXT_DIR = REPO_ROOT / "data" / "01_contexto"
SCHEMA = json.loads((CONTEXT_DIR / "ticket_salida.schema.json").read_text(encoding="utf-8"))
REPORT_SCHEMA = json.loads((CONTEXT_DIR / "informe_incidente.schema.json").read_text(encoding="utf-8"))
EXAMPLE = json.loads((CONTEXT_DIR / "ticket_ejemplo.json").read_text(encoding="utf-8"))


def test_context_keeps_what_data_sends():
    context = Context(alert={"alert_id": "A"}, logs={"proxy": [{"event_id": "P1"}]}, changes=[{"id": "CHG-1"}])
    dumped = context.model_dump()
    assert dumped["alert"] == {"alert_id": "A"}
    assert dumped["logs"] == {"proxy": [{"event_id": "P1"}]}
    assert dumped["changes"] == [{"id": "CHG-1"}]


def test_context_rejects_a_misspelt_field_instead_of_losing_it():
    with pytest.raises(ValidationError):
        Context(alert={}, logz=[])


def test_deloitte_example_loads_and_stays_valid():
    ticket = Ticket.model_validate(EXAMPLE)
    assert ticket.ticket_id == EXAMPLE["ticket_id"]
    jsonschema.validate(ticket.model_dump(exclude_none=True), SCHEMA)


def test_our_extra_fields_stay_valid_against_the_schema():
    ticket = Ticket.model_validate(
        {
            **EXAMPLE,
            "severity_inputs": {
                "rule_severity": "low",
                "criticality": "Crítica",
                "criticality_source": "asset",
                "adjustments": [{"delta": -1, "reason": "bloqueado"}],
            },
            "injection_flags": [{"event_id": "EVT-1", "description": "texto dirigido al sistema"}],
            "authorised_by": {"type": "change", "id": "CHG-1"},
            "merged_into": "TKT-2",
        }
    )
    jsonschema.validate(ticket.model_dump(exclude_none=True), SCHEMA)


@pytest.mark.parametrize(
    "change",
    [{"verdict": "probably_fine"}, {"severity": "urgent"}, {"confidence": 1.5}, {"escalation": {}}],
)
def test_bad_values_are_rejected(change):
    with pytest.raises(ValidationError):
        Ticket.model_validate({**EXAMPLE, **change})


def test_trace_event_has_the_agreed_fields_and_can_carry_a_ticket():
    event = TraceEvent(
        run_id="RUN-1", seq=1, at="2026-11-07T10:00:00.000Z", type="ticket_ready", ticket=Ticket.model_validate(EXAMPLE)
    )
    assert set(event.model_dump()) == {
        "run_id",
        "seq",
        "at",
        "type",
        "tool",
        "args",
        "summary",
        "event_ids",
        "truncated",
        "ticket",
        "report",
    }
    with pytest.raises(ValidationError):
        TraceEvent(run_id="RUN-1", seq=1, at="now", type="unknown")


def minimal_report(**extra):
    fields = dict(
        incident_id="INC-1",
        title="t",
        alert_ids=["A"],
        patient_zero="p",
        initial_access="i",
        root_cause="r",
        confidence=0.5,
        timeline=[
            TimelineEvent(timestamp="2026-10-07T07:42:00.000Z", event_id="PRX-1", description="d", mitre="T1566")
        ],
        containment_plan=[ContainmentStep(action="revoke_sessions", target="u@x", approver="N2")],
    )
    return IncidentReport(**{**fields, **extra})


def test_incident_report_matches_deloittes_schema():
    report = minimal_report()
    jsonschema.validate(report.model_dump(mode="json", exclude_none=True), REPORT_SCHEMA)
    assert set(REPORT_SCHEMA["required"]) <= set(report.model_dump())
    assert set(REPORT_SCHEMA["properties"]) <= set(report.model_dump())


def test_a_containment_step_can_only_be_a_proposal_that_needs_approval():
    with pytest.raises(ValidationError):
        ContainmentStep(action="isolate_host", target="WS-1", approver="N2", requires_approval=False)
    with pytest.raises(ValidationError):
        ContainmentStep(action="isolate_host", target="WS-1", approver="N2", status="executed")
    with pytest.raises(ValidationError):
        minimal_report(confidence=1.5)


def test_trace_event_can_carry_a_report():
    event = TraceEvent(
        run_id="RUN-1", seq=2, at="2026-11-07T10:00:00.000Z", type="report_ready", report=minimal_report()
    )
    assert event.report.incident_id == "INC-1"
