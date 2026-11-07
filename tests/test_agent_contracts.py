import json
import sys
from pathlib import Path

import jsonschema
import pytest
from pydantic import ValidationError

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from contracts.models import Ticket, TraceEvent  # noqa: E402

CONTEXT_DIR = REPO_ROOT / "data" / "01_contexto"
SCHEMA = json.loads((CONTEXT_DIR / "ticket_salida.schema.json").read_text(encoding="utf-8"))
EXAMPLE = json.loads((CONTEXT_DIR / "ticket_ejemplo.json").read_text(encoding="utf-8"))


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
    event = TraceEvent(run_id="RUN-1", seq=1, at="2026-11-07T10:00:00.000Z", type="ticket_ready", ticket=Ticket.model_validate(EXAMPLE))
    assert set(event.model_dump()) == {"run_id", "seq", "at", "type", "tool", "args", "summary", "event_ids", "truncated", "ticket"}
    with pytest.raises(ValidationError):
        TraceEvent(run_id="RUN-1", seq=1, at="now", type="unknown")
