"""Alerts in shapes we didn't expect: other field names, gaps and odd values."""
import json

import pytest

from src.agent.llm import LLMResult
from src.agent.triage import run_triage
from src.app.import_alerts import ImportProblem, parse_alerts
from src.tools.alert_fields import (
    entities_from_text,
    normalise_alert,
    parse_time,
    rename_fields,
    severity_word,
)
from src.tools.context import build_context

ROW = {"alert_id": "ALR-X-1", "rule_id": "UC-EDR-002", "severity": "medium", "description": "algo"}
TWO = [ROW, {**ROW, "alert_id": "ALR-X-2"}]


def imported(text):
    result = parse_alerts(text.encode("utf-8") if isinstance(text, str) else text)
    return [alert["alert_id"] for alert in result["alerts"]], result


@pytest.mark.parametrize("text", [
    json.dumps(TWO),
    "\n".join(map(json.dumps, TWO)),
    "\r\n".join(map(json.dumps, TWO)),
    "﻿" + json.dumps(TWO),
    json.dumps({"alerts": TWO}),
    json.dumps({"alertas": TWO}),
    json.dumps({"data": TWO}),
    json.dumps({"results": TWO, "total": 2}),
    json.dumps({"hits": {"hits": [{"_source": item} for item in TWO]}}),
    json.dumps({"export": TWO}),
    "\n".join(json.dumps(item, indent=2) for item in TWO),
    ",\n".join(json.dumps(item, indent=2) for item in TWO),
    "```json\n" + json.dumps(TWO) + "\n```",
    json.dumps([{"alert": item} for item in TWO]),
    "alert_id,rule_id,severity\nALR-X-1,UC-EDR-002,medium\nALR-X-2,UC-EDR-002,medium\n",
    "alert_id;rule_id;severity\nALR-X-1;UC-EDR-002;medium\nALR-X-2;UC-EDR-002;medium\n",
    "alert_id\trule_id\nALR-X-1\tUC-EDR-002\nALR-X-2\tUC-EDR-002\n",
    "ID,Regla,Severidad\nALR-X-1,UC-EDR-002,Alta\nALR-X-2,UC-EDR-002,Alta\n",
])
def test_every_shape_gives_the_same_two_alerts(text):
    ids, result = imported(text)
    assert ids == ["ALR-X-1", "ALR-X-2"] and result["errors"] == []


def test_utf16_and_windows_encoded_files_are_read():
    assert imported(json.dumps(TWO).encode("utf-16"))[0] == ["ALR-X-1", "ALR-X-2"]
    assert imported("alert_id;description\nALR-X-1;acción\n".encode("cp1252"))[1]["alerts"][0]["description"] == "acción"


@pytest.mark.parametrize("raw, word", [(b"PK\x03\x04" + bytes(range(200, 250)), "Excel"), (b"%PDF-1.7\n\xe2\xe3", "PDF")])
def test_excel_and_pdf_get_a_clear_message(raw, word):
    with pytest.raises(ImportProblem, match=word):
        parse_alerts(raw)


def test_a_field_with_another_name_is_added_and_the_original_kept():
    _, result = imported(json.dumps([{"id": "A-1", "regla": "UC-EDR-002", "Severidad": "Crítica", "fecha": "08/11/2026 09:00"}]))
    alert = result["alerts"][0]
    assert alert["alert_id"] == "A-1" and alert["rule_id"] == "UC-EDR-002" and alert["severity"] == "critical"
    assert alert["id"] == "A-1" and alert["severity_original"] == "Crítica"


def test_correctly_named_fields_are_left_alone():
    assert rename_fields({"alert_id": "A", "id": "B", "severity": "low", "severidad": "alta"}) == {"alert_id": "A", "id": "B", "severity": "low", "severidad": "alta"}


def test_csv_cells_holding_json_become_data():
    text = 'alert_id;entities;related_events\nA-1;{"hosts": ["WS-1"]};["EDR-0005329"]\n'
    alert = imported(text)[1]["alerts"][0]
    assert alert["entities"] == {"hosts": ["WS-1"]} and alert["related_events"] == ["EDR-0005329"]


def test_a_real_alert_with_no_id_gets_a_stable_one_but_rubbish_doesnt():
    rows = [{"rule_name": "Algo raro", "description": "texto"}, {"version": 1}]
    first, result = imported(json.dumps(rows))
    assert len(first) == 1 and first[0].startswith("IMP-") and [e["row"] for e in result["errors"]] == [2]
    assert imported(json.dumps(rows))[0] == first


def test_spaces_in_an_id_are_tidied_and_a_path_is_refused():
    ids, result = imported(json.dumps([{"alert_id": "ALR 1"}, {"alert_id": "../../x"}]))
    assert ids == ["ALR-1"] and "formato" in result["errors"][0]["error"]


def test_plain_text_is_not_mistaken_for_a_table():
    assert imported("hola, esto no es una alerta\nni esto, tampoco\n")[0] == []


@pytest.mark.parametrize("value, word", [("Alta", "high"), ("CRITICAL", "critical"), ("Crítica", "critical"), ("media", "medium"),
                                         ("Info", "informational"), ("baja", "low"), ("3", None), (None, None), (3, None)])
def test_severity_words(value, word):
    assert severity_word(value) == word


def test_missing_details_come_from_the_catalogue_and_are_mentioned():
    alert, notes = normalise_alert({"alert_id": "A", "rule_id": "UC-EDR-002", "created_at": "2026-10-05T07:56:30.000Z", "entities": {"hosts": ["WS-1"]}})
    assert alert["severity"] == "medium" and alert["runbook"] == "RB-02" and alert["rule_name"] and alert["source_product"] == "EDR"
    assert len(notes) == 1 and "catálogo" in notes[0]


def test_a_rule_can_be_found_by_its_exact_name():
    alert, _ = normalise_alert({"alert_id": "A", "rule_name": "PowerShell con comando codificado"})
    assert alert["rule_id"] == "UC-EDR-002"


def test_a_dataset_alert_needs_no_assumptions():
    alert = {"alert_id": "A", "rule_id": "UC-EDR-002", "severity": "high", "runbook": "RB-02", "created_at": "2026-10-05T07:56:30.000Z",
             "entities": {"hosts": [{"hostname": "WS-1"}]}, "related_events": ["EDR-1"]}
    clean, notes = normalise_alert(alert)
    assert notes == [] and {key: clean[key] for key in alert} == alert


def test_an_unrecognised_severity_is_never_silently_lowered():
    alert, notes = normalise_alert({"alert_id": "A", "rule_id": "UC-EDR-004", "severity": "P1"})
    assert alert["severity"] == "critical"
    assert any("catálogo" in note for note in notes)


def test_an_unknown_rule_and_severity_say_what_was_assumed():
    alert, notes = normalise_alert({"alert_id": "A", "rule_id": "UC-NEW-9"})
    assert alert["severity"] == "medium"
    assert any("se asume medium" in note for note in notes) and any("todas las fuentes" in note for note in notes)


@pytest.mark.parametrize("value, expected, assumed", [
    ("2026-11-08T09:00:00.000Z", "2026-11-08T09:00:00.000Z", False),
    ("2026-11-08T10:00:00+01:00", "2026-11-08T09:00:00.000Z", False),
    ("2026-11-08 09:00:00", "2026-11-08T09:00:00.000Z", True),
    ("08/11/2026 09:00", "2026-11-08T09:00:00.000Z", True),
    (1794128400, "2026-11-08T09:00:00.000Z", False),
    (1794128400000, "2026-11-08T09:00:00.000Z", False),
    ("1794128400", "2026-11-08T09:00:00.000Z", False),
    ("ayer por la tarde", None, False),
    (None, None, False),
])
def test_times_in_other_formats(value, expected, assumed):
    assert parse_time(value) == (expected, assumed)


def test_entities_are_found_in_text_when_none_are_given():
    alert = {"alert_id": "A", "description": "Login de ana@tarvia.example en WS-BCN-1174 (FS01) desde 203.0.113.45, ver CHG-2026-1031, UC-EDR-002 y EDR-0005329."}
    found = entities_from_text(alert)
    assert found["users"] == [{"upn": "ana@tarvia.example"}] and found["ips"] == ["203.0.113.45"]
    assert [item["hostname"] for item in found["hosts"]] == ["WS-BCN-1174", "FS01"]


def test_related_events_in_other_shapes():
    assert normalise_alert({"related_events": "EDR-0005329; PRX-0145144"})[0]["related_events"] == ["EDR-0005329", "PRX-0145144"]
    assert normalise_alert({"related_events": [{"event_id": "EDR-0005329"}, 7]})[0]["related_events"] == ["EDR-0005329"]
    assert normalise_alert({"related_events": 7})[0]["related_events"] == []


# With the real mock API and a fake model

def fake_llm(**answer):
    text = json.dumps({"title": "t", "verdict": "false_positive", "confidence": 0.9, "summary": "s", "evidence": [{"source": "alert", "finding": "f"}], **answer})
    return lambda system, user: LLMResult(text=text, model="fake")


BASE = {"alert_id": "TEST-1", "created_at": "2026-10-05T07:56:30.000Z", "source_product": "EDR", "rule_id": "UC-EDR-002", "rule_name": "PowerShell con comando codificado",
        "severity": "medium", "description": "Ejecución de PowerShell.", "entities": {"hosts": [{"hostname": "WS-BCN-1174", "ip": "10.10.1.185"}]},
        "related_events": ["EDR-0005329"], "runbook": "RB-02"}


@pytest.mark.parametrize("changes", [
    {}, {"related_events": None}, {"related_events": ["EDR-9999999", "NEW-0000001"]}, {"created_at": "2026-11-08T08:00:00Z"},
    {"created_at": "08/11/2026 09:00"}, {"created_at": None}, {"created_at": "2026-11-08 09:00:00"}, {"rule_id": "UC-NEW-999"}, {"rule_id": None, "rule_name": None},
    {"runbook": None}, {"severity": None}, {"severity": "Alta"}, {"entities": None}, {"entities": ["WS-BCN-1174", "x"]},
    {"entities": {"hosts": [{"hostname": "WS-NUEVO-1", "ip": "10.99.99.99"}], "users": [{"upn": "nadie@tarvia.example"}]}},
])
def test_triage_always_gives_a_ticket(changes):
    ticket, events = run_triage({**BASE, **changes}, llm=fake_llm())
    assert ticket.alert_ids == ["TEST-1"]
    assert not [event for event in events if event.type == "error"]


def test_entities_written_only_in_the_text_still_find_logs():
    alert = {"alert_id": "TEST-2", "created_at": "2026-10-05T07:56:30.000Z", "rule_id": "UC-EDR-002", "description": "Algo en WS-BCN-1174"}
    rows = sum(len(items) for items in build_context(normalise_alert(alert)[0]).logs.values())
    assert rows > 0


def test_an_unknown_rule_searches_every_log():
    alert = {**BASE, "rule_id": "UC-NEW-999", "related_events": [], "created_at": "2026-10-05T07:56:30.000Z"}
    known = {source for source in build_context({**BASE, "related_events": []}).logs}
    assert known <= {source for source in build_context(alert).logs}


def test_a_critical_alert_with_no_data_cant_be_closed():
    ticket, _ = run_triage({"alert_id": "TEST-3", "severity": "Crítica"}, llm=fake_llm())
    assert ticket.verdict == "needs_more_info" and ticket.escalation.escalate is True and ticket.severity == "critical"
    assert any("ningún log" in question for question in ticket.open_questions)


def test_only_an_id_cant_be_closed():
    ticket, _ = run_triage({"alert_id": "TEST-4"}, llm=fake_llm())
    assert ticket.verdict == "needs_more_info" and ticket.escalation.escalate is True


def test_the_ticket_lists_what_was_assumed():
    ticket, events = run_triage({"alert_id": "TEST-5", "rule_id": "UC-NEW-999"}, llm=fake_llm())
    assert any("se asume medium" in question for question in ticket.open_questions)
    assert any(event.type == "note" and "se asume medium" in event.summary for event in events)
