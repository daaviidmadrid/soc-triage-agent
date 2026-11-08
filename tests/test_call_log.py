"""The call log: every prompt, raw answer and reasoning, and what code did with them, kept apart from the trace."""

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from src.agent import llm as llm_module
from src.agent.batch import run_batch
from src.agent.llm import LLMResult, LLMUnavailable, complete
from src.agent.prompts import PROMPT_VERSION
from src.agent.triage import run_triage
from src.app import runner

ROOT = Path(__file__).resolve().parents[1]
# A detection rule with no fixed rule in src/agent/rules.py, so these alerts always reach the model.
ALERT = {
    "alert_id": "ALR-LOG-1",
    "rule_id": "UC-EDR-001",
    "severity": "medium",
    "created_at": "2026-10-05T07:56:30.000Z",
    "entities": {"hosts": [{"hostname": "WS-1"}]},
    "related_events": ["EVT-1"],
    "runbook": "RB-02",
}
CONTEXT = {
    "alert": ALERT,
    "criticality": "Media",
    "criticality_source": "asset",
    "users": [],
    "assets": [],
    "changes": [],
    "logs": [{"source": "proxy", "event_id": "EVT-1", "text": "fila"}],
    "truncated_sources": [],
}
GOOD = {
    "title": "t",
    "verdict": "true_positive",
    "confidence": 0.9,
    "summary": "s",
    "evidence": [{"source": "proxy", "event_id": "EVT-1", "finding": "f"}],
}


class ScriptedLLM:
    def __init__(self, *answers):
        self.answers = list(answers)

    def __call__(self, system, user):
        item = self.answers.pop(0)
        if isinstance(item, Exception):
            raise item
        text = item if isinstance(item, str) else json.dumps(item)
        return LLMResult(
            text=text, model="fake-model", prompt_tokens=100, completion_tokens=20, reasoning="pensando en voz alta"
        )


def triage_with_log(*answers, **options):
    calls = []
    options.setdefault("compute_severity", lambda *a, **k: {"final": "medium", "reason": "prueba"})
    options.setdefault("search_logs", lambda **a: [{"event_id": "EVT-9"}])
    ticket, events = run_triage(
        ALERT, build_context=lambda _alert: dict(CONTEXT), llm=ScriptedLLM(*answers), call_log=calls, **options
    )
    return ticket, events, calls


def test_an_accepted_answer_is_logged_with_its_prompt_answer_and_reasoning():
    ticket, _, calls = triage_with_log(GOOD)
    call, result = calls
    assert call["kind"] == "llm_call" and call["outcome"] == "accepted" and call["errors"] == []
    assert call["prompt_version"] == PROMPT_VERSION and call["model"] == "fake-model"
    assert "level 1 analyst" in call["system"] and "<untrusted_data>" in call["user"]
    assert json.loads(call["answer"])["verdict"] == "true_positive" and call["reasoning"] == "pensando en voz alta"
    assert (
        result["kind"] == "result"
        and result["model_verdict"] == "true_positive"
        and result["verdict"] == ticket.verdict
    )


def test_a_rejected_answer_and_its_reason_are_logged_and_the_system_prompt_kept_once():
    _, _, calls = triage_with_log("not json", "still not json", GOOD)
    first, second, third, _ = calls
    assert first["outcome"] == "rejected by code" and first["errors"] and first["answer"] == "not json"
    assert second["outcome"] == "rejected by code" and "rejected" in second["user"]
    # The first call may ask for a log search and later ones may not, so their system prompts differ.
    assert "No more log searches" in second["system"] and third["system"] == "(same as the previous call)"
    assert third["outcome"] == "accepted"


def test_a_log_search_request_is_logged():
    _, _, calls = triage_with_log({"action": "search_logs", "source": "proxy", "value": "x"}, GOOD)
    assert [entry.get("outcome") for entry in calls] == ["asked for a log search", "accepted", "ticket"]


def test_code_overriding_the_model_is_logged():
    _, _, calls = triage_with_log(*[{**GOOD, "verdict": "benign_true_positive"}] * 3)
    assert calls[-1]["model_verdict"] == "benign_true_positive" and calls[-1]["verdict"] == "needs_more_info"
    assert calls[-1]["code_changes"]


def test_a_failed_call_is_logged_and_the_failsafe_too():
    _, _, calls = triage_with_log(LLMUnavailable("down", attempts=2))
    assert calls[0]["outcome"] == "failed" and "down" in calls[0]["error"]
    assert calls[-1]["outcome"] == "triage failed and went to a person"


def test_the_trace_the_ui_shows_holds_no_prompt_or_reasoning():
    _, events, calls = triage_with_log(GOOD)
    shown = json.dumps([event.model_dump(exclude={"ticket"}) for event in events], ensure_ascii=False)
    assert "pensando en voz alta" not in shown and "level 1 analyst" not in shown and "<untrusted_data>" not in shown
    assert calls


def test_no_log_is_kept_unless_asked():
    ticket, _ = run_triage(
        ALERT,
        build_context=lambda _alert: dict(CONTEXT),
        llm=ScriptedLLM(GOOD),
        compute_severity=lambda *a, **k: {"final": "medium", "reason": "prueba"},
        search_logs=lambda **a: [],
    )
    assert ticket.verdict == "true_positive"


# The model's reasoning, as each provider sends it


def message_reply(content, **message_fields):
    choice = SimpleNamespace(finish_reason="stop", message=SimpleNamespace(content=content, **message_fields))
    return SimpleNamespace(choices=[choice], usage=None)


class OneReply:
    def __init__(self, reply):
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=lambda **request: reply))


@pytest.fixture
def plain_settings(monkeypatch):
    monkeypatch.setenv("LLM_MODEL", "main-model")
    monkeypatch.setenv("LLM_BACKUP_MODEL", "main-model")
    monkeypatch.setenv("LLM_API_KEY", "secret-test-key")
    monkeypatch.setenv("LLM_STREAM", "false")
    monkeypatch.setattr(llm_module, "_exhausted", {})


@pytest.mark.parametrize(
    "fields", [{"reasoning_content": "primero miro los logs"}, {"reasoning": "primero miro los logs"}]
)
def test_reasoning_fields_are_kept(plain_settings, fields):
    result = complete("s", "u", client=OneReply(message_reply('{"ok": true}', **fields)), sleep=lambda _: None)
    assert result.reasoning == "primero miro los logs" and result.text == '{"ok": true}'


def test_reasoning_inside_think_tags_is_kept_but_not_parsed(plain_settings):
    result = complete(
        "s",
        "u",
        client=OneReply(message_reply('<think>primero miro los logs</think>{"ok": true}')),
        sleep=lambda _: None,
    )
    assert result.reasoning == "primero miro los logs" and result.text == '{"ok": true}'


def test_streamed_reasoning_is_put_back_together(plain_settings, monkeypatch):
    monkeypatch.delenv("LLM_STREAM")

    def chunk(content="", reasoning=None, finish=None):
        delta = SimpleNamespace(content=content, reasoning_content=reasoning)
        return SimpleNamespace(choices=[SimpleNamespace(delta=delta, finish_reason=finish)], usage=None)

    stream = iter([chunk(reasoning="primero "), chunk(reasoning="miro"), chunk('{"ok": true}'), chunk(finish="stop")])
    result = complete("s", "u", client=OneReply(stream), sleep=lambda _: None)
    assert result.reasoning == "primero miro" and result.text == '{"ok": true}'


# Where the logs are written


def test_batch_writes_a_call_log_even_when_the_ticket_isnt_saved(tmp_path):
    options = {
        "build_context": lambda alert: dict(CONTEXT, alert=alert),
        "compute_severity": lambda *a, **k: "medium",
        "search_logs": lambda **a: [],
    }
    alerts = {"ALR-LOG-1": ALERT, "ALR-LOG-2": {**ALERT, "alert_id": "ALR-LOG-2"}}
    run_batch(
        ["ALR-LOG-1"],
        alerts=alerts,
        triage_options={**options, "llm": ScriptedLLM(GOOD)},
        out_dir=tmp_path,
        sleep=lambda _: None,
    )
    run_batch(
        ["ALR-LOG-2"],
        alerts=alerts,
        triage_options={**options, "llm": ScriptedLLM(LLMUnavailable("down", attempts=1))},
        out_dir=tmp_path,
        sleep=lambda _: None,
    )
    done = json.loads((tmp_path / "calls" / "ALR-LOG-1.json").read_text(encoding="utf-8"))
    failed = json.loads((tmp_path / "calls" / "ALR-LOG-2.json").read_text(encoding="utf-8"))
    assert (
        done["ticket_saved"] is True
        and done["prompt_version"] == PROMPT_VERSION
        and done["calls"][0]["outcome"] == "accepted"
    )
    assert failed["ticket_saved"] is False and not (tmp_path / "ALR-LOG-2.json").exists()


def test_batch_with_workers_writes_one_log_per_alert(tmp_path):
    alerts = {f"ALR-LOG-{i}": {**ALERT, "alert_id": f"ALR-LOG-{i}"} for i in range(4)}
    options = {
        "build_context": lambda alert: dict(CONTEXT, alert=alert),
        "compute_severity": lambda *a, **k: "medium",
        "search_logs": lambda **a: [],
        "llm": lambda system, user: LLMResult(text=json.dumps(GOOD), model="fake"),
    }
    run_batch(list(alerts), alerts=alerts, triage_options=options, out_dir=tmp_path, workers=3)
    for alert_id in alerts:
        log = json.loads((tmp_path / "calls" / f"{alert_id}.json").read_text(encoding="utf-8"))
        assert log["alert_id"] == alert_id and alert_id in log["calls"][0]["user"]


def test_the_app_writes_a_call_log_for_each_real_run(tmp_path, monkeypatch):
    from src.agent import triage as triage_module

    def fake_triage(alert, call_log=None):
        call_log.append({"kind": "llm_call", "outcome": "accepted"})
        yield {"type": "started", "summary": "x"}

    monkeypatch.setattr(triage_module, "triage", fake_triage)
    monkeypatch.setenv("APP_CALL_LOG_DIR", str(tmp_path))
    assert [event["type"] for event in runner.real_events({"alert_id": "IMP/1 raro"})] == ["started"]
    (path,) = tmp_path.glob("*.json")
    assert (
        path.name.startswith("IMP_1_raro_")
        and json.loads(path.read_text(encoding="utf-8"))["calls"][0]["outcome"] == "accepted"
    )


def test_a_log_that_cant_be_written_never_stops_the_app(tmp_path, monkeypatch):
    from src.agent import triage as triage_module

    def fake_triage(alert, call_log=None):
        call_log.append({"kind": "llm_call"})
        yield {"type": "started"}

    blocked = tmp_path / "a-file"
    blocked.write_text("x")
    monkeypatch.setattr(triage_module, "triage", fake_triage)
    monkeypatch.setenv("APP_CALL_LOG_DIR", str(blocked / "inside"))
    assert len(list(runner.real_events({"alert_id": "A"}))) == 1


# Reading a log back

spec = importlib.util.spec_from_file_location("exam_for_call_log", ROOT / "scripts" / "exam.py")
exam = importlib.util.module_from_spec(spec)
sys.modules["exam_for_call_log"] = exam
spec.loader.exec_module(exam)


def test_explain_shows_answer_reasoning_and_what_code_did(tmp_path, capsys):
    folder = tmp_path / "v9-test"
    (folder / "calls").mkdir(parents=True)
    calls = [
        {
            "kind": "llm_call",
            "call": 1,
            "outcome": "rejected by code",
            "errors": ["It cited event IDs that aren't in the data."],
            "system": "SYSTEM TEXT",
            "user": "USER TEXT",
            "answer": "{}",
            "reasoning": "x" * 3000,
            "model": "m",
            "seconds": 1.0,
        },
        {"kind": "result", "outcome": "ticket", "verdict": "needs_more_info"},
    ]
    (folder / "calls" / "A-1.json").write_text(
        json.dumps({"alert_id": "A-1", "prompt_version": "v9", "ticket_saved": True, "calls": calls}), encoding="utf-8"
    )
    assert exam.command_explain(exam.parser().parse_args(["explain", "A-1", "--folder", str(folder)])) == 0
    output = capsys.readouterr().out
    assert (
        "rejected by code" in output
        and "aren't in the data" in output
        and "use --full" in output
        and "needs_more_info" in output
    )
    assert "SYSTEM TEXT" not in output
    exam.command_explain(exam.parser().parse_args(["explain", "A-1", "--folder", str(folder), "--prompt", "--full"]))
    output = capsys.readouterr().out
    assert "SYSTEM TEXT" in output and "use --full" not in output


def test_explain_without_a_log_says_why(tmp_path):
    with pytest.raises(exam.Problem, match="no call log"):
        exam.command_explain(exam.parser().parse_args(["explain", "A-1", "--folder", str(tmp_path)]))
