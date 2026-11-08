import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.agent import batch  # noqa: E402
from src.agent.batch import load_alerts, main, run_batch  # noqa: E402
from src.agent.llm import LLMBlocked, LLMQuotaExhausted, LLMResult, LLMUnavailable  # noqa: E402

ANSWER = {
    "title": "Título",
    "verdict": "true_positive",
    "confidence": 0.9,
    "summary": "Resumen.",
    "evidence": [{"source": "alert", "event_id": "", "finding": "x"}],
}
ALERTS = {f"ALR-{i}": {"alert_id": f"ALR-{i}", "rule_id": "UC-TEST", "severity": "low"} for i in range(5)}


class FakeLLM:
    def __init__(self, failure=None):
        self.calls = 0
        self.failure = failure

    def __call__(self, system, user):
        self.calls += 1
        if self.failure:
            raise self.failure
        return LLMResult(text=json.dumps(ANSWER), model="fake", attempts=1)


def options(llm):
    return {
        "llm": llm,
        "build_context": lambda alert: {"alert": alert},
        "compute_severity": lambda *a, **k: "low",
        "search_logs": lambda **a: [],
    }


def run(tmp_path, ids, llm=None, **kwargs):
    kwargs.setdefault("sleep", lambda _seconds: None)
    return run_batch(ids, alerts=ALERTS, triage_options=options(llm or FakeLLM()), out_dir=tmp_path, **kwargs)


def test_saves_each_ticket_as_json(tmp_path):
    report = run(tmp_path, ["ALR-0", "ALR-1"])
    assert report["done"] == ["ALR-0", "ALR-1"]
    saved = json.loads((tmp_path / "ALR-0.json").read_text(encoding="utf-8"))
    assert saved["alert_ids"] == ["ALR-0"]
    assert saved["verdict"] == "true_positive"
    assert report["calls_used"] == 2


def test_default_folder_uses_the_prompt_version():
    assert batch.RUNS_DIR.name == "runs"


def test_skips_alerts_that_already_have_a_result(tmp_path):
    (tmp_path / "ALR-0.json").write_text("{}", encoding="utf-8")
    llm = FakeLLM()
    report = run(tmp_path, ["ALR-0", "ALR-1"], llm=llm)
    assert report["skipped"] == ["ALR-0"]
    assert report["done"] == ["ALR-1"]
    assert llm.calls == 1
    assert (tmp_path / "ALR-0.json").read_text(encoding="utf-8") == "{}"


def test_running_twice_makes_no_new_calls(tmp_path):
    llm = FakeLLM()
    run(tmp_path, ["ALR-0"], llm=llm)
    run(tmp_path, ["ALR-0"], llm=llm)
    assert llm.calls == 1


def test_paces_calls_but_not_before_the_first(tmp_path):
    waits = []
    run(tmp_path, ["ALR-0", "ALR-1", "ALR-2"], sleep=waits.append, pace_seconds=7)
    assert waits == [7, 7]


def test_stops_at_the_call_limit_and_reports_what_is_left(tmp_path):
    llm = FakeLLM()
    report = run(tmp_path, list(ALERTS), llm=llm, max_calls=4)
    assert report["done"] == ["ALR-0", "ALR-1"]
    assert report["not_started"] == ["ALR-2", "ALR-3", "ALR-4"]
    assert llm.calls == 2


def test_outage_is_not_saved_so_the_next_run_tries_again(tmp_path):
    report = run(tmp_path, ["ALR-0"], llm=FakeLLM(LLMUnavailable("down", attempts=4)))
    assert report["failed"] == ["ALR-0"]
    assert report["calls_used"] == 4
    assert not (tmp_path / "ALR-0.json").exists()
    assert run(tmp_path, ["ALR-0"])["done"] == ["ALR-0"]


def test_blocked_call_is_saved_as_a_result(tmp_path):
    report = run(tmp_path, ["ALR-0"], llm=FakeLLM(LLMBlocked("blocked")))
    assert report["done"] == ["ALR-0"]
    saved = json.loads((tmp_path / "ALR-0.json").read_text(encoding="utf-8"))
    assert saved["verdict"] == "needs_more_info"
    assert saved["escalation"]["escalate"] is True


def test_stops_after_repeated_failures(tmp_path):
    llm = FakeLLM(LLMUnavailable("down"))
    report = run(tmp_path, list(ALERTS), llm=llm)
    assert report["failed"] == ["ALR-0", "ALR-1", "ALR-2"]
    assert report["not_started"] == ["ALR-3", "ALR-4"]
    assert llm.calls == batch.MAX_FAILURES_IN_A_ROW


def test_unknown_alerts_are_reported(tmp_path):
    report = run(tmp_path, ["ALR-MISSING", "ALR-0"])
    assert report["not_found"] == ["ALR-MISSING"]
    assert report["done"] == ["ALR-0"]


@pytest.mark.parametrize("bad", ["../../etc/passwd", "a/b", "ALR 1", "..", ""])
def test_ids_that_are_not_safe_file_names_are_refused(tmp_path, bad):
    report = run(tmp_path, [bad])
    assert report["invalid_ids"] == [bad]
    assert list(tmp_path.iterdir()) == []


def test_repeated_ids_run_once(tmp_path):
    llm = FakeLLM()
    run(tmp_path, ["ALR-0", "ALR-0"], llm=llm)
    assert llm.calls == 1


def test_leaves_no_temporary_files(tmp_path):
    run(tmp_path, ["ALR-0"])
    assert sorted(path.name for path in tmp_path.iterdir()) == ["ALR-0.json", "calls", "traces"]
    assert [path.name for path in (tmp_path / "traces").iterdir()] == ["ALR-0.json"]
    assert [path.name for path in (tmp_path / "calls").iterdir()] == ["ALR-0.json"]
    assert not list(tmp_path.rglob("*.tmp"))


def test_trace_says_which_model_answered_and_holds_no_ticket(tmp_path):
    run(tmp_path, ["ALR-0"])
    events = json.loads((tmp_path / "traces" / "ALR-0.json").read_text(encoding="utf-8"))
    assert any(event.get("args", {}).get("model") == "fake" for event in events)
    assert all("ticket" not in event for event in events)


def test_daily_limit_stops_the_run_and_saves_nothing_new(tmp_path):
    llm = FakeLLM(failure=LLMQuotaExhausted("Daily limit", 1))
    report = run(tmp_path, ["ALR-0", "ALR-1", "ALR-2"], llm=llm)
    assert llm.calls == 1
    assert report["quota_exhausted"] is True
    assert report["failed"] == ["ALR-0"] and report["not_started"] == ["ALR-1", "ALR-2"]
    assert not (tmp_path / "ALR-0.json").exists()


def test_workers_do_every_alert_once(tmp_path):
    llm = FakeLLM()
    seen = []
    report = run(
        tmp_path,
        list(ALERTS) + ["NOT-THERE"],
        llm=llm,
        workers=3,
        on_result=lambda alert_id, status, seconds: seen.append((alert_id, status)),
    )
    assert sorted(report["done"]) == sorted(ALERTS) and report["not_found"] == ["NOT-THERE"]
    assert llm.calls == len(ALERTS) and report["calls_used"] == len(ALERTS)
    assert all((tmp_path / f"{alert_id}.json").exists() for alert_id in ALERTS)
    assert sorted(seen) == sorted([(alert_id, "done") for alert_id in ALERTS] + [("NOT-THERE", "not_found")])


def test_workers_skip_what_is_saved_and_stop_at_the_daily_limit(tmp_path):
    run(tmp_path, ["ALR-0"])
    llm = FakeLLM(failure=LLMQuotaExhausted("Daily limit", 1))
    report = run(tmp_path, list(ALERTS), llm=llm, workers=2)
    assert report["skipped"] == ["ALR-0"] and report["quota_exhausted"] is True and report["done"] == []
    assert set(report["failed"]) | set(report["not_started"]) == set(ALERTS) - {"ALR-0"}
    assert llm.calls <= 2


def test_workers_give_up_after_many_failures_in_a_row(tmp_path):
    many = {f"ALR-{i}": {"alert_id": f"ALR-{i}", "rule_id": "UC-TEST", "severity": "low"} for i in range(40)}
    llm = FakeLLM(failure=LLMUnavailable("down", 1))
    report = run_batch(list(many), alerts=many, triage_options=options(llm), out_dir=tmp_path, workers=2)
    assert report["done"] == [] and report["not_started"]
    assert llm.calls < len(many)


def test_reports_progress_for_each_alert(tmp_path):
    seen = []
    run(tmp_path, ["ALR-0", "NOT-THERE"], on_result=lambda alert_id, status, seconds: seen.append((alert_id, status)))
    assert seen == [("ALR-0", "done"), ("NOT-THERE", "not_found")]


def test_load_alerts_returns_only_what_was_asked(tmp_path):
    path = tmp_path / "alerts.jsonl"
    path.write_text('{"alert_id": "A"}\n\n{"alert_id": "B"}\n', encoding="utf-8")
    assert load_alerts(["B", "C"], path=path) == {"B": {"alert_id": "B"}}


def test_command_line_reads_a_file_of_ids(tmp_path, monkeypatch, capsys):
    seen = []

    def fake_run(ids):
        seen.extend(ids)
        return {
            "done": ids,
            "skipped": [],
            "failed": [],
            "not_found": [],
            "invalid_ids": [],
            "not_started": [],
            "calls_used": len(ids),
        }

    monkeypatch.setattr(batch, "run_batch", fake_run)
    ids_file = tmp_path / "ids.txt"
    ids_file.write_text("# a comment\nALR-0\n\n  ALR-1  \n", encoding="utf-8")
    assert main([str(ids_file)]) == 0
    assert seen == ["ALR-0", "ALR-1"]
    assert "Done 2" in capsys.readouterr().out


def test_command_line_explains_its_usage(capsys):
    assert main([]) == 2
    assert "Usage" in capsys.readouterr().out
