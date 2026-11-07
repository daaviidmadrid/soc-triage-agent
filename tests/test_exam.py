"""The script that splits the practice exam across laptops."""
import importlib.util
import json
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("exam_script", ROOT / "scripts" / "exam.py")
exam = importlib.util.module_from_spec(spec)
sys.modules["exam_script"] = exam
spec.loader.exec_module(exam)


def ticket(alert_id, verdict="true_positive"):
    return {"ticket_id": f"TKT-{alert_id}", "alert_ids": [alert_id], "verdict": verdict, "severity": "high", "confidence": 0.9,
            "evidence": [{"event_id": "E"}], "escalation": {"escalate": True}}


@pytest.fixture
def runs(tmp_path, monkeypatch):
    monkeypatch.setattr(exam, "RUNS_DIR", tmp_path)
    monkeypatch.setenv("LLM_MODEL", "test-model")
    monkeypatch.setattr(exam, "_load_env", lambda: None)
    return tmp_path


@pytest.mark.parametrize("laptops", [1, 2, 3, 7])
def test_split_gives_every_alert_to_exactly_one_laptop(laptops):
    ids = [f"A{i}" for i in range(40)]
    shares = [exam.split(ids, laptop, laptops) for laptop in range(1, laptops + 1)]
    assert sorted(sum(shares, [])) == sorted(ids)
    assert max(map(len, shares)) - min(map(len, shares)) <= 1


@pytest.mark.parametrize("laptop, laptops", [(0, 3), (4, 3), (1, 0)])
def test_split_refuses_a_laptop_that_doesnt_exist(laptop, laptops):
    with pytest.raises(exam.Problem):
        exam.split(["A"], laptop, laptops)


def test_sets_have_the_expected_sizes_and_no_held_out_alerts():
    from eval import score

    held_out = set(score._read_ids(score.HELDOUT_FILE))
    chosen = exam.choose_ids("exam")
    assert len(chosen) == 40 and not held_out & set(chosen)
    normal = exam.choose_ids("normal")
    assert len(normal) == 40 and not set(normal) & set(chosen) and not held_out & set(normal)
    assert exam.choose_ids("scored") == chosen + normal
    extra = exam.choose_ids("extra")
    final = exam.choose_ids("final")
    assert len(final) == 40 and not set(final) & set(chosen + normal) and not held_out & set(final)
    assert len(extra) == 62 and not set(extra) & set(chosen + normal + final) and not held_out & set(extra)
    assert exam.choose_ids("all") == chosen + normal + final + extra


def test_progress_bar_counts_saved_alerts_and_names_failures(capsys):
    bar, show = exam.progress_bar(2)
    with bar:
        show("A", "done", 1.0)
        show("B", "failed", 1.0)
        show("C", "skipped", 0.0)
    assert bar.n == 1
    assert "B failed" in capsys.readouterr().out


def test_a_laptop_without_tqdm_still_runs(monkeypatch, capsys):
    monkeypatch.setitem(sys.modules, "tqdm", None)
    bar, show = exam.progress_bar(1)
    with bar:
        show("A", "done", 1.0)
    assert bar.n == 1 and "1/1" in capsys.readouterr().out


def test_no_thinking_gets_its_own_folder(runs, monkeypatch):
    monkeypatch.setenv("LLM_ENABLE_THINKING", "false")
    assert exam.results_folder("ornith").name.endswith("-ornith-nothink")


def test_a_file_of_ids_is_accepted_but_never_held_out_alerts(tmp_path):
    from eval import score

    path = tmp_path / "ids.txt"
    path.write_text(f"# a comment\nALR-1\nALR-1\n{score._read_ids(score.HELDOUT_FILE)[0]}\n", encoding="utf-8")
    assert exam.choose_ids(str(path)) == ["ALR-1"]


def test_an_unknown_set_says_what_to_use():
    with pytest.raises(exam.Problem, match="exam, extra, all"):
        exam.choose_ids("nothing-called-this")


def test_results_folder_names_the_prompt_and_the_model(runs):
    from src.agent.prompts import PROMPT_VERSION

    assert exam.results_folder("gemini/odd name").name == f"{PROMPT_VERSION}-gemini_odd_name"


def test_a_run_uses_one_model_only(runs, monkeypatch):
    monkeypatch.setenv("LLM_BACKUP_MODEL", "other-model")
    assert exam._model() == "test-model"
    assert exam.os.environ["LLM_BACKUP_MODEL"] == "test-model"


def test_no_model_says_how_to_fix_it(runs, monkeypatch):
    monkeypatch.delenv("LLM_MODEL")
    with pytest.raises(exam.Problem, match="LLM_MODEL"):
        exam._model()


def make_laptop(base, name, alert_ids, folder="v2-test-model"):
    results = base / name / folder
    (results / "traces").mkdir(parents=True)
    for alert_id in alert_ids:
        (results / f"{alert_id}.json").write_text(json.dumps(ticket(alert_id)), encoding="utf-8")
        (results / "traces" / f"{alert_id}.json").write_text(json.dumps([{"tool": "llm", "args": {"model": "test-model", "seconds": 2.0}}]), encoding="utf-8")
    return results


def pack(monkeypatch, tmp_path, name, results, laptop):
    monkeypatch.setattr(exam, "RUNS_DIR", tmp_path / name)
    args = exam.parser().parse_args(["pack", "--laptop", str(laptop), "--folder", str(results)])
    assert exam.command_pack(args) == 0
    return tmp_path / name / f"exam_{results.name}_laptop{laptop}.zip"


def test_three_laptops_pack_and_merge_into_one_folder(tmp_path, monkeypatch):
    zips = [pack(monkeypatch, tmp_path, f"l{n}", make_laptop(tmp_path, f"l{n}", [f"A{n}", f"B{n}"]), n) for n in (1, 2, 3)]
    merged = tmp_path / "merged"
    for path in zips:
        assert exam.merge_zip(path, merged) == ("v2-test-model", 2, 0, 0)
    folder = merged / "v2-test-model"
    assert len(list(folder.glob("*.json"))) == 6 and len(list((folder / "traces").glob("*.json"))) == 6
    assert exam.merge_zip(zips[0], merged) == ("v2-test-model", 0, 2, 0)


def test_merge_never_overwrites_a_different_ticket(tmp_path, monkeypatch):
    path = pack(monkeypatch, tmp_path, "l1", make_laptop(tmp_path, "l1", ["A1"]), 1)
    merged = tmp_path / "merged" / "v2-test-model"
    merged.mkdir(parents=True)
    (merged / "A1.json").write_text(json.dumps(ticket("A1", "false_positive")), encoding="utf-8")
    assert exam.merge_zip(path, tmp_path / "merged") == ("v2-test-model", 0, 0, 1)
    assert json.loads((merged / "A1.json").read_text(encoding="utf-8"))["verdict"] == "false_positive"


@pytest.mark.parametrize("name", ["../evil.json", "v2/../../evil.json", "v2/a/b/c.json", "v2/evil.py", "../v2/ok.json", "ok.json", "/tmp/evil.json", "v2/traces/../evil.json"])
def test_merge_refuses_anything_that_isnt_a_ticket_or_trace(tmp_path, name):
    path = tmp_path / "bad.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(name, "{}")
    with pytest.raises(exam.Problem):
        exam.merge_zip(path, tmp_path / "merged")
    assert not list((tmp_path / "merged").glob("**/*.json")) if (tmp_path / "merged").exists() else True
    assert not (tmp_path / "evil.json").exists()


def test_merge_explains_a_broken_file(tmp_path, runs):
    path = tmp_path / "broken.zip"
    path.write_bytes(b"not a zip")
    args = exam.parser().parse_args(["merge", str(path)])
    with pytest.raises(exam.Problem, match="isn't a results pack"):
        exam.command_merge(args)


def test_run_does_only_what_is_missing_and_says_when_it_is_finished(runs, monkeypatch, capsys):
    from src.agent import batch

    folder = exam.results_folder("test-model")
    folder.mkdir(parents=True)
    ids = exam.split(exam.choose_ids("exam"), 2, 3)
    (folder / f"{ids[0]}.json").write_text(json.dumps(ticket(ids[0])), encoding="utf-8")
    seen = []

    def fake_batch(todo, alerts, out_dir, pace_seconds, max_calls, on_result, workers):
        seen.extend(todo)
        for alert_id in todo:
            (Path(out_dir) / f"{alert_id}.json").write_text(json.dumps(ticket(alert_id)), encoding="utf-8")
            on_result(alert_id, "done", 1.0)
        return {"quota_exhausted": False}

    monkeypatch.setattr(batch, "run_batch", fake_batch)
    monkeypatch.setattr(batch, "load_alerts", lambda pending: {alert_id: {"alert_id": alert_id} for alert_id in pending})
    monkeypatch.setattr(exam, "mock_is_up", lambda url=None: True)
    assert exam.command_run(exam.parser().parse_args(["run", "--laptop", "2", "--laptops", "3"])) == 0
    assert seen == ids[1:]
    output = capsys.readouterr().out
    assert f"{len(ids)} of {len(ids)} saved" in output and "pack --laptop 2" in output
    assert exam.command_run(exam.parser().parse_args(["run", "--laptop", "2", "--laptops", "3"])) == 0
    assert "Nothing to do" in capsys.readouterr().out


def test_run_stops_cleanly_at_the_daily_limit(runs, monkeypatch, capsys):
    from src.agent import batch

    calls = []

    def fake_batch(todo, **_options):
        calls.append(todo)
        return {"quota_exhausted": True}

    monkeypatch.setattr(batch, "run_batch", fake_batch)
    monkeypatch.setattr(batch, "load_alerts", lambda pending: {alert_id: {} for alert_id in pending})
    monkeypatch.setattr(exam, "mock_is_up", lambda url=None: True)
    assert exam.command_run(exam.parser().parse_args(["run"])) == 1
    assert len(calls) == 1
    output = capsys.readouterr().out
    assert "daily limit" in output and "again to carry on" in output


def test_score_marks_labelled_tickets_and_counts_the_rest(tmp_path, runs, monkeypatch, capsys):
    from eval import score

    results = make_laptop(tmp_path, "l1", ["A1", "NOLABEL"])
    monkeypatch.setattr(score, "load_labels", lambda: [{"alert_id": "A1", "verdict": "true_positive", "severity": "high", "escalate": "true"}])
    assert exam.command_score(exam.parser().parse_args(["score", "--folder", str(results)])) == 0
    output = capsys.readouterr().out
    assert "verdict                1/1" in output and "no answer to compare: 1" in output and "test-model" in output
    assert "Disagreements" not in output


def test_score_lists_disagreements_with_the_key(tmp_path, runs, monkeypatch, capsys):
    from eval import score

    results = make_laptop(tmp_path, "l1", ["A1"])
    monkeypatch.setattr(score, "load_labels", lambda: [{"alert_id": "A1", "verdict": "false_positive", "severity": "", "escalate": "false"}])
    exam.command_score(exam.parser().parse_args(["score", "--folder", str(results)]))
    output = capsys.readouterr().out
    assert "Disagreements with the key: 1" in output and "verdict: AI true_positive, key false_positive" in output


def test_score_with_no_tickets_says_so(tmp_path, runs):
    with pytest.raises(exam.Problem, match="no tickets"):
        exam.command_score(exam.parser().parse_args(["score", "--folder", str(tmp_path / "empty")]))


def test_a_problem_is_a_message_not_a_traceback(monkeypatch, capsys):
    monkeypatch.setattr(exam, "_running_from_venv", lambda: True)
    assert exam.main(["run", "--laptop", "9", "--laptops", "3"]) == 1
    assert "Stopped:" in capsys.readouterr().out
