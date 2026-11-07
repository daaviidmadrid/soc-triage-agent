"""Runs many alerts and saves results in runs/. Branch: agent/batch

Run from the repo root: python -m src.agent.batch alert_ids.txt
To split a run across laptops, use scripts/exam.py, which calls this.
"""
import json
import os
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from src.agent.prompts import PROMPT_VERSION
from src.agent.triage import MAX_LLM_CALLS, run_triage

REPO_ROOT = Path(__file__).resolve().parents[2]
ALERTS_FILE = REPO_ROOT / "data" / "03_alertas" / "alertas.jsonl"
RUNS_DIR = REPO_ROOT / "runs"

# A pause between alerts, to stay under per-minute limits. If we still hit one, src/agent/llm.py waits as long as the provider asks.
PACE_SECONDS = float(os.environ.get("LLM_PACE_SECONDS", 2))
# A safety stop, not a provider limit. When the provider's daily limit is reached, the run stops by itself.
MAX_CALLS_PER_RUN = 100

MAX_FAILURES_IN_A_ROW = 3


def load_alerts(alert_ids, path=ALERTS_FILE):
    wanted = set(alert_ids)
    found = {}
    with open(path, encoding="utf-8") as file:
        for line in file:
            if line.strip():
                alert = json.loads(line)
                if alert.get("alert_id") in wanted:
                    found[alert["alert_id"]] = alert
    return found


def _calls_used(events):
    """Counts real attempts, including retries, because those use up the free limit too."""
    return sum(
        event.args.get("attempts", 1)
        for event in events
        if event.tool == "llm" and (event.type == "error" or (event.type == "tool_result" and "model" in event.args))
    )


def _should_save(events):
    """An outage is not a result, so it isn't saved and the next run tries again. A blocked call won't change."""
    return not any(event.type == "error" and event.args.get("kind") != "blocked" for event in events)


def _out_of_quota(events):
    return any(event.type == "error" and event.args.get("kind") == "quota" for event in events)


def _write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(path)


def _save(path, ticket, events):
    """The trace says which model answered and how long it took, and holds only counts and IDs."""
    _write_json(path.parent / "traces" / path.name, [event.model_dump(exclude={"ticket"}, exclude_none=True) for event in events])
    _write_json(path, ticket.model_dump(exclude_none=True))


def _triage(alert, triage_options):
    """Returns (ticket, events, calls). calls holds each prompt, raw answer and reasoning, and what code did with them."""
    calls = []
    ticket, events = run_triage(alert, **{**(triage_options or {}), "call_log": calls})
    return ticket, events, calls


def _save_calls(out_dir, alert_id, calls, saved):
    """Written even when the ticket isn't, because a failure is what most needs explaining. A later run overwrites it.
    It holds alert and log text, which is untrusted: read it as data. runs/ is not in git."""
    _write_json(out_dir / "calls" / f"{alert_id}.json",
                {"alert_id": alert_id, "prompt_version": PROMPT_VERSION, "ticket_saved": saved, "calls": calls})


def _run_in_parallel(todo, alerts, triage_options, out_dir, workers, max_calls, report, notify):
    """Several alerts at a time, for providers with no request limit. Every failure still counts, and nothing is saved twice."""
    lock = threading.Lock()
    stop = threading.Event()
    waiting = iter(todo)
    failures = {"in_a_row": 0}

    def work():
        while not stop.is_set():
            with lock:
                alert_id = next(waiting, None)
            if alert_id is None:
                return
            started = time.monotonic()
            ticket, events, calls = _triage(alerts[alert_id], triage_options)
            saved = _should_save(events)
            _save_calls(out_dir, alert_id, calls, saved)
            if saved:
                _save(out_dir / f"{alert_id}.json", ticket, events)
            with lock:
                report["calls_used"] += _calls_used(events)
                report["done" if saved else "failed"].append(alert_id)
                failures["in_a_row"] = 0 if saved else failures["in_a_row"] + 1
                if _out_of_quota(events):
                    report["quota_exhausted"] = True
                if report["quota_exhausted"] or failures["in_a_row"] >= MAX_FAILURES_IN_A_ROW * workers or report["calls_used"] + MAX_LLM_CALLS > max_calls:
                    stop.set()
            notify(alert_id, "done" if saved else "failed", time.monotonic() - started)

    with ThreadPoolExecutor(workers) as pool:
        for future in [pool.submit(work) for _ in range(workers)]:
            future.result()
    report["not_started"] = [item for item in todo if item not in report["done"] and item not in report["failed"]]
    return report


def run_batch(alert_ids, alerts=None, triage_options=None, out_dir=None, pace_seconds=PACE_SECONDS, max_calls=MAX_CALLS_PER_RUN, sleep=time.sleep, on_result=None, workers=1):
    """Returns a report: done, skipped, failed, not_found, invalid_ids, not_started, calls_used and quota_exhausted.

    on_result(alert_id, status, seconds) is called after each alert, for showing progress.
    workers above 1 runs that many alerts at a time, with no pause between them."""
    alert_ids = list(dict.fromkeys(alert_ids))
    out_dir = Path(out_dir or RUNS_DIR / PROMPT_VERSION)
    report = {"done": [], "skipped": [], "failed": [], "not_found": [], "invalid_ids": [], "not_started": [], "calls_used": 0, "quota_exhausted": False}
    # IDs become file names, so anything else is refused.
    safe_ids = []
    for alert_id in alert_ids:
        (safe_ids if re.fullmatch(r"[A-Za-z0-9_-]+", alert_id) else report["invalid_ids"]).append(alert_id)
    alerts = load_alerts(safe_ids) if alerts is None else alerts
    notify = on_result or (lambda *_: None)

    if workers > 1:
        todo = []
        for alert_id in safe_ids:
            if (out_dir / f"{alert_id}.json").exists():
                report["skipped"].append(alert_id)
                notify(alert_id, "skipped", 0.0)
            elif alert_id not in alerts:
                report["not_found"].append(alert_id)
                notify(alert_id, "not_found", 0.0)
            else:
                todo.append(alert_id)
        return _run_in_parallel(todo, alerts, triage_options, out_dir, workers, max_calls, report, notify)

    failures_in_a_row = 0
    called_yet = False
    for position, alert_id in enumerate(safe_ids):
        path = out_dir / f"{alert_id}.json"
        if path.exists():
            report["skipped"].append(alert_id)
            notify(alert_id, "skipped", 0.0)
            continue
        if alert_id not in alerts:
            report["not_found"].append(alert_id)
            notify(alert_id, "not_found", 0.0)
            continue
        if report["calls_used"] + MAX_LLM_CALLS > max_calls or failures_in_a_row >= MAX_FAILURES_IN_A_ROW:
            report["not_started"] = [item for item in safe_ids[position:] if not (out_dir / f"{item}.json").exists()]
            break
        if called_yet:
            sleep(pace_seconds)
        called_yet = True
        started = time.monotonic()
        ticket, events, calls = _triage(alerts[alert_id], triage_options)
        report["calls_used"] += _calls_used(events)
        _save_calls(out_dir, alert_id, calls, _should_save(events))
        if _should_save(events):
            _save(path, ticket, events)
            report["done"].append(alert_id)
            failures_in_a_row = 0
            notify(alert_id, "done", time.monotonic() - started)
        else:
            report["failed"].append(alert_id)
            failures_in_a_row += 1
            notify(alert_id, "failed", time.monotonic() - started)
        if _out_of_quota(events):
            report["quota_exhausted"] = True
            report["not_started"] = [item for item in safe_ids[position + 1:] if not (out_dir / f"{item}.json").exists()]
            break
    return report


def main(arguments=None):
    arguments = sys.argv[1:] if arguments is None else arguments
    if len(arguments) != 1:
        print("Usage: python -m src.agent.batch file_of_alert_ids.txt")
        return 2
    lines = Path(arguments[0]).read_text(encoding="utf-8").splitlines()
    alert_ids = [line.strip() for line in lines if line.strip() and not line.startswith("#")]
    report = run_batch(alert_ids)
    print(json.dumps(report, indent=2))
    print(f"Done {len(report['done'])}, skipped {len(report['skipped'])}, failed {len(report['failed'])}, not started {len(report['not_started'])}, calls used {report['calls_used']}.")
    if report.get("quota_exhausted"):
        print("The provider's daily limit was reached. Saved tickets are kept, so run this again once it resets.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
