"""Runs many alerts and saves results in runs/. Branch: agent/batch

Run from the repo root: python -m src.agent.batch alert_ids.txt
"""
import json
import re
import sys
import time
from pathlib import Path

from src.agent.prompts import PROMPT_VERSION
from src.agent.triage import MAX_LLM_CALLS, run_triage

REPO_ROOT = Path(__file__).resolve().parents[2]
ALERTS_FILE = REPO_ROOT / "data" / "03_alertas" / "alertas.jsonl"
RUNS_DIR = REPO_ROOT / "runs"

# TODO(decision): calls per day and the pace, until someone reads the real limit in AI Studio.
PACE_SECONDS = 15
# TODO(decision): calls per day and the pace, until someone reads the real limit in AI Studio.
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


def _save(path, ticket):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(ticket.model_dump(exclude_none=True), ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(path)


def run_batch(alert_ids, alerts=None, triage_options=None, out_dir=None, pace_seconds=PACE_SECONDS, max_calls=MAX_CALLS_PER_RUN, sleep=time.sleep):
    """Returns a report: done, skipped, failed, not_found, invalid_ids, not_started and calls_used."""
    alert_ids = list(dict.fromkeys(alert_ids))
    out_dir = Path(out_dir or RUNS_DIR / PROMPT_VERSION)
    report = {"done": [], "skipped": [], "failed": [], "not_found": [], "invalid_ids": [], "not_started": [], "calls_used": 0}
    # IDs become file names, so anything else is refused.
    safe_ids = []
    for alert_id in alert_ids:
        (safe_ids if re.fullmatch(r"[A-Za-z0-9_-]+", alert_id) else report["invalid_ids"]).append(alert_id)
    alerts = load_alerts(safe_ids) if alerts is None else alerts

    failures_in_a_row = 0
    called_yet = False
    for position, alert_id in enumerate(safe_ids):
        path = out_dir / f"{alert_id}.json"
        if path.exists():
            report["skipped"].append(alert_id)
            continue
        if alert_id not in alerts:
            report["not_found"].append(alert_id)
            continue
        if report["calls_used"] + MAX_LLM_CALLS > max_calls or failures_in_a_row >= MAX_FAILURES_IN_A_ROW:
            report["not_started"] = [item for item in safe_ids[position:] if not (out_dir / f"{item}.json").exists()]
            break
        if called_yet:
            sleep(pace_seconds)
        called_yet = True
        ticket, events = run_triage(alerts[alert_id], **(triage_options or {}))
        report["calls_used"] += _calls_used(events)
        if _should_save(events):
            _save(path, ticket)
            report["done"].append(alert_id)
            failures_in_a_row = 0
        else:
            report["failed"].append(alert_id)
            failures_in_a_row += 1
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
    return 0


if __name__ == "__main__":
    sys.exit(main())
