"""Investigates the alerts of one escalated incident and writes its report (level 3). Run from the repo root:
    python scripts/investigate.py ALR-... ALR-... [--tickets runs/FOLDER] [--out runs/reports]

Needs the mock API and an LLM key in .env. Refuses the held-out alerts (eval/heldout_alerts.txt) unless
--allow-heldout is given, which is only for the final evaluation. The report only proposes containment:
the policy check here names the approvers, and nothing approves or runs an action.
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.agent import investigate as inv  # noqa: E402
from src.agent.batch import _write_json, load_alerts  # noqa: E402
from src.policy.containment import step_checker  # noqa: E402
from src.tools import api_client  # noqa: E402


def heldout_ids(path=inv.HELDOUT_FILE):
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError:
        return set()
    return {line.strip() for line in lines if line.strip() and not line.startswith("#")}


def _load_tickets(folder, alert_ids):
    tickets = []
    for alert_id in alert_ids:
        path = Path(folder) / f"{alert_id}.json"
        if path.exists():
            tickets.append(json.loads(path.read_text(encoding="utf-8")))
    return tickets


def main(arguments=None):
    parser = argparse.ArgumentParser(description="Investigates the alerts of one incident and writes its report.")
    parser.add_argument("alert_ids", nargs="+")
    parser.add_argument("--tickets", help="folder of triage tickets from the batch, used as leads")
    parser.add_argument("--out", default=str(inv.REPORTS_DIR))
    parser.add_argument(
        "--allow-heldout", action="store_true", help="only for the final evaluation, never while tuning"
    )
    args = parser.parse_args(arguments)
    held = sorted(set(args.alert_ids) & heldout_ids())
    if held and not args.allow_heldout:
        print(f"Refused: {', '.join(held)} are held out (eval/heldout_alerts.txt). Don't tune on them.")
        return 2
    alerts = load_alerts(args.alert_ids)
    missing = [a for a in args.alert_ids if a not in alerts]
    if missing:
        print(f"Not found: {', '.join(missing)}")
        return 2
    tickets = _load_tickets(args.tickets, args.alert_ids) if args.tickets else []
    calls = []
    check = step_checker(api_client.get_asset, api_client.get_user)
    report, events = inv.run_investigation(
        [alerts[a] for a in args.alert_ids], tickets=tickets, call_log=calls, check_containment=check
    )
    out = Path(args.out)
    _write_json(out / f"{report.incident_id}.json", report.model_dump(mode="json"))
    _write_json(
        out / "traces" / f"{report.incident_id}.json",
        [e.model_dump(mode="json", exclude={"report"}, exclude_none=True) for e in events],
    )
    _write_json(
        out / "calls" / f"{report.incident_id}.json",
        {"incident_id": report.incident_id, "prompt_version": inv.PROMPT_VERSION, "calls": calls},
    )
    print(f"{report.incident_id}: {report.title}")
    print(
        f"Evidence: {report.evidence_summary.rows_retrieved} rows, {report.evidence_summary.rows_not_linked_by_alerts} not linked by any alert"
    )
    for step in report.timeline:
        extra = f" (+{len(step.similar_event_ids)})" if step.similar_event_ids else ""
        linked = "alert" if step.linked_by_alerts else "found"
        print(f"  {step.timestamp}  {step.event_id}{extra}  [{linked}/{step.added_by}]  {step.description[:110]}")
    print(f"Related: {report.related_incidents or 'none'}. {report.related_note}")
    for note in report.code_notes:
        print(f"  code: {note}")
    print(f"Written to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())


if __name__ == "__main__":
    sys.exit(main())
