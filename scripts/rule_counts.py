#!/usr/bin/env python3
"""Counts how many alerts each fixed rule (src/agent/rules.py) would close, with no LLM. Start from the repo root.

    python3 scripts/rule_counts.py [--workers 8] [--out FILE.jsonl]

Runs the same steps as the triage up to the LLM call: the alert's context from the mock API, the rule,
then the severity matrix and the policy's mandatory escalation. Covers every alert in
data/03_alertas/alertas.jsonl whose detection rule has a fixed rule, except the held-out alerts.
--out writes one line per alert: whether it closed, and the condition that failed if not.
Needs the mock API (MOCK_API_URL, default http://localhost:8000).
"""

import argparse
import collections
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from eval import score  # noqa: E402
from src.agent.prompts import context_to_dict  # noqa: E402
from src.agent.rules import RULES, check_rules  # noqa: E402
from src.agent.triage import rule_ticket  # noqa: E402
from src.policy.severity import compute_severity  # noqa: E402
from src.tools.alert_fields import normalise_alert  # noqa: E402
from src.tools.context import build_context  # noqa: E402


def outcome(raw):
    """One alert, as the triage would see it before any LLM call."""
    alert, assumptions = normalise_alert(raw)
    context = context_to_dict(build_context(alert))
    context.setdefault("alert", alert)
    if assumptions:
        context["data_gaps"] = list(assumptions)
    check = check_rules(alert, context)
    ticket = None
    if check.applies:
        ticket, refusal = rule_ticket(alert, context, check, compute_severity, 0.0)
        check.refuse(refusal)
    return {
        "alert_id": raw.get("alert_id"),
        "detection_rule": raw.get("rule_id"),
        "rule": check.rule_id,
        "closed": ticket is not None,
        "failed": check.failed,
        "verdict": ticket.verdict if ticket else None,
        "severity": ticket.severity if ticket else None,
        "truncated_sources": context.get("truncated_sources") or [],
    }


def main(arguments=None):
    parser = argparse.ArgumentParser(description="Count what each fixed rule would close, without the LLM.")
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--out", help="write one JSON line per alert to this file")
    args = parser.parse_args(arguments)

    held_out = set(score._read_ids(score.HELDOUT_FILE))
    alerts = [
        alert
        for alert in score._read_jsonl(score.ALL_ALERTS)
        if alert.get("rule_id") in RULES and alert.get("alert_id") not in held_out
    ]
    print(f"{len(alerts)} alerts covered by a fixed rule, held-out alerts left out. Working ...", flush=True)
    with ThreadPoolExecutor(args.workers) as pool:
        results = list(pool.map(outcome, alerts))

    for rule in sorted({result["rule"] for result in results}):
        mine = [result for result in results if result["rule"] == rule]
        closed = [result for result in mine if result["closed"]]
        verdicts = collections.Counter((result["verdict"], result["severity"]) for result in closed)
        print(
            f"\n{rule} ({mine[0]['detection_rule']}): closes {len(closed)} of {len(mine)} alerts. "
            + ", ".join(f"{count} {verdict} {severity}" for (verdict, severity), count in verdicts.most_common())
        )
        for reason, count in collections.Counter(
            result["failed"] for result in mine if not result["closed"]
        ).most_common():
            print(f"  goes to the LLM, {count}: {reason}")
    if args.out:
        Path(args.out).write_text(
            "".join(json.dumps(result, ensure_ascii=False) + "\n" for result in results), encoding="utf-8"
        )
        print(f"\nOne line per alert in {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
