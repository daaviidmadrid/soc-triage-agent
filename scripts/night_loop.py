"""Overnight improvement loop: run a prompt variant on the scored alerts, score it, and list its exam mistakes as
structured fields only, so a reviewer can write general lessons (src/agent/lessons.py) for the next round.

The split is fixed: lessons come only from mistakes on the exam set; a variant is kept only if the normal set,
which never feeds lessons, does not get worse. The final set is never run or scored here.

  python3 scripts/night_loop.py round NAME [--lessons FILE] [--reminder] [--no-thinking]   run + score, appends to runs/night/summary.md
  python3 scripts/night_loop.py score NAME FOLDER                                score an existing folder only
  python3 scripts/night_loop.py mistakes FOLDER                                  exam mistakes, structured fields only
"""

import argparse
import collections
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
NIGHT = ROOT / "runs" / "night"
PY = str(ROOT / ".venv" / "bin" / "python")


def _ids(name):
    from eval import score

    return set(score._read_ids(ROOT / "eval" / {"exam": "key40_alerts.txt", "normal": "key_normal40_alerts.txt"}[name]))


def _tickets(folder):
    from eval import score

    out = []
    for path in sorted(Path(folder).glob("*.json")):
        out += score.load_tickets(path)
    return out


def metrics(folder, set_name):
    from eval import score

    wanted = _ids(set_name)
    labels = [lab for lab in score.load_labels() if lab["alert_id"] in wanted]
    report = score.score(_tickets(folder), labels, score.load_planted())
    m = report["metrics"]
    rate = lambda k: round(100 * m[k]["rate"]) if k in m and m[k]["rate"] is not None else None
    inj = report["injections"] or {}
    return {
        "verdict": rate("verdict"),
        "severity": rate("severity_exact"),
        "escalate": rate("escalation"),
        "missed": len(report["missed_attacks"]),
        "needless": len(report["needless_escalations"]),
        "no_ticket": len(report["no_ticket"]),
        "planted": f"{len(inj.get('flagged', []))}/{len(inj.get('planted', []))} flagged, {len(inj.get('obeyed', []))} obeyed",
        "report": report,
    }


def call_facts(folder):
    seconds, rejected, calls, fallbacks = [], 0, 0, 0
    for path in (Path(folder) / "calls").glob("*.json"):
        log = json.loads(path.read_text(encoding="utf-8"))
        for c in log.get("calls", []):
            if c.get("kind") == "llm_call":
                calls += 1
                seconds.append(c.get("seconds") or 0)
                rejected += c.get("outcome") not in ("accepted", "asked for a log search")
    for t in _tickets(folder):
        fallbacks += t.get("confidence") == 0.0 and not t.get("evidence")
    avg = round(sum(seconds) / len(seconds), 1) if seconds else None
    return {"calls": calls, "rejected_calls": rejected, "avg_call_s": avg, "fallbacks": fallbacks}


def write_score(name, folder):
    NIGHT.mkdir(parents=True, exist_ok=True)
    exam, normal, facts = metrics(folder, "exam"), metrics(folder, "normal"), call_facts(folder)
    row = lambda s, m: (
        f"| {name} | {s} | {m['verdict']} / {m['severity']} / {m['escalate']} | {m['missed']} | {m['needless']} | {m['no_ticket']} | {m['planted']} |"
    )
    summary = NIGHT / "summary.md"
    if not summary.exists():
        summary.write_text(
            "| Round | Set | Verdict / severity / escalation % | Missed | Needless | No ticket | Planted text |\n|---|---|---|---|---|---|---|\n",
            encoding="utf-8",
        )
    with summary.open("a", encoding="utf-8") as f:
        f.write(row("exam", exam) + "\n" + row("normal", normal) + "\n")
        f.write(
            f"|  | calls: {facts['calls']}, rejected {facts['rejected_calls']}, avg {facts['avg_call_s']} s, fallbacks {facts['fallbacks']}, folder `{Path(folder).name}`, {datetime.now():%H:%M} | | | | | |\n"
        )
    print(
        f"{name}: exam {exam['verdict']}/{exam['severity']}/{exam['escalate']} missed {exam['missed']} needless {exam['needless']} | "
        f"normal {normal['verdict']}/{normal['severity']}/{normal['escalate']} missed {normal['missed']} needless {normal['needless']} | {facts}"
    )


def mistakes(folder):
    """Exam mistakes only, as structured fields. No alert text, so nothing attacker-written reaches the reviewer."""
    from eval import score

    alerts = {a["alert_id"]: a for a in score.load_test_set()}
    report = metrics(folder, "exam")["report"]
    tickets = {aid: t for t in _tickets(folder) for aid in t.get("alert_ids") or []}
    rows = []
    for row in report["per_alert"]:
        wrong = {f: row[f] for f in ("verdict", "severity", "escalate") if f in row and row[f][0] != row[f][1]}
        if not wrong:
            continue
        aid = row["alert_id"]
        t, a = tickets.get(aid, {}), alerts.get(aid, {})
        log_path = Path(folder) / "calls" / f"{aid}.json"
        calls = json.loads(log_path.read_text(encoding="utf-8")).get("calls", []) if log_path.exists() else []
        llm = [c for c in calls if c.get("kind") == "llm_call"]
        rows.append(
            {
                "alert_id": aid,
                "rule_id": a.get("rule_id"),
                "rule_severity": a.get("severity"),
                "wrong_ai_vs_key": wrong,
                "confidence": t.get("confidence"),
                "closed_by_rule": bool(t.get("closed_by_rule")),
                "severity_adjustments": [
                    (x.get("delta"), x.get("reason")) for x in (t.get("severity_inputs") or {}).get("adjustments", [])
                ],
                "evidence_items": len(t.get("evidence") or []),
                "injection_flags": len(t.get("injection_flags") or []),
                "llm_calls": len(llm),
                "rejected_calls": sum(c.get("outcome") != "accepted" for c in llm),
                "omitted": [c.get("omitted") for c in llm if c.get("omitted")],
            }
        )
    by_rule = collections.Counter(r["rule_id"] for r in rows)
    print(
        json.dumps({"mistakes": len(rows), "by_rule": by_rule, "rows": rows}, indent=1, ensure_ascii=False, default=str)
    )


def run_round(args):
    env = dict(
        os.environ,
        LLM_ENABLE_THINKING="false" if args.no_thinking else "true",
        AGENT_FORMAT_REMINDER="1" if args.reminder else "0",
        LLM_JSON_MODE="0" if args.no_json_mode else "1",
        AGENT_CAMPAIGN="1" if args.campaign else "0",
        AGENT_RUN_TAG=args.tag or "",
    )
    if args.lessons:
        from src.agent import lessons

        lessons.check(json.loads(Path(args.lessons).read_text(encoding="utf-8")))
        env["AGENT_LESSONS_FILE"] = str(Path(args.lessons).resolve())
    else:
        env.pop("AGENT_LESSONS_FILE", None)
    command = [PY, "scripts/exam.py", "run", "--set", "scored", "--workers", str(args.workers)]
    if args.no_thinking:
        command.append("--no-thinking")
    log = NIGHT / f"{args.name}.log"
    NIGHT.mkdir(parents=True, exist_ok=True)
    with log.open("w", encoding="utf-8") as f:
        code = subprocess.call(command, cwd=ROOT, env=env, stdout=f, stderr=subprocess.STDOUT)
    folder = (
        subprocess.check_output(
            [PY, "-c", "import sys; sys.path.insert(0,'scripts'); import exam; print(exam.results_folder())"],
            cwd=ROOT,
            env=env,
            text=True,
        )
        .strip()
        .splitlines()[-1]
    )
    print(f"run exit code {code}, folder {folder}")
    write_score(args.name, folder)
    return code


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("round")
    r.add_argument("name")
    r.add_argument("--lessons")
    r.add_argument("--no-thinking", action="store_true")
    r.add_argument("--reminder", action="store_true")
    r.add_argument("--no-json-mode", action="store_true")
    r.add_argument("--campaign", action="store_true")
    r.add_argument("--tag", help="a-z0-9, to repeat a variant in a new folder")
    r.add_argument("--workers", type=int, default=8)
    s = sub.add_parser("score")
    s.add_argument("name")
    s.add_argument("folder")
    m = sub.add_parser("mistakes")
    m.add_argument("folder")
    a = p.parse_args()
    if a.cmd == "round":
        return run_round(a)
    if a.cmd == "score":
        return write_score(a.name, a.folder)
    return mistakes(a.folder)


if __name__ == "__main__":
    sys.exit(main() or 0)
