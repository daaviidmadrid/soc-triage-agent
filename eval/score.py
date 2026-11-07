"""Compares tickets with eval/labels.csv and prints a scorecard. Branch: data/eval

Usage: python eval/score.py   (reads runs/*.json and eval/labels.csv)
"""
import csv
import glob
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVAL = ROOT / "eval"
SAMPLE = ROOT / "data" / "03_alertas" / "alertas_muestra_desarrollo.jsonl"
ALL_ALERTS = ROOT / "data" / "03_alertas" / "alertas.jsonl"
EXTRA_FILE = EVAL / "extra_alerts.txt"
HELDOUT_FILE = EVAL / "heldout_alerts.txt"
LABELS_FILE = EVAL / "labels.csv"
RUNS_GLOB = str(ROOT / "runs" / "*.json")

LEVELS = ["informational", "low", "medium", "high", "critical"]


def _read_ids(path):
    """One alert ID per line; blank lines and # comments ignored."""
    if not Path(path).exists():
        return []
    ids = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            ids.append(line)
    return ids


def _read_jsonl(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(l) for l in f if l.strip()]


def load_test_set():
    """Alerts to tune on: the development sample, plus eval/extra_alerts.txt,
    minus eval/heldout_alerts.txt. Returns full alert dicts, sample order first."""
    heldout = set(_read_ids(HELDOUT_FILE))
    alerts = _read_jsonl(SAMPLE)
    have = {a["alert_id"] for a in alerts}
    extra = [i for i in _read_ids(EXTRA_FILE) if i not in have]
    if extra:
        wanted = set(extra)
        by_id = {a["alert_id"]: a for a in _read_jsonl(ALL_ALERTS) if a["alert_id"] in wanted}
        missing = wanted - set(by_id)
        if missing:
            raise ValueError(f"extra alerts not found in alertas.jsonl: {sorted(missing)}")
        alerts += [by_id[i] for i in extra]
    return [a for a in alerts if a["alert_id"] not in heldout]


# --- reading tickets and labels -------------------------------------------------

def load_tickets(path):
    """Tickets from one run file. The format isn't decided yet; this accepts a list of
    tickets, one ticket, or {"tickets": [...]}. Change only this function when it is."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict):
        data = data.get("tickets", [data])
    return list(data)


def load_labels(path=LABELS_FILE):
    with open(path, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def _bool(v):
    if isinstance(v, bool):
        return v
    s = str(v).strip().lower()
    if s in ("true", "1", "yes", "si", "sí", "y"):
        return True
    if s in ("false", "0", "no", "n"):
        return False
    return None  # blank or unknown: not labelled


def _ticket_escalates(t):
    esc = t.get("escalation")
    if isinstance(esc, dict) and "escalate" in esc:
        return _bool(esc["escalate"])
    return _bool(t.get("escalate", ""))


def _norm(v):
    return str(v or "").strip().lower()


# --- scoring --------------------------------------------------------------------

def score(tickets, labels):
    """Score tickets against labels. Pure function: takes lists of dicts.

    A ticket covers every alert in its alert_ids. Each metric only counts alerts that
    have a ticket and a value for that field in the label.
    Missed attacks: labelled true_positive but with no ticket, a non-true_positive
    verdict, or no escalation.
    """
    by_alert, dupes = {}, set()
    for t in tickets:
        for aid in t.get("alert_ids") or []:
            if aid in by_alert:
                dupes.add(aid)
                continue  # first ticket wins; duplicates are reported
            by_alert[aid] = t

    counts = {k: [0, 0] for k in ("verdict", "severity_exact", "severity_within_one", "escalation")}
    no_ticket, missed, rows = [], [], []
    for lab in labels:
        aid = lab["alert_id"]
        t = by_alert.get(aid)
        lv, ls, le = _norm(lab.get("verdict")), _norm(lab.get("severity")), _bool(lab.get("escalate"))
        if t is None:
            no_ticket.append(aid)
            if lv == "true_positive":
                missed.append({"alert_id": aid, "reason": "no ticket"})
            continue
        tv, ts, te = _norm(t.get("verdict")), _norm(t.get("severity")), _ticket_escalates(t)
        row = {"alert_id": aid, "ticket_id": t.get("ticket_id")}
        if lv:
            counts["verdict"][1] += 1
            counts["verdict"][0] += tv == lv
            row["verdict"] = (tv, lv)
        if ls in LEVELS:
            counts["severity_exact"][1] += 1
            counts["severity_within_one"][1] += 1
            counts["severity_exact"][0] += ts == ls
            if ts in LEVELS:
                counts["severity_within_one"][0] += abs(LEVELS.index(ts) - LEVELS.index(ls)) <= 1
            row["severity"] = (ts, ls)
        if le is not None:
            counts["escalation"][1] += 1
            counts["escalation"][0] += te == le
            row["escalate"] = (te, le)
        rows.append(row)
        if lv == "true_positive":
            reasons = []
            if tv != "true_positive":
                reasons.append(f"verdict {tv or 'missing'}")
            if te is not True:
                reasons.append("not escalated")
            if reasons:
                missed.append({"alert_id": aid, "ticket_id": t.get("ticket_id"), "reason": ", ".join(reasons)})

    metrics = {k: {"correct": c, "total": n, "rate": (c / n if n else None)} for k, (c, n) in counts.items()}
    return {
        "labelled": len(labels),
        "metrics": metrics,
        "no_ticket": no_ticket,
        "missed_attacks": missed,
        "alerts_in_several_tickets": sorted(dupes),
        "per_alert": rows,
    }


def _print(report):
    print(f"Labelled alerts: {report['labelled']}")
    for name, m in report["metrics"].items():
        rate = f"{m['rate']:.0%}" if m["rate"] is not None else "n/a"
        print(f"  {name:<22} {m['correct']}/{m['total']}  {rate}")
    print(f"Alerts with no ticket: {len(report['no_ticket'])}")
    for aid in report["no_ticket"]:
        print(f"  {aid}")
    print(f"MISSED ATTACKS: {len(report['missed_attacks'])}")
    for m in report["missed_attacks"]:
        print(f"  {m['alert_id']}  {m.get('ticket_id') or '-'}  {m['reason']}")
    if report["alerts_in_several_tickets"]:
        print(f"Alerts in several tickets: {', '.join(report['alerts_in_several_tickets'])}")


def main():
    tickets = []
    for path in sorted(glob.glob(RUNS_GLOB)):
        tickets += load_tickets(path)
    test_ids = {a["alert_id"] for a in load_test_set()}
    labels = [l for l in load_labels() if l["alert_id"] in test_ids]
    if not labels:
        print("No labels for the test set in eval/labels.csv yet.")
    print(f"Tickets read: {len(tickets)} from {RUNS_GLOB}")
    _print(score(tickets, labels))


if __name__ == "__main__":
    main()
