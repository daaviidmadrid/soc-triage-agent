"""Level 2: groups alerts from the same attack into one incident ticket. Plain code, no LLM.

Run from the repo root on a folder of tickets from the batch:
    python -m src.agent.correlate runs/v3-ornith-nothink [--out FOLDER]

Section 6 of politica_soc.md asks for one ticket per intrusion with all its alert_ids, and section 5
asks to escalate a chain of alerts even when each one is low. Alerts are linked only by exact
identifiers they share, and every link is kept with its reason so a person can check it:
- Two escalated alerts may link by anything they share, but by an account or a host only within
  LINK_WINDOW, because a person or a laptop shows up in unrelated alerts over a month.
- A closed alert joins an escalated one only by a specific identifier: an event, session, message,
  sender, mail domain, file hash, outside IP, domain, customer or cloud identity.
- Two closed attacks, such as blocked attempts, link by a specific identifier within LINK_WINDOW.
  False positives and authorised activity never link to each other: that noise is counted instead.
- An identifier seen in more than MAX_SHARED_BY alerts links nothing, because something everyone
  shares, such as a newsletter's sender or the online shop, says nothing about one attack.
- Never by display name, by IPs shared by many identities, or by ID numbers.
"""

import argparse
import collections
import hashlib
import ipaddress
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse

from contracts.models import Ticket
from src.tools.alert_fields import normalise_alert, parse_time
from src.tools.context import SHARED_IPS

ALERTS_FILE = Path(__file__).resolve().parents[2] / "data" / "03_alertas" / "alertas.jsonl"

LINK_WINDOW = timedelta(days=14)
MAX_SHARED_BY = 25
MAX_EVIDENCE = 40
MAX_QUESTIONS = 20

SEVERITIES = ("informational", "low", "medium", "high", "critical")
OWN_DOMAINS = ("tarvia.example",)
INTERNAL_NETWORKS = [
    ipaddress.ip_network(net) for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8")
]
IP = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")

BROAD = {"account", "host"}
SPECIFIC = {
    "event",
    "session",
    "message",
    "sender",
    "mail_domain",
    "file",
    "ip",
    "domain",
    "customer",
    "cloud",
    "ai_session",
}
LABELS = {
    "account": "misma cuenta",
    "host": "mismo equipo",
    "event": "mismo evento",
    "session": "misma sesión",
    "message": "mismo mensaje",
    "sender": "mismo remitente",
    "mail_domain": "mismo dominio de correo",
    "file": "mismo fichero",
    "ip": "misma IP externa",
    "domain": "mismo dominio",
    "customer": "mismo cliente",
    "cloud": "misma identidad cloud",
    "ai_session": "misma sesión del asistente",
}
CHAIN_REASON = (
    "Cadena de {count} alertas relacionadas (política, apartado 5): se escala aunque cada una por separado sea baja."
)


# --- identifiers -----------------------------------------------------------------------------


def _external_ip(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return value not in SHARED_IPS and not any(address in network for network in INTERNAL_NETWORKS)


def _own(domain):
    return any(domain == own or domain.endswith("." + own) for own in OWN_DOMAINS)


def _mail_domain(text):
    found = re.search(r"@([A-Za-z0-9.-]+\.[A-Za-z]{2,})", text or "")
    return found.group(1).lower() if found else None


def _items(value):
    return value if isinstance(value, list) else [value] if value else []


def _strings(value, depth=0):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict) and depth < 4:
        for item in value.values():
            yield from _strings(item, depth + 1)
    elif isinstance(value, list) and depth < 4:
        for item in value:
            yield from _strings(item, depth + 1)


def identifiers(alert, ticket=None):
    """The exact identifiers an alert carries, as (kind, value) pairs. Display names are never one."""
    alert = normalise_alert(alert)[0] if isinstance(alert, dict) else {}
    entities = alert.get("entities") if isinstance(alert.get("entities"), dict) else {}
    evidence = alert.get("evidence") if isinstance(alert.get("evidence"), dict) else {}
    found = set()
    for user in _items(entities.get("users")):
        upn = user.get("upn") if isinstance(user, dict) else user
        if isinstance(upn, str) and "@" in upn and not upn.startswith("("):
            found.add(("account", upn.lower()))
    for host in _items(entities.get("hosts")):
        name = host.get("hostname") if isinstance(host, dict) else host
        if isinstance(name, str) and name and not IP.fullmatch(name):
            found.add(("host", name.upper()))
    for value in [*_items(entities.get("ips")), *(text for text in _strings(evidence) for text in IP.findall(text))]:
        if isinstance(value, str) and _external_ip(value):
            found.add(("ip", value))
    for value in [
        *_items(entities.get("domains")),
        *(urlparse(url).hostname for url in _items(entities.get("urls")) if isinstance(url, str)),
    ]:
        if isinstance(value, str) and value and not _own(value.lower()):
            found.add(("domain", value.lower()))
    for item in _items(entities.get("files")):
        sha = item.get("sha256") if isinstance(item, dict) else item
        if isinstance(sha, str) and len(sha) == 64:
            found.add(("file", sha.lower()))
    if isinstance(evidence.get("sha256"), str) and len(evidence["sha256"]) == 64:
        found.add(("file", evidence["sha256"].lower()))
    for item in _items(entities.get("customers")):
        customer = item.get("customer_id") if isinstance(item, dict) else item
        if customer:
            found.add(("customer", str(customer)))
    for item in _items(entities.get("cloud")):
        if isinstance(item, dict):
            for key, value in item.items():
                if value and key != "account":  # one cloud account holds everything, so it says nothing
                    found.add(("cloud", str(value)))
    for session in _items(entities.get("ai_session")):
        found.add(("ai_session", str(session)))
    if evidence.get("session_id"):
        found.add(("session", str(evidence["session_id"])))
    if isinstance(evidence.get("message_id"), str) and evidence["message_id"]:
        found.add(("message", evidence["message_id"]))
        domain = _mail_domain(evidence["message_id"])
        if domain and not _own(domain):
            found.add(("mail_domain", domain))
    if isinstance(evidence.get("sender"), str) and "@" in evidence["sender"]:
        sender = evidence["sender"].strip().lower()
        domain = _mail_domain(sender)
        if domain and not _own(domain):
            found.add(("sender", sender))
            found.add(("mail_domain", domain))
    for event in _items(alert.get("related_events")):
        if isinstance(event, str) and event:
            found.add(("event", event))
    for item in (ticket or {}).get("evidence") or []:
        if isinstance(item, dict) and item.get("event_id"):
            found.add(("event", str(item["event_id"])))
    return found


@lru_cache(maxsize=2)
def _history(path, modified):
    """How many alerts in the history carry each identifier. Only counts, never which alert."""
    counts, seen = collections.Counter(), set()
    try:
        with open(path, encoding="utf-8") as file:
            for line in file:
                if line.strip():
                    alert = json.loads(line)
                    seen.add(alert.get("alert_id"))
                    counts.update(identifiers(alert))
    except OSError:
        pass
    return counts, frozenset(seen)


def shared_by(alerts, path=ALERTS_FILE):
    """Counts over the history plus any alert that isn't in it, such as the alerts given to us on the day."""
    path = Path(path)
    history, seen = _history(str(path), path.stat().st_mtime if path.exists() else 0)
    counts = collections.Counter(history)
    for alert in alerts:
        if alert.get("alert_id") not in seen:
            counts.update(identifiers(alert))
    return counts


# --- linking ---------------------------------------------------------------------------------


def role(ticket):
    """escalated: a person will look at it. attack: a closed true positive, such as a blocked attempt. noise: everything else."""
    if (ticket.get("escalation") or {}).get("escalate") is True:
        return "escalated"
    return "attack" if ticket.get("verdict") == "true_positive" else "noise"


def allowed_kinds(first, second, close_in_time):
    roles = {first, second}
    if roles == {"escalated"}:
        return SPECIFIC | BROAD if close_in_time else SPECIFIC
    if "escalated" in roles:
        return SPECIFIC
    if roles == {"attack"} and close_in_time:
        return SPECIFIC
    return set()


def _time(alert):
    moment = parse_time(alert.get("created_at"))[0]
    return datetime.fromisoformat(moment.replace("Z", "+00:00")) if moment else None


def _reason(kind, value):
    return f"{LABELS[kind]} ({value})"


def find_links(items, counts):
    """Returns {(first id, second id): [reasons]} for every pair of alerts that may link."""
    by_key = collections.defaultdict(list)
    for alert_id, item in items.items():
        for key in item["ids"]:
            if counts.get(key, 0) <= MAX_SHARED_BY:
                by_key[key].append(alert_id)
    links = collections.defaultdict(list)
    for (kind, value), members in sorted(by_key.items()):
        for i, first in enumerate(members):
            for second in members[i + 1 :]:
                a, b = items[first], items[second]
                close = bool(a["time"] and b["time"] and abs(a["time"] - b["time"]) <= LINK_WINDOW)
                if kind in allowed_kinds(a["role"], b["role"], close):
                    pair = tuple(sorted((first, second)))
                    links[pair].append(_reason(kind, value))
    return links


def _groups(alert_ids, links):
    parent = {alert_id: alert_id for alert_id in alert_ids}

    def find(alert_id):
        while parent[alert_id] != alert_id:
            parent[alert_id] = parent[parent[alert_id]]
            alert_id = parent[alert_id]
        return alert_id

    for first, second in links:
        parent[find(first)] = find(second)
    members = collections.defaultdict(list)
    for alert_id in alert_ids:
        members[find(alert_id)].append(alert_id)
    return [group for group in members.values() if len(group) > 1]


# --- the incident ticket ---------------------------------------------------------------------


def _dedupe(items, key):
    seen, out = set(), []
    for item in items:
        k = key(item)
        if k not in seen:
            seen.add(k)
            out.append(item)
    return out


def incident_id_for(alert_ids):
    """The same alerts always give the same incident ID, so a report and its level 2 incident share it."""
    return "INC-" + hashlib.sha256("|".join(sorted(alert_ids)).encode()).hexdigest()[:10].upper()


def merge(members, links, items):
    """One ticket for the whole incident. Plain code decides everything. Each member keeps its own ticket."""
    ordered = sorted(
        members, key=lambda alert_id: (items[alert_id]["time"] or datetime.max.replace(tzinfo=timezone.utc), alert_id)
    )
    tickets = [items[alert_id]["ticket"] for alert_id in ordered]
    alerts = [items[alert_id]["alert"] for alert_id in ordered]
    incident_id = incident_id_for(members)
    severity = max(
        (t.get("severity") for t in tickets if t.get("severity") in SEVERITIES), key=SEVERITIES.index, default="medium"
    )
    verdicts = [t.get("verdict") for t in tickets]
    verdict = next(
        (v for v in ("true_positive", "needs_more_info") if v in verdicts),
        "benign_true_positive" if set(verdicts) == {"benign_true_positive"} else "false_positive",
    )
    rules = {a.get("rule_id") for a in alerts if a.get("rule_id")}
    chain = len(rules) >= 2 and "true_positive" in verdicts
    reasons = [r for t in tickets for r in [(t.get("escalation") or {}).get("reason")] if r]
    if chain:
        reasons.insert(0, CHAIN_REASON.format(count=len(members)))
    escalate = chain or any((t.get("escalation") or {}).get("escalate") is True for t in tickets)
    target = ("N2 de guardia (teléfono)" if severity == "critical" else "N2") if escalate else ""
    reason = " ".join(_dedupe(reasons, str))[:1500]
    main = max(tickets, key=lambda t: SEVERITIES.index(t.get("severity")) if t.get("severity") in SEVERITIES else 0)
    times = [items[alert_id]["time"] for alert_id in ordered if items[alert_id]["time"]]
    span = f" entre {times[0]:%Y-%m-%d %H:%M} y {times[-1]:%Y-%m-%d %H:%M} UTC" if times else ""
    kinds = collections.Counter(r.split(" (")[0] for rs in links.values() for r in rs)
    summary = (
        f"{len(members)} alertas relacionadas{span}: "
        + "; ".join(f"{a.get('alert_id')} {a.get('rule_name') or a.get('rule_id') or ''}".strip() for a in alerts)
        + ". Se agrupan por "
        + ", ".join(k for k, _ in kinds.most_common(4))
        + "."
    )
    actions = [
        {
            "action": "escalate" if escalate else "close",
            "target": target or "ticket",
            "requires_approval": False,
            "justification": reason or summary[:200],
        }
    ]
    actions += _dedupe(
        [a for t in tickets for a in t.get("recommended_actions") or [] if a.get("requires_approval")],
        lambda a: (a.get("action"), a.get("target")),
    )
    affected = {
        field: _dedupe([x for t in tickets for x in (t.get("affected") or {}).get(field) or []], json.dumps)
        for field in ("users", "hosts", "business_services", "customers")
    }
    group_links = [
        {"alert_id": second, "linked_to": first, "reasons": reasons_}
        for (first, second), reasons_ in sorted(links.items())
    ]
    ticket = Ticket(
        ticket_id=incident_id,
        alert_ids=ordered,
        title=f"Incidente: {main.get('title') or alerts[0].get('rule_name') or incident_id}",
        verdict=verdict,
        confidence=min(
            (t.get("confidence") for t in tickets if isinstance(t.get("confidence"), (int, float))), default=0.0
        ),
        severity=severity,
        severity_rationale=f"La severidad más alta de las {len(members)} alertas del incidente.",
        affected=affected,
        summary=summary,
        evidence=_dedupe(
            [e for t in tickets for e in t.get("evidence") or []], lambda e: (e.get("event_id"), e.get("finding"))
        )[:MAX_EVIDENCE],
        enrichment=_dedupe([e for t in tickets for e in t.get("enrichment") or []], lambda e: e.get("indicator")),
        mitre=_dedupe([m for t in tickets for m in t.get("mitre") or []], str),
        recommended_actions=actions,
        escalation={"escalate": escalate, "to": target, "reason": reason},
        open_questions=_dedupe([q for t in tickets for q in t.get("open_questions") or []], str)[:MAX_QUESTIONS],
        injection_flags=_dedupe([f for t in tickets for f in t.get("injection_flags") or []], json.dumps),
        group_links=group_links,
    )
    member_rows = [
        {
            "alert_id": alert_id,
            "ticket_id": items[alert_id]["ticket"].get("ticket_id"),
            "rule_id": items[alert_id]["alert"].get("rule_id"),
            "rule_name": items[alert_id]["alert"].get("rule_name"),
            "created_at": items[alert_id]["alert"].get("created_at"),
            "verdict": items[alert_id]["ticket"].get("verdict"),
            "severity": items[alert_id]["ticket"].get("severity"),
            "escalate": (items[alert_id]["ticket"].get("escalation") or {}).get("escalate") is True,
        }
        for alert_id in ordered
    ]
    return {
        "incident_id": incident_id,
        "chain": chain,
        "members": member_rows,
        "ticket": ticket.model_dump(mode="json"),
    }


def _noise(items, grouped):
    """Closed alerts left on their own, counted by rule and verdict, with how many sources they came from."""
    buckets = collections.defaultdict(lambda: {"count": 0, "sources": set(), "examples": []})
    for alert_id, item in items.items():
        if alert_id in grouped or item["role"] == "escalated":
            continue
        alert, ticket = item["alert"], item["ticket"]
        bucket = buckets[(alert.get("rule_id") or "", ticket.get("verdict") or "")]
        bucket["count"] += 1
        bucket["rule_name"] = alert.get("rule_name")
        bucket["sources"] |= {value for kind, value in item["ids"] if kind in ("ip", "sender", "domain", "customer")}
        if len(bucket["examples"]) < 3:
            bucket["examples"].append(alert_id)
    rows = [
        {
            "rule_id": rule,
            "rule_name": b["rule_name"],
            "verdict": verdict,
            "count": b["count"],
            "sources": len(b["sources"]),
            "examples": b["examples"],
        }
        for (rule, verdict), b in buckets.items()
    ]
    return sorted(rows, key=lambda row: (-row["count"], row["rule_id"]))


def correlate(pairs, history=ALERTS_FILE):
    """pairs: (alert, ticket) for each triaged alert. Returns incidents, which alert is in which, and the counted noise."""
    items = {}
    for alert, ticket in pairs:
        if not isinstance(alert, dict) or not isinstance(ticket, dict) or not alert.get("alert_id"):
            continue
        alert = normalise_alert(alert)[0]
        items[alert["alert_id"]] = {
            "alert": alert,
            "ticket": ticket,
            "ids": identifiers(alert, ticket),
            "role": role(ticket),
            "time": _time(alert),
        }
    counts = shared_by([item["alert"] for item in items.values()], history)
    links = find_links(items, counts)
    incidents = []
    for group in _groups(list(items), links):
        members = set(group)
        incidents.append(merge(group, {pair: r for pair, r in links.items() if set(pair) <= members}, items))
    incidents.sort(
        key=lambda inc: (-SEVERITIES.index(inc["ticket"]["severity"]), inc["members"][0]["created_at"] or "")
    )
    memberships = {member["alert_id"]: inc["incident_id"] for inc in incidents for member in inc["members"]}
    return {
        "incidents": incidents,
        "memberships": memberships,
        "noise": _noise(items, set(memberships)),
        "alerts": len(items),
        "settings": {"link_window_days": LINK_WINDOW.days, "max_shared_by": MAX_SHARED_BY},
    }


# --- command line ----------------------------------------------------------------------------


def load_folder(folder, alerts_file=ALERTS_FILE):
    """Tickets saved by the batch, with their alerts from the dataset."""
    tickets = {}
    for path in sorted(Path(folder).glob("*.json")):
        ticket = json.loads(path.read_text(encoding="utf-8"))
        for alert_id in ticket.get("alert_ids") or []:
            tickets[alert_id] = ticket
    alerts = {}
    with open(alerts_file, encoding="utf-8") as file:
        for line in file:
            if line.strip():
                alert = json.loads(line)
                if alert.get("alert_id") in tickets:
                    alerts[alert["alert_id"]] = alert
    return [(alerts[alert_id], ticket) for alert_id, ticket in tickets.items() if alert_id in alerts]


def main(arguments=None):
    parser = argparse.ArgumentParser(description="Groups the tickets in a folder into incidents.")
    parser.add_argument("folder")
    parser.add_argument("--out", help="where to write incidents (default: FOLDER/incidents)")
    args = parser.parse_args(arguments)
    result = correlate(load_folder(args.folder))
    out = Path(args.out or Path(args.folder) / "incidents")
    out.mkdir(parents=True, exist_ok=True)
    for incident in result["incidents"]:
        (out / f"{incident['incident_id']}.json").write_text(
            json.dumps(incident, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    (out / "noise.json").write_text(json.dumps(result["noise"], ensure_ascii=False, indent=2), encoding="utf-8")
    print(
        f"{result['alerts']} alerts, {len(result['incidents'])} incidents holding {len(result['memberships'])} of them. Written to {out}"
    )
    for incident in result["incidents"]:
        t = incident["ticket"]
        print(
            f"\n{incident['incident_id']}  {t['severity']}  {'escalate' if t['escalation']['escalate'] else 'close'}{'  CHAIN' if incident['chain'] else ''}  {len(incident['members'])} alerts"
        )
        for member in incident["members"]:
            print(
                f"  {member['alert_id']}  {member['rule_id']}  {member['verdict']}  {member['severity']}  {'escalate' if member['escalate'] else 'close'}"
            )
        for link in t["group_links"]:
            print(f"    {link['alert_id']} with {link['linked_to']}: {'; '.join(link['reasons'][:3])}")
    print("\nCounted, not grouped:")
    for row in result["noise"][:12]:
        print(f"  {row['count']:4}  {row['rule_id']}  {row['verdict']}  from {row['sources']} distinct sources")
    return 0


if __name__ == "__main__":
    sys.exit(main())
