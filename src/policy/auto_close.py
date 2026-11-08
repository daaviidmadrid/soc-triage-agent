"""Which closed tickets may skip human review. Plain code, and only about WHO looks at the result.

The close or escalate decision was already made by src/agent/triage.py and is never changed here. A ticket skips
review only if every condition holds, and each one fails towards a person: anything missing, odd or impossible to
check keeps the ticket in the human queue. Delay is never a reason: nothing here looks at time or at the SLA.

Text from the data can't close anything here. Free text is only searched for OT hosts and IPs, which can only send
a ticket to a person.
"""

import csv
import ipaddress
import json
from functools import lru_cache
from pathlib import Path

from src.policy.containment import OT_ZONES
from src.tools.alert_fields import EVENT_ID, HOSTNAME, IP, NOT_A_HOST

ZONES_FILE = Path(__file__).resolve().parents[2] / "data" / "02_inventario" / "zonas_red.csv"
LOW_RISK = ("informational", "low")
OT_RULE_PREFIX = "UC-OT-"
# Used if the zones file is missing, from the same file: the OT range must not depend on it being there.
OT_NETWORKS_FALLBACK = ("10.40.16.0/20",)
MAX_LOOKUPS = 60

VERDICTS = ("true_positive", "benign_true_positive", "false_positive")


@lru_cache(maxsize=1)
def _ot_networks():
    try:
        with open(ZONES_FILE, encoding="utf-8") as file:
            found = [row["cidr"] for row in csv.DictReader(file) if row.get("zona") in OT_ZONES]
    except (OSError, KeyError):
        found = []
    return [ipaddress.ip_network(cidr) for cidr in found or OT_NETWORKS_FALLBACK]


def _in_ot_network(ip):
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(address in network for network in _ot_networks())


def _names_and_ips(*values):
    """Every host name and IP anywhere in these values, entities and free text alike."""
    text = json.dumps(values, ensure_ascii=False, default=str)
    hosts = (name for name in HOSTNAME.findall(text) if not NOT_A_HOST.match(name) and not EVENT_ID.fullmatch(name))
    return sorted({*IP.findall(text), *hosts})


def involves_ot(ticket, alert, lookup_asset):
    """True or False, or None if it couldn't be checked. Checks the rule, the OT range and the CMDB's zone."""
    if str(alert.get("rule_id") or "").startswith(OT_RULE_PREFIX):
        return True
    names = _names_and_ips(ticket, alert)
    if any(_in_ot_network(name) for name in names):
        return True
    if len(names) > MAX_LOOKUPS:
        return None
    try:
        return any((lookup_asset(name) or {}).get("zone") in OT_ZONES for name in names)
    except Exception:  # the CMDB is unavailable: not knowing is not the same as no
        return None


def assess(ticket, alert, mode, lookup_asset):
    """Returns (eligible, failed), where failed lists the conditions that didn't hold, by key."""
    ticket = ticket if isinstance(ticket, dict) else {}
    escalation = ticket.get("escalation") if isinstance(ticket.get("escalation"), dict) else {}
    checks = ticket.get("checks") if isinstance(ticket.get("checks"), dict) else {}
    actions = ticket.get("recommended_actions") if isinstance(ticket.get("recommended_actions"), list) else []
    closed = escalation.get("escalate") is False and any(
        isinstance(a, dict) and a.get("action") == "close" for a in actions
    )
    failed = []
    if mode != "real":
        failed.append("mode")
    if not closed:
        failed.append("not_closed")
    if ticket.get("severity") not in LOW_RISK:
        failed.append("severity")
    if ticket.get("verdict") not in VERDICTS:
        failed.append("verdict")
    if "policy_flags" not in ticket or ticket["policy_flags"]:
        failed.append("policy_flags")
    if ticket.get("injection_flags"):
        failed.append("injection_flags")
    if checks.get("evidence") is not True:
        failed.append("evidence_check")
    if checks.get("authorisation") is not True:
        failed.append("authorisation_check")
    ot = involves_ot(ticket, alert if isinstance(alert, dict) else {}, lookup_asset)
    if ot is not False:
        failed.append("ot" if ot else "ot_unknown")
    return not failed, failed


def closure_reason(ticket):
    """Fixed text, with no value from the data except the rule's own ID, which is set by code."""
    rule = ticket.get("closed_by_rule") if isinstance(ticket.get("closed_by_rule"), dict) else None
    if rule:
        return f"La regla fija {rule.get('rule_id')} cerró el ticket y se cumplen todas las condiciones de cierre automático."
    return "El código de política cerró el ticket tras el triaje del LLM y se cumplen todas las condiciones de cierre automático."
