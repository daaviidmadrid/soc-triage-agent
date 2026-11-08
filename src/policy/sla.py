"""SLA targets and the arithmetic on them. The one source of these numbers: the API and the UI read them from here.

Source: data/01_contexto/politica_soc.md, section 3. The policy gives informational a daily batch review and no time,
so it has no deadline here rather than an invented one.

The clock starts when an alert enters the store, not at its timestamp in the data: imported alerts are historical
and would otherwise all show as breached. Everything here takes severities and times worked out by code. Text from
the data never reaches it.
"""
from datetime import datetime, timedelta, timezone

from src.policy.severity import LEVELS

TARGETS = {
    "critical": {"seconds": 15 * 60, "label": "15 min", "escalation": "Inmediato a N2 de guardia por teléfono", "notify": ["Responsable SOC", "CISO"]},
    "high": {"seconds": 30 * 60, "label": "30 min", "escalation": "A N2 en la misma jornada", "notify": ["Responsable SOC"]},
    "medium": {"seconds": 4 * 3600, "label": "4 h", "escalation": "Si tras el triaje hay indicios de compromiso", "notify": []},
    "low": {"seconds": 24 * 3600, "label": "24 h", "escalation": "No", "notify": []},
    "informational": {"seconds": None, "label": "lote diario", "escalation": "No", "notify": []},
}
# Severities whose escalation a person has to confirm, because the system calls nobody.
CONFIRMED_ESCALATION = ("critical", "high")
DEFAULT_SEVERITY = "medium"
# Under this share of its time left, an open alert is at risk.
AT_RISK_FRACTION = 0.25


def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def format_time(moment):
    return moment.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def rule_severity(alert):
    """(severity, assumed). Same default as triage for an alert with no usable severity. Only an exact value counts."""
    value = alert.get("severity") if isinstance(alert, dict) else None
    return (value, False) if value in TARGETS else (DEFAULT_SEVERITY, True)


def deadline_for(started_at, severity):
    """The deadline as text, or None for the daily batch."""
    seconds = TARGETS[severity]["seconds"]
    return None if seconds is None else format_time(parse_time(started_at) + timedelta(seconds=seconds))


def is_higher(severity, than):
    return LEVELS.index(severity) > LEVELS.index(than)


def outcome(stopped_at, deadline):
    """met or breached for a stopped clock. Exactly on the deadline still counts as met."""
    return "met" if deadline is None or parse_time(stopped_at) <= parse_time(deadline) else "breached"


def live_status(deadline, target_seconds, now):
    """on_track, at_risk, breached or batch for a clock still running. Exactly on the deadline isn't breached yet."""
    if deadline is None:
        return "batch"
    left = (parse_time(deadline) - parse_time(now)).total_seconds()
    if left < 0:
        return "breached"
    return "at_risk" if left <= target_seconds * AT_RISK_FRACTION else "on_track"


def required_action(severity):
    """What the policy requires a person to do, for the severities where a person must confirm it."""
    return TARGETS[severity]["escalation"] if severity in CONFIRMED_ESCALATION else None
