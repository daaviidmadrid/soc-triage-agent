"""Severity matrix from the SOC policy. Branch: data/severity

Source: data/01_contexto/politica_soc.md, section 2. Where the sample ticket
(ticket_ejemplo.json) disagrees, this follows the policy: the sample drops two levels
(blocked by WAF, then "path does not exist"), which breaks the one-level cap.
"""
import csv
from pathlib import Path

LEVELS = ["informational", "low", "medium", "high", "critical"]
CRITICALITIES = ["Baja", "Media", "Alta", "Crítica"]

# Rule severity x criticality of the most critical affected asset or identity.
MATRIX = {
    #                Baja             Media            Alta        Crítica
    "informational": {"Baja": "informational", "Media": "informational", "Alta": "low",      "Crítica": "low"},
    "low":           {"Baja": "informational", "Media": "low",           "Alta": "low",      "Crítica": "medium"},
    "medium":        {"Baja": "low",           "Media": "medium",        "Alta": "medium",   "Crítica": "high"},
    "high":          {"Baja": "medium",        "Media": "high",          "Alta": "high",     "Crítica": "critical"},
    "critical":      {"Baja": "high",          "Media": "critical",      "Alta": "critical", "Crítica": "critical"},
}

MAX_ADJUSTMENT = 1  # policy: at most one level up or down in total

# The policy allows informational or low for an approved change or authorised flow.
# docs/decisions.md (analysis section 8): low, or informational if the base already is.
AUTHORISED_SEVERITY = "low"

_CRIT_ALIASES = {
    "baja": "Baja", "low": "Baja",
    "media": "Media", "medium": "Media",
    "alta": "Alta", "high": "Alta",
    "crítica": "Crítica", "critica": "Crítica", "critical": "Crítica",
}


def normalise_criticality(value):
    c = _CRIT_ALIASES.get(str(value).strip().lower())
    if not c:
        raise ValueError(f"unknown criticality: {value!r}")
    return c


def _level(value):
    v = str(value).strip().lower()
    if v not in LEVELS:
        raise ValueError(f"unknown severity: {value!r}")
    return v


def _adjustment(item):
    if isinstance(item, dict):
        return {"delta": int(item["delta"]), "reason": item.get("reason", "")}
    if isinstance(item, (tuple, list)):
        return {"delta": int(item[0]), "reason": item[1] if len(item) > 1 else ""}
    return {"delta": int(item.delta), "reason": getattr(item, "reason", "")}


def _shift(level, delta):
    i = min(max(LEVELS.index(level) + delta, 0), len(LEVELS) - 1)
    return LEVELS[i]


def compute_severity(rule_severity, criticality, adjustments=(), runbook_floor=None, authorised=False,
                     evidence_complete=True):
    """Final severity per policy section 2.

    adjustments: items with delta (+1/-1) and reason, as dicts, (delta, reason) tuples or objects.
    Their sum is capped at one level up or down. runbook_floor can then raise the result.
    authorised=True (approved change or flow) gives AUTHORISED_SEVERITY, or informational
    if the base already is.
    evidence_complete=False (a search was truncated or rows were cut from the context):
    downward adjustments are ignored, since missing rows can't show "no later activity"
    (analysis section 4). Upward ones still apply.

    Returns {"base", "adjustments", "net_delta", "floor", "authorised", "evidence_complete",
    "final", "reason"}. `adjustments` lists every item given, with "applied" set.
    """
    rule = _level(rule_severity)
    crit = normalise_criticality(criticality)
    base = MATRIX[rule][crit]
    adj = [_adjustment(a) for a in adjustments]
    for a in adj:
        a["applied"] = evidence_complete or a["delta"] >= 0
    requested = sum(a["delta"] for a in adj if a["applied"])
    net = max(-MAX_ADJUSTMENT, min(MAX_ADJUSTMENT, requested))
    final = _shift(base, net)
    parts = [f"Regla {rule} sobre activo de criticidad {crit} = {base}"]
    for a in adj:
        note = "" if a["applied"] else " (no aplicado: evidencia incompleta)"
        parts.append(f"{a['delta']:+d} {a['reason']}{note}".strip())
    if net != requested:
        parts.append(f"ajuste total limitado a {net:+d} (política: máximo un nivel)")
    if net:
        parts.append(f"tras ajustes: {final}")
    floor = _level(runbook_floor) if runbook_floor else None
    if floor and LEVELS.index(floor) > LEVELS.index(final):
        final = floor
        parts.append(f"mínimo del runbook: {floor}")
    if authorised:
        final = "informational" if base == "informational" else AUTHORISED_SEVERITY
        parts.append(f"actividad autorizada (cambio o flujo aprobado): {final}")
    return {
        "base": base,
        "adjustments": adj,
        "net_delta": net,
        "floor": floor,
        "authorised": bool(authorised),
        "evidence_complete": bool(evidence_complete),
        "final": final,
        "reason": "; ".join(parts) + ".",
    }


# --- Criticality ---------------------------------------------------------------

SERVICES_CSV = Path(__file__).resolve().parents[2] / "data" / "02_inventario" / "servicios_negocio.csv"

# docs/decisions.md (analysis section 6): the machine named, then the user's workstation,
# then Crítica for RB-05 (the online shop), then Media. Media and Alta give the same matrix
# result for every alert, so only rules whose service is Crítica or Baja matter here.
RULE_SERVICE = {
    "UC-WEB-001": "Tienda online y app",
    "UC-WEB-002": "Tienda online y app",
    "UC-WEB-003": "Tienda online y app",
    "UC-EDR-009": "Tienda online y app",
}

DEFAULT_CRITICALITY = "Media"

_services = None


def service_criticality(name):
    global _services
    if _services is None:
        with open(SERVICES_CSV, encoding="utf-8") as f:
            _services = {r["servicio"]: r["criticidad"] for r in csv.DictReader(f)}
    c = _services.get(name)
    return normalise_criticality(c) if c else None


def _get(obj, key, default=None):
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _max_crit(pairs):
    """pairs: (criticality, label). Returns the most critical pair or None."""
    pairs = [(normalise_criticality(c), label) for c, label in pairs if c]
    return max(pairs, key=lambda p: CRITICALITIES.index(p[0])) if pairs else None


def resolve_criticality(alert, context):
    """(criticality, source) following docs/decisions.md: the machine named, then the
    user's workstation, then the service the rule targets (RULE_SERVICE), then
    DEFAULT_CRITICALITY. The source says which step decided, for the UI.

    context: Context or dict with `entities` and `assets` (and `users` for workstations).
    A machine counts as named if it is a host entity, or an IP entity that the CMDB knows.
    """
    assets = {}
    for a in _get(context, "assets", []) or []:
        assets[str(a.get("hostname", "")).lower()] = a
        if a.get("ip"):
            assets[a["ip"]] = a
    named = []
    for e in _get(context, "entities", []) or []:
        etype, value = _get(e, "type"), str(_get(e, "value"))
        if etype in ("host", "ip"):
            a = assets.get(value.lower()) or assets.get(value)
            if a:
                named.append((a.get("criticality"), f"asset:{a['hostname']}"))
    best = _max_crit(named)
    if best:
        return best

    workstations = []
    for u in _get(context, "users", []) or []:
        ws = u.get("workstation")
        a = assets.get(str(ws).lower()) if ws else None
        if a:
            workstations.append((a.get("criticality"), f"workstation:{a['hostname']} ({u.get('upn')})"))
    best = _max_crit(workstations)
    if best:
        return best

    service = RULE_SERVICE.get(alert.get("rule_id"))
    if service:
        c = service_criticality(service)
        if c:
            return c, f"service:{service}"

    return DEFAULT_CRITICALITY, "default"
