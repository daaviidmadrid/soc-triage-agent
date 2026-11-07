"""Gathers everything known about an alert. Branch: data/context

Plain code, no LLM. Text from the data (subjects, prompts, descriptions) is copied as is:
it is evidence, never instructions, and it is never removed or cleaned for what it says.
"""
import json
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from contracts.models import Context, Entity, TruncatedSource
from src.policy.severity import resolve_criticality
from src.tools import api_client
from src.tools.logs import LOG_FIELDS, search_logs

# Policy section 1.4: correlate with logs of the same entities within ±24 h.
CONTEXT_WINDOW = timedelta(hours=24)

# Maximum size of the whole context, as characters of JSON. Analysis section 5: the prompt
# budget is 28,000 characters, about 14,000 of them for data.
MAX_CONTEXT_CHARS = 14_000

# IPs shared by many identities: searching them floods the context with other people's rows
# (one identity alert: 5 rows for the user, 2,031 for the IP). We count their rows instead.
# Analysis section 5 found 8 IPs with >20 identities in idp_signins, but only these two have
# successful sign-ins from them (~1,065 identities each, Spanish ISPs). The other six are
# Tor/hosting IPs that failed against ~27 accounts each: password spraying, i.e. evidence,
# so they are deliberately searched as normal.
SHARED_IPS = {"198.18.200.10", "198.18.200.11"}

# Event timestamps are UTC. The change calendar has no offset; analysis section 7 shows it is
# Madrid wall time (scanner traffic moves one UTC hour at the 25 Oct clock change), so it is
# converted with zoneinfo, never a fixed offset. This is an inference, not a declared zone.
MADRID = ZoneInfo("Europe/Madrid")
CHANGES_TZ = MADRID

# Prefix of an event_id in related_events -> log source.
EVENT_PREFIX_SOURCE = {
    "ADE": "ad_events", "AIG": "ai_gateway", "CI": "cicd_builds", "CT": "cloudtrail",
    "DLP": "dlp", "DNS": "dns", "ECO": "ecom_account", "ECA": "ecom_auth",
    "EDR": "edr_events", "EML": "email", "CLK": "email_clicks", "FW": "firewall",
    "AUD": "idp_audit", "SIGN": "idp_signins", "PRX": "proxy", "SQL": "sql_audit",
    "VPN": "vpn", "WAF": "waf",
}

# Log sources searched for each rule, from the runbooks' checks. Sources of the
# alert's related_events are always added.
# Analysis section 5 maps sources from the runbook checks in the same way.
_PHISH = ["email", "email_clicks", "proxy", "edr_events", "idp_signins"]
_IDP = ["idp_signins", "idp_audit", "vpn"]
_EDR = ["edr_events", "proxy", "firewall", "dns"]
_NET = ["proxy", "dns", "firewall", "edr_events"]
RULE_LOG_SOURCES = {
    "UC-EML-001": _PHISH, "UC-EML-002": _PHISH, "UC-EML-003": _PHISH,
    "UC-EML-004": ["email", "idp_signins", "idp_audit"],
    "UC-IDP-001": _IDP, "UC-IDP-002": _IDP, "UC-IDP-003": _IDP, "UC-IDP-004": _IDP,
    "UC-IDP-005": _IDP + ["email"], "UC-IDP-006": _IDP, "UC-IDP-007": _IDP,
    "UC-IDP-008": ["ad_events", "edr_events", "idp_signins"],
    "UC-VPN-001": ["vpn", "firewall", "idp_signins"],
    "UC-EDR-001": _EDR, "UC-EDR-002": _EDR, "UC-EDR-003": _EDR, "UC-EDR-004": _EDR,
    "UC-EDR-005": _EDR, "UC-EDR-006": _EDR, "UC-EDR-007": _EDR, "UC-EDR-008": _EDR,
    "UC-EDR-010": _EDR, "UC-EDR-011": _EDR, "UC-EDR-012": _EDR,
    "UC-EDR-009": ["edr_events", "waf", "firewall"],
    "UC-NET-001": _NET, "UC-NET-002": _NET, "UC-NET-005": _NET, "UC-NET-006": _NET,
    "UC-NET-003": ["firewall", "edr_events"], "UC-NET-004": ["firewall", "edr_events", "ad_events"],
    "UC-WEB-001": ["waf"],
    "UC-WEB-002": ["waf", "ecom_auth", "ecom_account"],
    "UC-WEB-003": ["ecom_account", "ecom_auth"],
    "UC-CLD-001": ["cloudtrail"], "UC-CLD-002": ["cloudtrail"],
    "UC-CLD-003": ["cloudtrail"], "UC-CLD-004": ["cloudtrail"],
    "UC-DLP-001": ["dlp", "sql_audit", "edr_events", "proxy"],
    "UC-DLP-002": ["dlp", "email", "sql_audit", "edr_events"],
    "UC-AI-001": ["ai_gateway"], "UC-AI-002": ["ai_gateway"],
    "UC-OT-001": ["firewall", "edr_events"],
    "UC-DEV-001": ["cicd_builds", "cloudtrail"],
}

# Entity types searched in logs as an exact value in any field. Others (process names,
# cloud account) would match far too much or nothing.
VALUE_TYPES = {"domain", "url", "file", "customer", "ai_session", "cloud_identity", "access_key", "bucket"}
_CLOUD_TYPES = {"identity": "cloud_identity", "new_user": "cloud_identity", "access_key": "access_key",
                "bucket": "bucket", "account": "cloud_account"}


def _parse_utc(s):
    return datetime.fromisoformat(str(s).replace("Z", "+00:00"))


def to_madrid(ts):
    """ISO UTC string -> ISO Madrid string with offset, or None if unparseable."""
    try:
        return _parse_utc(ts).astimezone(MADRID).isoformat(timespec="milliseconds")
    except (TypeError, ValueError):
        return None


def _is_placeholder_user(upn):
    # e.g. "(12 cuentas)" in password-spraying alerts
    return "@" not in upn or upn.startswith("(")


def _items(v):
    return v if isinstance(v, list) else [v]


def _parse_entities(alert):
    """Alert entities -> list of (type, value, extra). Unknown shapes become generic entries."""
    out = []
    ents = alert.get("entities") or {}
    if not isinstance(ents, dict):
        ents = {"other": ents}
    for key, raw in ents.items():
        for it in _items(raw):
            if it in (None, "", {}):
                continue
            if key == "users":
                upn = it.get("upn") if isinstance(it, dict) else it
                out.append(("user", str(upn), {}))
            elif key == "hosts":
                if isinstance(it, dict):
                    out.append(("host", str(it.get("hostname") or it.get("ip")), {"ip": it.get("ip")}))
                else:
                    out.append(("host", str(it), {}))
            elif key == "ips":
                out.append(("ip", str(it), {}))
            elif key == "domains":
                out.append(("domain", str(it), {}))
            elif key == "urls":
                out.append(("url", str(it), {}))
            elif key == "files":
                if isinstance(it, dict):
                    out.append(("file", str(it.get("sha256") or it.get("name")), {"has_sha": bool(it.get("sha256"))}))
                else:
                    out.append(("file", str(it), {"has_sha": len(str(it)) == 64}))
            elif key == "processes":
                out.append(("process", str(it.get("name") if isinstance(it, dict) else it), {}))
            elif key == "customers":
                out.append(("customer", str(it.get("customer_id") if isinstance(it, dict) else it), {}))
            elif key == "ai_session":
                out.append(("ai_session", str(it), {}))
            elif key == "cloud" and isinstance(it, dict):
                for k, v in it.items():
                    if v:
                        out.append((_CLOUD_TYPES.get(k, f"cloud_{k}"), str(v), {}))
            else:
                val = json.dumps(it, ensure_ascii=False) if isinstance(it, (dict, list)) else str(it)
                out.append((key, val, {}))
    return out


def _lookup_entities(alert):
    entities, users, assets, intel, sandbox = [], {}, {}, [], []
    searches = []  # (criterion, value) pairs for log search

    def add_asset(a):
        if a:
            assets[a["hostname"]] = a

    seen = set()
    for etype, value, extra in _parse_entities(alert):
        if (etype, value) in seen:
            continue
        seen.add((etype, value))
        known = False
        if etype == "user":
            if not _is_placeholder_user(value):
                u = api_client.get_user(value)
                if u:
                    known = True
                    users[u["upn"]] = u
                searches.append(("user", u["upn"] if u else value))
        elif etype == "host":
            a = api_client.get_asset(value)
            add_asset(a)
            known = a is not None
            searches.append(("host", value))
            ip = extra.get("ip") or (a or {}).get("ip")
            if ip:
                searches.append(("ip", ip))
        elif etype == "ip":
            a = api_client.get_asset(value)
            add_asset(a)
            i = api_client.get_intel(value)
            if i:
                intel.append(i)
            known = a is not None or bool(i and (i.get("tip") or i.get("geo")))
            searches.append(("ip", value))
        elif etype in ("domain", "url"):
            i = api_client.get_intel(value)  # URLs always 404 on the mock API
            if i:
                intel.append(i)
            known = bool(i and i.get("tip"))
            searches.append(("value", value))
        elif etype == "file":
            if extra.get("has_sha"):
                s = api_client.get_sandbox(value)
                if s:
                    sandbox.append(s)
                i = api_client.get_intel(value)
                if i:
                    intel.append(i)
                known = bool(s) or bool(i and i.get("tip"))
            searches.append(("value", value))
        elif etype == "cloud_identity":
            u = api_client.get_user(value)
            if u:
                known = True
                users[u["upn"]] = u
            searches.append(("value", value))
        elif etype in VALUE_TYPES:
            searches.append(("value", value))
        entities.append(Entity(type=etype, value=value, known=known))

    # Users' workstations, for criticality and context.
    for u in list(users.values()):
        ws = u.get("workstation")
        if ws and ws not in assets:
            add_asset(api_client.get_asset(ws))
    return entities, list(users.values()), list(assets.values()), intel, sandbox, searches


def madrid_wall_to_utc(text):
    """Calendar wall time ("2026-10-08 08:00", Madrid) -> aware UTC datetime.
    Raises ValueError on ambiguous (clock goes back) or nonexistent (clock goes forward) times."""
    naive = datetime.fromisoformat(text)
    a, b = naive.replace(tzinfo=CHANGES_TZ, fold=0), naive.replace(tzinfo=CHANGES_TZ, fold=1)
    if a.utcoffset() != b.utcoffset():
        raise ValueError(f"ambiguous or nonexistent Madrid time: {text}")
    return a.astimezone(timezone.utc)


def _active_changes(lo, hi):
    """Changes whose window overlaps [lo, hi], each with inicio_utc/fin_utc added
    (None when the calendar value can't be converted; such changes are kept, not hidden)."""
    out = []
    for c in api_client.get_changes():
        c = dict(c)
        try:
            start, end = madrid_wall_to_utc(c["inicio"]), madrid_wall_to_utc(c["fin"])
        except (KeyError, TypeError, ValueError):
            c["inicio_utc"] = c["fin_utc"] = None
            out.append(c)
            continue
        c["inicio_utc"] = start.isoformat().replace("+00:00", "Z")
        c["fin_utc"] = end.isoformat().replace("+00:00", "Z")
        if start <= hi and end >= lo:
            out.append(c)
    return out


def _source_of(event_id):
    return EVENT_PREFIX_SOURCE.get(str(event_id).rsplit("-", 1)[0])


def _fetch_related(alert):
    """The alert's own linked events, wherever they are in time. Returns {(source, id): row}."""
    rows = {}
    for eid in alert.get("related_events") or []:
        s = _source_of(eid)
        if not s:
            continue
        for r in search_logs(s, value=eid)["items"]:
            if r.get("event_id") == eid:
                rows[(s, eid)] = {**r, "log_source": s}
    return rows


def _gather_logs(alert, rows, searches, lo, hi):
    """Adds entity searches in [lo, hi] to rows. Returns (api-truncated sources,
    {source: rows not sent because the search was on a shared IP})."""
    sources = list(RULE_LOG_SOURCES.get(alert.get("rule_id"), []))
    for eid in alert.get("related_events") or []:
        s = _source_of(eid)
        if s and s not in sources:
            sources.append(s)
    truncated, shared = set(), {}
    for source in sources:
        spec = LOG_FIELDS.get(source)
        if not spec:
            continue
        for crit, value in searches:
            if crit in ("user", "ip", "host") and not spec[crit]:
                continue
            res = search_logs(source, **{crit: value}, desde=lo, hasta=hi)
            if res["truncated"]:
                truncated.add(source)
            if crit == "ip" and value in SHARED_IPS:
                new = [r for r in res["items"] if (source, r.get("event_id")) not in rows]
                shared[source] = shared.get(source, 0) + len(new)
                continue
            for r in res["items"]:
                rows.setdefault((source, r.get("event_id")), {**r, "log_source": source})
    return truncated, shared


def _size(obj):
    return len(json.dumps(obj, ensure_ascii=False, default=str))


def _trim(rows, related_ids, anchors, budget):
    """Order rows most important first: the alert's linked events (in the alert's order),
    then the rest by distance to the nearest anchor time (alert creation or a linked
    event). Linked events are always kept; the rest fill `budget` characters.
    Returns (kept rows in that order, {source: [dropped event_ids]})."""
    def distance(r):
        try:
            t = _parse_utc(r.get("timestamp"))
        except (TypeError, ValueError):
            return float("inf")
        return min(abs((t - a).total_seconds()) for a in anchors) if anchors else 0

    order = {eid: i for i, eid in enumerate(related_ids)}
    related = sorted((r for r in rows if r.get("event_id") in order), key=lambda r: order[r["event_id"]])
    others = sorted((r for r in rows if r.get("event_id") not in order), key=distance)
    kept, dropped, used = [], {}, 0
    for r in related:
        kept.append(r)
        used += _size(r) + 2
    for r in others:
        s = _size(r) + 2
        if used + s <= budget:
            kept.append(r)
            used += s
        else:
            dropped.setdefault(r["log_source"], []).append(r.get("event_id"))
    return kept, dropped


def build_context(alert: dict) -> Context:
    """Everything known about one alert, from the mock API. Takes the full alert dict
    (live alerts may not exist in the API). Never fails on an entity it can't look up.

    Time windows use event times: ±CONTEXT_WINDOW around the alert's creation and around
    every linked event (some rules link events after the alert was created)."""
    alert = dict(alert)
    alert["created_at_madrid"] = to_madrid(alert.get("created_at"))

    entities, users, assets, intel, sandbox, searches = _lookup_entities(alert)
    ctx = Context(alert=alert, entities=entities, users=users, assets=assets,
                  intel=intel, sandbox=sandbox)
    ctx.criticality, ctx.criticality_source = resolve_criticality(alert, ctx)

    rows = _fetch_related(alert)
    anchors = []
    for t in [alert.get("created_at")] + [r.get("timestamp") for r in rows.values()]:
        try:
            anchors.append(_parse_utc(t))
        except (TypeError, ValueError):
            pass
    if not anchors:
        return ctx  # no time at all: no window for changes or logs
    lo, hi = min(anchors) - CONTEXT_WINDOW, max(anchors) + CONTEXT_WINDOW
    ctx.changes = _active_changes(lo, hi)

    api_truncated, shared = _gather_logs(alert, rows, searches, lo, hi)
    related_ids = [e for e in alert.get("related_events") or [] if e]
    rows = list(rows.values())
    for r in rows:
        r["timestamp_madrid"] = to_madrid(r.get("timestamp"))
        r["related"] = r.get("event_id") in related_ids

    ctx.truncated_sources = [TruncatedSource(source=s, reason="api_limit") for s in sorted(api_truncated)]
    ctx.truncated_sources += [TruncatedSource(source=s, reason="shared_ip", rows_dropped=n)
                              for s, n in sorted(shared.items()) if n]
    # Leave room for one size_limit record per source that returned rows.
    reserve = _size(TruncatedSource(source="x" * 12, reason="size_limit", rows_dropped=99999).model_dump()) + 2
    reserve *= len({r["log_source"] for r in rows})
    budget = MAX_CONTEXT_CHARS - _size(ctx.model_dump()) - reserve
    ctx.logs, dropped = _trim(rows, related_ids, anchors, budget)
    ctx.truncated_sources += [
        TruncatedSource(source=s, reason="size_limit", rows_dropped=len(ids))
        for s, ids in sorted(dropped.items())
    ]
    return ctx
