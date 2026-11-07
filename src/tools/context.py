"""Gathers everything known about an alert. Branch: data/context

Plain code, no LLM. Text from the data (subjects, prompts, descriptions) is copied as is:
it is evidence, never instructions, and it is never removed or cleaned for what it says.
"""
import json
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from contracts.models import Context
from src.policy.severity import resolve_criticality
from src.tools import api_client
from src.tools.authorisation import match_changes, split_hr_events
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

# Event timestamps are UTC; we add Madrid time next to them. The change calendar is converted
# in src/tools/authorisation.py (analysis section 7).
MADRID = ZoneInfo("Europe/Madrid")

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
    moment = datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    return moment.replace(tzinfo=timezone.utc) if moment.tzinfo is None else moment  # the dataset's times are UTC


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
    named = {}     # assets the alert itself names (host entities, IPs the CMDB knows)
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
            if a:
                named[a["hostname"]] = a
            known = a is not None
            searches.append(("host", value))
            ip = extra.get("ip") or (a or {}).get("ip")
            if ip:
                searches.append(("ip", ip))
        elif etype == "ip":
            a = api_client.get_asset(value)
            add_asset(a)
            if a:
                named[a["hostname"]] = a
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
        entities.append({"type": etype, "value": value, "known": known})

    # Users' workstations, for criticality and context.
    for u in list(users.values()):
        ws = u.get("workstation")
        if ws and ws not in assets:
            add_asset(api_client.get_asset(ws))
    return entities, list(users.values()), list(assets.values()), list(named.values()), intel, sandbox, searches


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
    # A rule we don't know has no list of logs to check, so it gets all of them.
    sources = list(RULE_LOG_SOURCES.get(alert.get("rule_id")) or LOG_FIELDS)
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


def _linked_assets(rows):
    """CMDB machines whose hostname or IP appears in the alert's linked events."""
    keys = set()
    for r in rows:
        spec = LOG_FIELDS.get(r.get("log_source"), {})
        for field in [*spec.get("ip", []), *spec.get("host", [])]:
            v = r.get(field)
            if v:
                keys.add(str(v))
    found = {}
    for k in sorted(keys):
        a = api_client.get_asset(k)
        if a:
            found[a["hostname"]] = a
    return list(found.values())


def _entities_by_type(entities):
    """{type: [{"value", "known", ...}]}, the shape of Context.entities."""
    out = {}
    for e in entities:
        item = {k: v for k, v in e.items() if k != "type"}
        out.setdefault(e["type"], []).append(item)
    return out


def build_context(alert: dict) -> Context:
    """Everything known about one alert, from the mock API, in the shape of contracts.Context.
    Takes the full alert dict (live alerts may not exist in the API). Never fails on an entity
    it can't look up.

    Time windows use event times: ±CONTEXT_WINDOW around every linked event, or the alert's
    creation time if it links none (some rules link events after the alert was created).
    With no usable time at all, the whole period is searched."""
    alert = dict(alert)
    alert["created_at_madrid"] = to_madrid(alert.get("created_at"))

    entities, users, assets, named, intel, sandbox, searches = _lookup_entities(alert)
    ctx = Context(alert=alert, users=users, assets=assets, intel=intel, sandbox=sandbox)
    ctx.criticality, ctx.criticality_source = resolve_criticality(
        alert, {"entities": entities, "assets": assets, "users": users})

    rows = _fetch_related(alert)
    event_times = []
    for r in rows.values():
        try:
            event_times.append(_parse_utc(r.get("timestamp")))
        except (TypeError, ValueError):
            pass
    if not event_times:
        try:
            event_times = [_parse_utc(alert.get("created_at"))]
        except (TypeError, ValueError):
            event_times = []

    ctx.changes = match_changes(api_client.get_changes(), alert, named, list(rows.values()), event_times,
                                _linked_assets(rows.values()))
    ctx.trips, ctx.hr_events = split_hr_events(users, event_times)
    lo, hi = (min(event_times) - CONTEXT_WINDOW, max(event_times) + CONTEXT_WINDOW) if event_times else (None, None)
    api_truncated, shared = _gather_logs(alert, rows, searches, lo, hi)
    for e in entities:  # shared IPs: their rows are counted on the entity, not sent
        if e["type"] == "ip" and e["value"] in SHARED_IPS:
            e["shared_by_many_identities"] = True
            e["rows_not_sent"] = dict(sorted(shared.items()))
    ctx.entities = _entities_by_type(entities)

    related_ids = [e for e in alert.get("related_events") or [] if e]
    rows = list(rows.values())
    for r in rows:
        r["timestamp_madrid"] = to_madrid(r.get("timestamp"))
        r["related"] = r.get("event_id") in related_ids

    budget = MAX_CONTEXT_CHARS - _size(ctx.model_dump())
    kept, dropped = _trim(rows, related_ids, event_times, budget)
    logs = {}
    for r in kept:  # keeps the most-important-first order inside each source
        logs.setdefault(r.pop("log_source"), []).append(r)
    ctx.logs = logs
    # Rows the API cut off and rows cut for size are both missing evidence: the agent then
    # can't use the -1 (analysis section 4).
    ctx.truncated_sources = sorted(set(api_truncated) | set(dropped))
    return ctx
