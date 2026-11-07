"""Log search with exact-field matching. Branch: data/search-logs

The mock API's `q` is a case-insensitive substring match on the whole JSON row, so
q="laura.ferrer" also returns laura.ferrer2 and q="10.10.1.1" also returns 10.10.1.12.
We use `q` only to narrow the scan (with the JSON quotes around the value, which cuts
most false hits), then keep rows whose named field is exactly equal.
"""
import json
from datetime import datetime, timezone

from src.tools import api_client

# Which fields name people, machines and IPs in each log, and how a person is written.
# User formats: "upn" (laura.ferrer2@tarvia.example), "username" (laura.ferrer2),
# "domain\\username" (TARVIA\\laura.ferrer2). Nested fields use dots; lists match any item.
# Analysis section 3 finds the same formats. Cloud identities have no UPN: search them with value=.
LOG_FIELDS = {
    "ad_events":    {"user": {"subject": "username", "target": "username"}, "ip": [], "host": ["src_host", "dc"]},
    "ai_gateway":   {"user": {}, "ip": ["src_ip"], "host": []},
    "cicd_builds":  {"user": {}, "ip": [], "host": ["runner"]},
    "cloudtrail":   {"user": {"userIdentity.userName": "username"}, "ip": ["sourceIPAddress"], "host": []},
    "dlp":          {"user": {"user": "username"}, "ip": [], "host": ["hostname"]},
    "dns":          {"user": {}, "ip": ["src_ip", "response"], "host": ["hostname"]},
    "ecom_account": {"user": {}, "ip": ["src_ip"], "host": []},
    "ecom_auth":    {"user": {}, "ip": ["src_ip"], "host": []},
    "edr_events":   {"user": {"user": "domain\\username"}, "ip": [], "host": ["hostname"]},
    "email":        {"user": {"sender": "upn", "recipients": "upn"}, "ip": ["sender_ip"], "host": []},
    "email_clicks": {"user": {"user": "upn"}, "ip": ["src_ip"], "host": []},
    "firewall":     {"user": {}, "ip": ["src_ip", "dst_ip"], "host": []},
    "idp_audit":    {"user": {"actor_upn": "upn", "target": "upn"}, "ip": ["src_ip"], "host": []},
    "idp_signins":  {"user": {"user_upn": "upn"}, "ip": ["src_ip"], "host": []},
    "proxy":        {"user": {"user": "username"}, "ip": ["src_ip", "dst_ip"], "host": ["hostname"]},
    "sql_audit":    {"user": {"user": "username"}, "ip": [], "host": ["client_host"]},
    "vpn":          {"user": {"user": "username"}, "ip": ["src_ip", "assigned_ip"], "host": []},
    "waf":          {"user": {}, "ip": ["src_ip"], "host": []},
}

API_LIMIT = 2000  # the mock API's maximum page size
# How many times a cut-off window is halved before we give up and report it truncated.
# Analysis section 4: the largest unfiltered ±24 h window is 18,721 proxy rows; 4 halvings
# allow up to 16 windows x 2,000 rows. Anything still cut off is reported as truncated.
MAX_SPLIT_DEPTH = 4


def _username(upn):
    return upn.split("@", 1)[0].lower()


def _field(row, path):
    """Values at a dotted path; lists are flattened."""
    vals = [row]
    for part in path.split("."):
        nxt = []
        for v in vals:
            if isinstance(v, list):
                v = [x.get(part) for x in v if isinstance(x, dict)]
                nxt.extend(v)
            elif isinstance(v, dict) and part in v:
                nxt.append(v[part])
        vals = nxt
    out = []
    for v in vals:
        out.extend(v if isinstance(v, list) else [v])
    return [v for v in out if v is not None and not isinstance(v, (dict, list))]


def _leaves(obj):
    if isinstance(obj, dict):
        for v in obj.values():
            yield from _leaves(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _leaves(v)
    elif obj is not None:
        yield obj


def _user_matches(value, fmt, upn):
    v = str(value).lower()
    if fmt == "upn":
        return v == upn.lower()
    if fmt == "username":
        return v == _username(upn)
    if fmt == "domain\\username":
        return v.rsplit("\\", 1)[-1] == _username(upn)
    raise ValueError(f"unknown user format: {fmt}")


def _quoted(value):
    """How a string value appears inside the JSON row the API searches."""
    return json.dumps(str(value), ensure_ascii=False)


def _user_q(fmt, upn):
    if fmt == "upn":
        return _quoted(upn)
    if fmt == "username":
        return _quoted(_username(upn))
    # "TARVIA\\laura" is dumped as "TARVIA\\\\laura": match its escaped tail and closing quote.
    return _quoted("\\" + _username(upn))[1:]


def _matcher(spec, user, ip, host, value):
    """Returns (list of q strings to send, predicate on a row, unsupported criteria)."""
    checks, qs, unsupported = [], [], []
    if user:
        fields = spec["user"]
        if not fields:
            unsupported.append("user")
        checks.append(lambda r: any(_user_matches(v, fmt, user)
                                    for path, fmt in fields.items() for v in _field(r, path)))
        qs.append(sorted({_user_q(fmt, user) for fmt in fields.values()}))
    if ip:
        if not spec["ip"]:
            unsupported.append("ip")
        checks.append(lambda r: any(str(v) == ip for p in spec["ip"] for v in _field(r, p)))
        qs.append([_quoted(ip)])
    if host:
        if not spec["host"]:
            unsupported.append("host")
        checks.append(lambda r: any(str(v).lower() == host.lower() for p in spec["host"] for v in _field(r, p)))
        qs.append([_quoted(host)])
    if value:
        checks.append(lambda r: any(str(v).lower() == str(value).lower() for v in _leaves(r)))
        qs.append([_quoted(value)])
    # The API takes one q; use the first criterion to narrow, filter the rest client-side.
    return (qs[0] if qs else [""]), (lambda r: all(c(r) for c in checks)), unsupported


def _fmt_ts(t):
    if isinstance(t, str):
        return t
    return t.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _parse_ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def _fetch(source, q, desde, hasta, depth=0):
    """Fetch every row for q in [desde, hasta], halving the window when the API cuts off.
    Returns (items, truncated)."""
    r = api_client.get_logs(source, q=q, desde=desde, hasta=hasta, limit=API_LIMIT)
    if not r["truncated"]:
        return r["items"], False
    if depth >= MAX_SPLIT_DEPTH or not (desde and hasta):
        return r["items"], True
    a, b = _parse_ts(desde), _parse_ts(hasta)
    if (b - a).total_seconds() < 2:
        return r["items"], True
    mid = _fmt_ts(a + (b - a) / 2)
    left, tl = _fetch(source, q, desde, mid, depth + 1)
    right, tr = _fetch(source, q, mid, hasta, depth + 1)
    return left + right, tl or tr


def search_logs(source, user=None, ip=None, host=None, value=None, desde=None, hasta=None):
    """Rows of `source` where every given criterion matches exactly.

    user: full UPN; matched in the source's user fields in that log's own format.
    ip / host: exact match in the source's IP / hostname fields (host is case-insensitive).
    value: exact, case-insensitive match against any field (message_id, sha256, session...).
    desde / hasta: ISO strings or datetimes (UTC); both ends inclusive.

    Returns {"source", "items", "truncated", "unsupported"}. `truncated` is True if any
    window was still cut off by the API limit after splitting, so results may be missing.
    `unsupported` lists criteria this source has no field for (then items is empty).
    """
    if source not in LOG_FIELDS:
        raise ValueError(f"unknown log source: {source}")
    desde = _fmt_ts(desde) if desde else ""
    hasta = _fmt_ts(hasta) if hasta else ""
    qs, keep, unsupported = _matcher(LOG_FIELDS[source], user, ip, host, value)
    if unsupported:
        return {"source": source, "items": [], "truncated": False, "unsupported": unsupported}
    seen, items, truncated = set(), [], False
    for q in qs:
        rows, t = _fetch(source, q, desde, hasta)
        truncated = truncated or t
        for row in rows:
            key = row.get("event_id") or json.dumps(row, sort_keys=True)
            if key in seen or not keep(row):
                continue
            seen.add(key)
            items.append(row)
    items.sort(key=lambda r: r.get("timestamp", ""))
    return {"source": source, "items": items, "truncated": truncated, "unsupported": []}
