"""Which approved changes, flows and trips fit an alert.

The agent may only call an alert authorised by citing an ID that this code returned
(docs/decisions.md, "What counts as authorised"). So matching is deliberately strict:
anything this code can't confirm does not match, and the alert goes to a person instead.
A change fits only if, all at once:
  - time: every event time (linked events, or the alert time if none) is inside its window,
    and inside its daily window if it states one ("diariamente 08:00-10:00");
  - scope: the machines the alert names are in its scope (alcance);
  - identity: the origin it names (host, IP, email; else account) appears in the alert.
Text in the calendar is data written by people; it is parsed, never obeyed.
"""
import re
import unicodedata
from datetime import date, datetime, timezone
from zoneinfo import ZoneInfo

# Analysis section 7: the calendar has no offset and is Madrid wall time (inferred, not declared).
MADRID = ZoneInfo("Europe/Madrid")

# docs/decisions.md, SCCM account: the calendar names svc_sccm, but EDR logs these runs as
# NT AUTHORITY\SYSTEM. Accept that only with this parent, this exact command and the daily window.
SCCM_ACCOUNT = "svc_sccm"
SCCM_LOGGED_AS = "nt authority\\system"
SCCM_PARENT = "ccmexec.exe"
SCCM_KNOWN_COMMAND = ("$inv = Get-CimInstance Win32_Product | Select Name,Version | ConvertTo-Json"
                      " | Out-File C:\\Windows\\CCM\\Inventory\\sw.json")

_HOSTS = re.compile(r"\b([A-Z]+(?:-[A-Z]+)*)(\d+)(?:\.\.(\d+))?\b")
_IPS = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})(?:-(\d{1,3}))?\b")
_EMAILS = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_DOMAINS = re.compile(r"\b(?:[a-z0-9-]+\.)+example\b")
_ACCOUNTS = re.compile(r"\b(svc_\w+|ext\.\w+|adm\.\w+)\b")
_DAILY = re.compile(r"diariamente\s+(\d{1,2}):(\d{2})\s*-\s*(\d{1,2}):(\d{2})")
_TRIP_DATES = re.compile(r"del\s+(\d{1,2})/(\d{1,2})\s+al\s+(\d{1,2})/(\d{1,2})")


def madrid_wall_to_utc(text):
    """Calendar wall time ("2026-10-08 08:00", Madrid) -> aware UTC datetime.
    Raises ValueError on ambiguous (clock goes back) or nonexistent (clock goes forward) times."""
    naive = datetime.fromisoformat(text)
    a, b = naive.replace(tzinfo=MADRID, fold=0), naive.replace(tzinfo=MADRID, fold=1)
    if a.utcoffset() != b.utcoffset():
        raise ValueError(f"ambiguous or nonexistent Madrid time: {text}")
    return a.astimezone(timezone.utc)


def _utc_text(dt):
    return dt.isoformat().replace("+00:00", "Z")


def _plain(text):
    return unicodedata.normalize("NFKD", str(text)).encode("ascii", "ignore").decode().lower()


def _expand_hosts(text):
    out = set()
    for prefix, start, end in _HOSTS.findall(text or ""):
        last = int(end) if end else int(start)
        for n in range(int(start), last + 1):
            out.add(f"{prefix}{str(n).zfill(len(start))}".lower())
    return out


def _expand_ips(text):
    out = set()
    for base, start, end in _IPS.findall(text or ""):
        for n in range(int(start), (int(end) if end else int(start)) + 1):
            out.add(f"{base}{n}")
    return out


def parse_change(change):
    """What a calendar row names, as sets of lower-case tokens."""
    detail, scope = change.get("detalle", ""), change.get("alcance", "")
    emails = {e.lower() for e in _EMAILS.findall(detail)}
    detail_no_email = _EMAILS.sub(" ", detail)
    daily = _DAILY.search(_plain(detail))
    return {
        "origin_hosts": _expand_hosts(detail_no_email),
        "ips": _expand_ips(detail_no_email),
        "emails": emails,
        "accounts": {a.lower() for a in _ACCOUNTS.findall(detail_no_email)},
        "scope_hosts": _expand_hosts(scope),
        "scope_domains": set(_DOMAINS.findall(detail_no_email.lower())),
        "scope_text": _plain(scope),
        "daily": tuple(int(x) for x in daily.groups()) if daily else None,
    }


def _leaves(obj):
    if isinstance(obj, dict):
        for v in obj.values():
            yield from _leaves(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _leaves(v)
    elif obj is not None:
        yield str(obj)


def _account(value):
    v = value.lower().rsplit("\\", 1)[-1]
    return v.split("@", 1)[0]


def _url_host(value):
    m = re.match(r"[a-z]+://([^/:?#]+)", value.lower())
    return m.group(1) if m else value.lower()


def _in_scope(p, alert, named_assets, linked_assets=()):
    """Explicit host lists also accept machines touched by the alert's linked events
    (e.g. firewall rows to the PLCs). Broad scopes only look at the machines the alert names."""
    names = {a["hostname"].lower() for a in [*named_assets, *linked_assets]}
    if p["scope_hosts"] & names:
        return True
    if p["scope_domains"]:
        hosts = {_url_host(v) for v in _leaves(alert.get("entities"))}
        if p["scope_domains"] & hosts:
            return True
    s = p["scope_text"]
    if "todos los puestos" in s:
        return bool(named_assets) and all(
            a.get("type") == "Portátil" or str(a.get("business_service", "")).startswith("Puesto de trabajo")
            for a in named_assets)
    if "todas las redes salvo ot" in s:
        return all(a.get("zone") != "LOGISTICS-OT" for a in named_assets)
    if "servidores windows" in s:
        return bool(named_assets) and all(str(a.get("os", "")).startswith("Windows Server") for a in named_assets)
    if "directorio activo" in s:
        return alert.get("source_product") == "AD" or any(a.get("type") == "Controlador de dominio" for a in named_assets)
    if s.strip() == "correo":
        return alert.get("source_product") in ("EMAIL_GW", "DLP")
    return False


def _sccm_exception(related_rows):
    edr = [r for r in related_rows if r.get("log_source") == "edr_events"]
    return bool(edr) and all(
        str(r.get("user", "")).lower() == SCCM_LOGGED_AS
        and str(r.get("parent_name", "")).lower() == SCCM_PARENT
        and (r.get("details") or {}).get("decoded") == SCCM_KNOWN_COMMAND
        for r in edr)


def _identity(p, alert, related_rows):
    """Returns (ok, what matched). Origin groups (hosts, IPs, emails) are all required when
    named; accounts are required only when no origin is named."""
    values = {v.lower() for v in _leaves([alert.get("entities"), alert.get("evidence"), related_rows])}
    accounts = {_account(v) for v in values}
    hits = []
    for group in ("origin_hosts", "ips", "emails"):
        if p[group]:
            found = p[group] & values
            if not found:
                return False, ""
            hits.append(sorted(found)[0])
    if hits:
        return True, ", ".join(hits)
    if p["accounts"]:
        found = p["accounts"] & accounts
        if found:
            return True, sorted(found)[0]
        if p["accounts"] == {SCCM_ACCOUNT} and _sccm_exception(related_rows):
            return True, f"{SCCM_ACCOUNT} (EDR: NT AUTHORITY\\SYSTEM, CcmExec.exe, comando conocido)"
        return False, ""
    return True, "sin identidad en el calendario"


def _in_daily_window(daily, times):
    h1, m1, h2, m2 = daily
    for t in times:
        local = t.astimezone(MADRID)
        minutes = local.hour * 60 + local.minute
        if not (h1 * 60 + m1 <= minutes <= h2 * 60 + m2):
            return False
    return True


def match_changes(changes, alert, named_assets, related_rows, event_times, linked_assets=()):
    """Calendar rows that fit the alert, each with inicio_utc, fin_utc and matched_on added."""
    out = []
    if not event_times:
        return out
    for c in changes:
        try:
            start, end = madrid_wall_to_utc(c["inicio"]), madrid_wall_to_utc(c["fin"])
        except (KeyError, TypeError, ValueError):
            continue  # can't place it in time: can't authorise anything
        if not all(start <= t <= end for t in event_times):
            continue
        p = parse_change(c)
        if p["daily"] and not _in_daily_window(p["daily"], event_times):
            continue
        if not _in_scope(p, alert, named_assets, linked_assets):
            continue
        ok, who = _identity(p, alert, related_rows)
        if not ok:
            continue
        out.append({**c, "inicio_utc": _utc_text(start), "fin_utc": _utc_text(end),
                    "matched_on": f"hora del evento, alcance, identidad: {who}"})
    return out


def _trip_range(hr):
    m = _TRIP_DATES.search(hr.get("detalle", ""))
    if not m or hr.get("tipo") != "viaje":
        return None
    year = int(str(hr.get("fecha_efectiva") or hr.get("fecha"))[:4])
    d1, m1, d2, m2 = (int(x) for x in m.groups())
    return date(year, m1, d1), date(year, m2, d2)


def split_hr_events(users, event_times):
    """(trips, other HR events) for the affected users. A trip counts only with explicit dates
    ("del 11/10 al 14/10") covering every event time in Madrid. Everything else is context only."""
    trips, others = [], []
    for u in users:
        for hr in u.get("hr_events") or []:
            rng = _trip_range(hr)
            if rng and event_times and all(rng[0] <= t.astimezone(MADRID).date() <= rng[1] for t in event_times):
                username = str(hr.get("usuario", "")).split("@", 1)[0]
                trips.append({"id": f"TRIP-{username}-{rng[0].isoformat()}", **hr,
                              "desde": rng[0].isoformat(), "hasta": rng[1].isoformat()})
            else:
                others.append(dict(hr))
    return trips, others
