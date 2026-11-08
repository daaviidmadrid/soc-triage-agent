"""Fixed rules that close well-known noise without calling the LLM.

A rule may only close. It never escalates, never decides that something is an attack beyond
what the logs show, and never overrides a mandatory escalation (src/agent/triage.py checks the
severity and the policy's escalation rules before a rule's ticket is used).

Every condition must hold exactly. If anything is missing, different or truncated, the rule
doesn't apply and the alert goes to the LLM as before. Conditions use parsed log fields, the CMDB
and the change calendar. Text in the alert (description, evidence, rule name) is never read: an
attacker can write it. The alert's own fields are only compared with the logs, so they can make a
rule refuse but never make it apply. No condition uses an alert or event ID number: IDs are only cited.

Texts for a refusal are fixed, with no values from the data, because they go into the trace.
"""

from dataclasses import dataclass, field

from src.agent.correlate import _external_ip
from src.policy.severity import RULE_SERVICE
from src.tools.authorisation import (
    MADRID,
    SCCM_ACCOUNT,
    _sccm_exception,
    match_changes,
    parse_change,
)
from src.tools.context import CONTEXT_WINDOW, _parse_utc
from src.tools.logs import search_logs

# Checked on the WAF log (7 Nov 2026): every row is either action "blocked" with status 403
# (4,220 rows) or action "allowed" with status 200 or 401. A block needs both fields.
WAF_BLOCKED_ACTION = "blocked"
WAF_BLOCKED_STATUS = 403
# The WAF sits in front of the online shop (data/01_contexto/empresa_tarvia.md), and this is the
# shop's host in the WAF log and in the pentest change's scope (calendario_cambios.csv).
SHOP_HOSTS = {"www.tarvia.example"}
# The shop's application logs. Any row from the source there means a request got through.
SHOP_APP_SOURCES = ("ecom_auth", "ecom_account")

DATA_GAPS_FAILED = "La alerta llegó en otro formato y hubo que suponer datos."
RULE_NOTE = "Solo se ha cerrado por regla porque cada condición se cumple con campos de los logs, la CMDB y el calendario de cambios."


@dataclass
class RuleCheck:
    """One rule's verdict on one alert. `failed` is None when every condition held."""

    rule_id: str
    name: str
    detection_rule: str
    conditions: list[str] = field(default_factory=list)
    failed: str | None = None
    event_ids: list[str] = field(default_factory=list)
    # Extra log searches the rule made: {"source", "args", "event_ids", "truncated", "count"}.
    lookups: list[dict] = field(default_factory=list)
    # What the ticket says when the rule applies.
    verdict: str = ""
    adjustments: list[dict] = field(default_factory=list)
    authorised_by: dict | None = None
    title: str = ""
    summary: str = ""
    evidence: list[dict] = field(default_factory=list)
    enrichment: list[dict] = field(default_factory=list)
    affected: dict = field(default_factory=dict)
    mitre: list[str] = field(default_factory=list)
    # Sources the rule doesn't rely on that were truncated; the ticket lists them, as v5 does.
    other_truncated: list[str] = field(default_factory=list)

    @property
    def applies(self):
        return self.failed is None

    def need(self, ok, passed, failed):
        """Records a condition. Returns False, and remembers why, the first time one doesn't hold.
        passed can be None when the text is written later, once it can name what matched."""
        if self.failed is not None:
            return False
        if ok:
            if passed:
                self.conditions.append(passed)
            return True
        self.failed = failed
        return False

    def refuse(self, reason):
        if self.failed is None:
            self.failed = reason


def default_find(source, **criteria):
    """search_logs as (rows, truncated)."""
    result = search_logs(source, **criteria)
    return list(result["items"]), bool(result["truncated"])


def check_rules(alert, context, find=None):
    """Returns the RuleCheck of the rule for this alert's detection rule, or None if no rule covers it.
    Never changes the context, so an alert a rule refuses reaches the LLM exactly as before."""
    rule = RULES.get(alert.get("rule_id"))
    if rule is None:
        return None
    return rule(alert, context, find or default_find)


# --- helpers ---------------------------------------------------------------------------------


def _log_groups(logs):
    """{source: rows}, from the context's dict of sources or a list of rows that carry "source"."""
    if isinstance(logs, dict):
        return {str(key): value for key, value in logs.items() if isinstance(value, list)}
    groups = {}
    for row in logs or []:
        if isinstance(row, dict):
            groups.setdefault(row.get("source", "logs"), []).append(row)
    return groups


def _related_rows(alert, context, source):
    """The alert's linked events, as rows of `source` from the context, in the alert's order.
    None if the alert links none, or if any of them isn't a row of that source."""
    ids = alert.get("related_events")
    if not isinstance(ids, list) or not ids or not all(isinstance(item, str) and item for item in ids):
        return None
    rows = {
        row.get("event_id"): row for row in _log_groups(context.get("logs")).get(source, []) if isinstance(row, dict)
    }
    if any(item not in rows for item in ids):
        return None
    return [{**rows[item], "log_source": source} for item in dict.fromkeys(ids)]


def _times(rows):
    try:
        return [_parse_utc(row["timestamp"]) for row in rows]
    except (KeyError, TypeError, ValueError):
        return None


def _utc(moment):
    return moment.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _madrid_clock(moment):
    return moment.astimezone(MADRID).strftime("%H:%M")


def _named(alert, key, field_name=None):
    """Values the alert names under entities[key], lower-cased."""
    entities = alert.get("entities")
    items = entities.get(key) if isinstance(entities, dict) else None
    if not isinstance(items, list):
        return set()
    values = set()
    for item in items:
        value = item.get(field_name) if field_name and isinstance(item, dict) else item
        if isinstance(value, str) and value:
            values.add(value.lower())
    return values


def _assets_by(context, key):
    return {
        str(asset.get(key)).lower(): asset
        for asset in context.get("assets") or []
        if isinstance(asset, dict) and asset.get(key)
    }


# --- rule 1: approved software inventory -------------------------------------------------------


def sccm_inventory(alert, context, find):
    """UC-EDR-002, encoded PowerShell. Closes only SCCM's approved inventory script: the EDR event's
    account, parent process and decoded command must pass the SCCM exception of src/tools/authorisation.py,
    and the approved change must fit the event time, its daily window, scope and identity using log fields only."""
    check = RuleCheck("R1", "Inventario de software aprobado por SCCM", "UC-EDR-002", mitre=["T1059.001"])
    if not check.need(
        not context.get("data_gaps"),
        "La alerta llegó con todos sus campos: no hubo que suponer nada.",
        DATA_GAPS_FAILED,
    ):
        return check
    rows = _related_rows(alert, context, "edr_events")
    if not check.need(
        rows is not None,
        f"Los {len(rows or [])} evento(s) enlazados están en los logs del EDR.",
        "Algún evento enlazado falta o no es del EDR.",
    ):
        return check
    # The rule reads only the linked events, fetched by their IDs and never cut to fit. Other searches that were
    # truncated don't change what it checks, and the ticket lists them, as v5 does. Rule 2 is stricter because
    # its "no later activity" needs every row (docs/decisions.md, Incomplete evidence).
    check.other_truncated = [str(item) for item in context.get("truncated_sources") or []]
    if check.other_truncated:
        check.conditions.append(
            f"Los eventos enlazados se leyeron completos. Las búsquedas truncadas ({', '.join(check.other_truncated)}) "
            "no intervienen en esta regla y el ticket lo indica."
        )

    hosts = {str(row.get("hostname") or "").lower() for row in rows}
    assets = _assets_by(context, "hostname")
    if not check.need(
        all(hosts) and hosts == _named(alert, "hosts", "hostname"),
        "El equipo de los eventos es el que nombra la alerta.",
        "El equipo de los eventos no es el que nombra la alerta.",
    ):
        return check
    in_cmdb = all(host in assets for host in hosts)
    if not check.need(
        in_cmdb,
        "El equipo está en la CMDB: " + ", ".join(sorted(assets[host]["hostname"] for host in hosts)) + "."
        if in_cmdb
        else None,
        "El equipo de los eventos no está en la CMDB.",
    ):
        return check
    if not check.need(
        _sccm_exception(rows),
        "Excepción SCCM: en el EDR, usuario NT AUTHORITY\\SYSTEM, proceso padre CcmExec.exe y comando decodificado idéntico al inventario conocido.",
        "El usuario, el proceso padre o el comando decodificado del EDR no son los del inventario SCCM.",
    ):
        return check
    times = _times(rows)
    if not check.need(
        bool(times), "La hora de cada evento se puede leer.", "La hora de algún evento no se puede leer."
    ):
        return check

    # The calendar match again, with no alert fields at all: scope, time and identity can only come from the logs.
    named_assets = [assets[host] for host in sorted(hosts)]
    matches = [
        change
        for change in match_changes(context.get("changes") or [], {}, named_assets, rows, times, named_assets)
        if parse_change(change)["accounts"] == {SCCM_ACCOUNT} and parse_change(change)["daily"]
    ]
    if not check.need(
        len(matches) == 1,
        None,
        "Ningún cambio aprobado encaja, solo con campos del log, con la excepción SCCM y su ventana diaria.",
    ):
        return check
    change = matches[0]
    h1, m1, h2, m2 = parse_change(change)["daily"]
    window = f"{h1:02d}:{m1:02d}-{h2:02d}:{m2:02d}"
    clocks = ", ".join(_madrid_clock(moment) for moment in times)
    check.conditions.append(
        f"El cambio aprobado {change['id']} encaja por hora del evento, alcance e identidad, comprobado solo con campos del log "
        f"(vigente del {change.get('inicio')} al {change.get('fin')}, hora de Madrid)."
    )
    check.conditions.append(f"Hora del evento {clocks} (Madrid) dentro de la ventana diaria {window} del cambio.")

    host_names = sorted(assets[host]["hostname"] for host in hosts)
    services = sorted(
        {str(assets[host].get("business_service")) for host in hosts if assets[host].get("business_service")}
    )
    check.event_ids = [row["event_id"] for row in rows]
    check.verdict = "benign_true_positive"
    check.authorised_by = {"type": "change", "id": str(change["id"])}
    check.title = f"Inventario de software aprobado (SCCM) en {', '.join(host_names)}"
    check.summary = (
        f"Cerrada por la regla fija R1, sin consultar al modelo. El EDR registra en {', '.join(host_names)} PowerShell con "
        f"-EncodedCommand lanzado por CcmExec.exe (agente SCCM) como NT AUTHORITY\\SYSTEM, con el comando de inventario de software "
        f"conocido, a las {clocks} hora de Madrid. Encaja con el cambio aprobado {change['id']}, que autoriza ese script cada día "
        f"en la ventana {window}. Es actividad autorizada. {RULE_NOTE}"
    )
    check.evidence = [
        {
            "source": "edr_events",
            "event_id": row["event_id"],
            "finding": f"powershell.exe con -EncodedCommand, padre CcmExec.exe, usuario NT AUTHORITY\\SYSTEM, comando de inventario SCCM, {_madrid_clock(moment)} Madrid",
        }
        for row, moment in zip(rows, times)
    ] + [
        {
            "source": "changes",
            "event_id": "",
            "finding": f"Cambio aprobado {change['id']}: svc_sccm ejecuta el inventario diariamente {window}",
        }
    ]
    check.affected = {"hosts": host_names, "business_services": services}
    return check


# --- rule 2: blocked internet scans on the shop ------------------------------------------------


def _blocked(row):
    return row.get("action") == WAF_BLOCKED_ACTION and row.get("status") == WAF_BLOCKED_STATUS


def _intel_for(context, ip):
    enrichment = []
    for item in context.get("intel") or []:
        if not isinstance(item, dict) or item.get("indicator") != ip:
            continue
        enrichment.append(
            {
                "indicator": ip,
                "type": "ip",
                "source": "ti_feed",
                "result": "conocida en el TIP interno" if item.get("tip") else "sin coincidencias",
            }
        )
        geo = item.get("geo")
        if isinstance(geo, dict):
            flags = [
                label
                for key, label in (
                    ("is_hosting", "hosting"),
                    ("is_tor", "Tor"),
                    ("is_vpn_provider", "VPN"),
                    ("is_residential_proxy", "proxy residencial"),
                )
                if str(geo.get(key)).lower() == "true"
            ]
            parts = [str(geo[key]) for key in ("country", "asn") if geo.get(key)] + flags
            enrichment.append(
                {"indicator": ip, "type": "ip", "source": "geoip_asn", "result": ", ".join(parts) or "sin datos"}
            )
    return enrichment


def blocked_web_scan(alert, context, find):
    """UC-WEB-001, injection signature on the WAF. Closes only an internet source whose every request was
    blocked, with nothing from it getting through for 24 hours: a real attempt with no effect, so true_positive
    with the policy's -1, then closed, as in data/01_contexto/ticket_ejemplo.json."""
    check = RuleCheck("R2", "Escaneo de Internet bloqueado contra la tienda online", "UC-WEB-001", mitre=["T1190"])
    if not check.need(
        not context.get("data_gaps"),
        "La alerta llegó con todos sus campos: no hubo que suponer nada.",
        DATA_GAPS_FAILED,
    ):
        return check
    rows = _related_rows(alert, context, "waf")
    if not check.need(
        rows is not None,
        f"Los {len(rows or [])} evento(s) enlazados están en los logs del WAF.",
        "Algún evento enlazado falta o no es del WAF.",
    ):
        return check
    # Docs/decisions.md, Incomplete evidence: cut-off rows can't show that nothing happened afterwards.
    if not check.need(
        not context.get("truncated_sources"),
        "Ninguna búsqueda del contexto se truncó ni se recortó.",
        "Hay resultados truncados o recortados en el contexto: la evidencia está incompleta.",
    ):
        return check
    if not check.need(
        all(_blocked(row) for row in rows),
        f"Todas las peticiones enlazadas fueron bloqueadas por el WAF (action {WAF_BLOCKED_ACTION}, estado {WAF_BLOCKED_STATUS}).",
        "Alguna petición enlazada no fue bloqueada por el WAF.",
    ):
        return check
    if not check.need(
        all(row.get("host") in SHOP_HOSTS for row in rows),
        "Todas iban a la tienda online.",
        "Alguna petición no iba a la tienda online.",
    ):
        return check
    sources = {str(row.get("src_ip") or "") for row in rows}
    ip = next(iter(sources)) if len(sources) == 1 else ""
    if not check.need(
        bool(ip), f"Todas vienen de un mismo origen: {ip}.", "Las peticiones no vienen de un único origen."
    ):
        return check
    if not check.need(
        _named(alert, "ips") == {ip.lower()},
        "Es la IP que nombra la alerta.",
        "La alerta no nombra exactamente la IP de origen de los eventos.",
    ):
        return check
    known_hosts = _assets_by(context, "ip")
    # Outside Tarvia's networks and not one of the IPs shared by many identities, as for grouping (src/agent/correlate.py).
    if not check.need(
        _external_ip(ip) and ip.lower() not in known_hosts,
        "El origen no es interno: fuera de las redes de Tarvia, no está en la CMDB ni es una IP compartida por muchas identidades.",
        "El origen es interno, está en la CMDB o es una IP compartida por muchas identidades.",
    ):
        return check
    if not check.need(
        not context.get("changes") and not context.get("trips"),
        "Ningún cambio aprobado ni viaje encaja con la alerta.",
        "Hay un cambio aprobado o un viaje que encaja con la alerta: puede estar autorizada.",
    ):
        return check
    times = _times(rows)
    if not check.need(
        bool(times), "La hora de cada evento se puede leer.", "La hora de algún evento no se puede leer."
    ):
        return check

    # Afterwards: from the first blocked request to 24 h after the last (policy section 1.4, the context window).
    desde, hasta = _utc(min(times)), _utc(max(times) + CONTEXT_WINDOW)
    later = {}
    for source in ("waf", *SHOP_APP_SOURCES):
        found, truncated = find(source, ip=ip, desde=desde, hasta=hasta)
        found = [row for row in found if isinstance(row, dict)]
        check.lookups.append(
            {
                "source": source,
                "args": {"source": source, "ip": ip, "desde": desde, "hasta": hasta},
                "event_ids": [row["event_id"] for row in found if row.get("event_id")],
                "truncated": truncated,
                "count": len(found),
            }
        )
        if not check.need(not truncated, None, "Una búsqueda de actividad posterior del origen está truncada."):
            return check
        later[source] = found
    waf_later = later["waf"]
    if not check.need(
        all(_blocked(row) for row in waf_later),
        f"Desde el primer intento hasta 24 h después, las {len(waf_later)} petición(es) de esa IP en el WAF fueron todas bloqueadas: ninguna tuvo éxito.",
        "La IP tiene peticiones que el WAF dejó pasar después del primer intento.",
    ):
        return check
    if not check.need(
        not any(later[source] for source in SHOP_APP_SOURCES),
        "Esa IP no aparece en los logs de la tienda (ecom_auth, ecom_account) en ese periodo.",
        "La IP tiene actividad en los logs de la tienda después del primer intento.",
    ):
        return check

    signatures = sorted({f"{row.get('rule_id')} ({row.get('rule_msg')})" for row in rows if row.get("rule_id")})
    countries = sorted({str(row.get("country")) for row in rows if row.get("country")})
    check.event_ids = list(
        dict.fromkeys([row["event_id"] for row in rows] + [row["event_id"] for row in waf_later if row.get("event_id")])
    )
    check.verdict = "true_positive"
    check.adjustments = [
        {"delta": -1, "reason": "Bloqueado por el WAF antes de producir efecto, sin actividad posterior"}
    ]
    check.title = "Escaneo de Internet contra la tienda online, bloqueado por el WAF"
    check.summary = (
        f"Cerrada por la regla fija R2, sin consultar al modelo. {len(rows)} intento(s) desde {ip}"
        + (f" ({', '.join(countries)})" if countries else "")
        + " contra la tienda online, todos bloqueados por el WAF con 403"
        + (f", firma {', '.join(signatures)}" if signatures else "")
        + f". En las 24 h siguientes esa IP no consiguió ninguna petición con éxito ({len(waf_later)} en el WAF, todas bloqueadas) "
        "ni aparece en los logs de la tienda. Es un intento real sin efecto: verdadero positivo con −1 por el bloqueo, y se cierra. "
        + RULE_NOTE
    )
    check.evidence = [
        {
            "source": "waf",
            "event_id": row["event_id"],
            "finding": f"{row.get('status')} {row.get('action')} desde {ip}"
            + (f", firma {row.get('rule_id')} ({row.get('rule_msg')})" if row.get("rule_id") else ""),
        }
        for row in rows
    ]
    check.enrichment = _intel_for(context, ip)
    service = RULE_SERVICE.get("UC-WEB-001")
    check.affected = {"business_services": [service] if service else []}
    return check


# Detection rule -> the fixed rule that may close it. Every other alert goes to the LLM.
RULES = {
    "UC-EDR-002": sccm_inventory,
    "UC-WEB-001": blocked_web_scan,
}
