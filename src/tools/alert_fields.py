"""Puts an alert into the shape the rest of the system expects, whatever its source called things.

We don't know the format of the alerts Deloitte will give us, so this accepts other field names,
fills gaps from Deloitte's rule catalogue and says what it had to assume. It never reads an alert's
text as instructions, and it never drops a field, so the original values stay visible.
"""
import csv
import re
import unicodedata
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

CATALOGUE = Path(__file__).resolve().parents[2] / "data" / "01_contexto" / "catalogo_casos_de_uso.csv"

DEFAULT_SEVERITY = "medium"

# Other names a field might have. Compared without case, accents, spaces or punctuation.
FIELD_NAMES = {
    "alert_id": ("id", "alertid", "alert", "alerta", "idalerta", "alertaid", "alertuid", "uuid"),
    "created_at": ("createdat", "timestamp", "time", "date", "datetime", "fecha", "fechahora", "hora", "eventtime",
                   "detectedat", "alerttime", "fechaalerta"),
    "rule_id": ("ruleid", "rule", "regla", "idregla", "reglaid", "usecase", "usecaseid", "casodeuso", "uc"),
    "rule_name": ("rulename", "name", "title", "nombre", "titulo", "nombreregla", "alertname"),
    "severity": ("severidad", "sev", "priority", "prioridad", "level", "nivel"),
    "description": ("descripcion", "desc", "summary", "resumen", "detail", "details", "detalle", "message", "mensaje"),
    "source_product": ("sourceproduct", "product", "producto", "source", "fuente", "origen"),
    "entities": ("entidades", "entity", "entidad", "observables"),
    "related_events": ("relatedevents", "eventosrelacionados", "events", "eventos", "eventids", "idseventos"),
    "evidence": ("evidencia", "evidencias"),
    "runbook": ("playbook", "manual"),
}
_ALIAS_TO_FIELD = {alias: field for field, aliases in FIELD_NAMES.items() for alias in aliases}

SEVERITY_WORDS = {
    "informational": "informational", "info": "informational", "informativa": "informational", "informativo": "informational",
    "informacional": "informational", "none": "informational", "low": "low", "baja": "low", "bajo": "low",
    "medium": "medium", "med": "medium", "moderate": "medium", "media": "medium", "medio": "medium", "moderada": "medium",
    "high": "high", "alta": "high", "alto": "high", "critical": "critical", "crit": "critical", "critica": "critical",
    "critico": "critical", "severe": "critical",
}

# Only used when the alert names no entities we can read. These are lookup keys, nothing more.
IP = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
SHA256 = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])")
HOSTNAME = re.compile(r"(?<![\w-])[A-Z][A-Z0-9]+(?:-[A-Z0-9]+)*(?![\w-])")
NOT_A_HOST = re.compile(r"^(?:UC|CHG|CVE|SEC|RB|ALR|TKT|INC|RUN|T\d)")
EVENT_ID = re.compile(r"(?<![\w-])[A-Z]{2,4}-\d{5,}(?![\w-])")
ENTITY_KEYS = ("users", "hosts", "ips", "domains", "urls", "files", "processes", "customers", "ai_session", "cloud")
MAX_FOUND = 12
MAX_TEXT = 20_000

TIME_FORMATS = ("%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M", "%d/%m/%Y", "%d-%m-%Y %H:%M:%S", "%d-%m-%Y %H:%M", "%d-%m-%Y",
                "%Y/%m/%d %H:%M:%S", "%Y/%m/%d %H:%M", "%Y/%m/%d")


def _key(name):
    text = unicodedata.normalize("NFKD", str(name)).encode("ascii", "ignore").decode()
    return re.sub(r"[^a-z0-9]", "", text.lower())


def known_field(name):
    """The expected name for a column or field, or None if we don't know it."""
    key = _key(name)
    return _ALIAS_TO_FIELD.get(key) or next((field for field in FIELD_NAMES if _key(field) == key), None)


def severity_word(value):
    """'Alta' -> 'high'. None if the value isn't a severity we recognise."""
    return SEVERITY_WORDS.get(_key(value)) if isinstance(value, str) else None


def rename_fields(alert):
    """Adds the expected field name beside any other name for it, and turns 'Alta' into 'high'.

    A field already named correctly wins, and the original names and values are kept."""
    if not isinstance(alert, dict):
        return alert
    clean = dict(alert)
    for name, value in alert.items():
        field = _ALIAS_TO_FIELD.get(_key(name))
        if not field or value in (None, "") or clean.get(field) not in (None, ""):
            continue
        if field == "alert_id" and not isinstance(value, (str, int)):
            continue  # {"alert": {...}} holds a whole alert, not an ID
        clean[field] = value
    word = severity_word(clean.get("severity"))
    if word and clean.get("severity") != word:
        clean["severity_original"] = clean["severity"]
        clean["severity"] = word
    return clean


@lru_cache(maxsize=1)
def _catalogue_rows():
    try:
        with open(CATALOGUE, encoding="utf-8", newline="") as file:
            return tuple(csv.DictReader(file))
    except OSError:
        return ()


def catalogue_rule(alert):
    """The catalogue row for this alert, by rule ID and otherwise by its exact rule name."""
    rule_id, rule_name = alert.get("rule_id"), _key(alert.get("rule_name") or "")
    for row in _catalogue_rows():
        if row.get("rule_id") == rule_id or (rule_name and _key(row.get("nombre") or "") == rule_name):
            return row
    return None


def fill_from_catalogue(alert):
    """Adds what the catalogue knows about the alert's rule, without changing anything the alert already says."""
    rule = catalogue_rule(alert)
    if not rule:
        return alert, None
    filled = dict(alert)
    for field, column in (("rule_id", "rule_id"), ("rule_name", "nombre"), ("runbook", "runbook"), ("source_product", "fuente")):
        if not filled.get(field) and rule.get(column):
            filled[field] = rule[column]
    return filled, rule


def parse_time(value):
    """Returns (ISO time in UTC, whether a timezone had to be assumed), or (None, False) if it can't be read."""
    if isinstance(value, bool):
        return None, False
    if isinstance(value, str) and value.strip().isdigit():
        value = int(value.strip())
    if isinstance(value, (int, float)):
        seconds = value / 1000 if value > 100_000_000_000 else value
        try:
            moment = datetime.fromtimestamp(seconds, timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None, False
        return moment.isoformat(timespec="milliseconds").replace("+00:00", "Z"), False
    if not isinstance(value, str) or not value.strip():
        return None, False
    text = value.strip()
    try:
        moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        for form in TIME_FORMATS:
            try:
                moment = datetime.strptime(text, form)
                break
            except ValueError:
                continue
        else:
            return None, False
    assumed = moment.tzinfo is None
    moment = moment.replace(tzinfo=timezone.utc) if assumed else moment.astimezone(timezone.utc)
    return moment.isoformat(timespec="milliseconds").replace("+00:00", "Z"), assumed


def _strings(value, depth=0):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict) and depth < 6:
        for item in value.values():
            yield from _strings(item, depth + 1)
    elif isinstance(value, list) and depth < 6:
        for item in value:
            yield from _strings(item, depth + 1)


def _has_entities(entities):
    return isinstance(entities, dict) and any(entities.get(key) for key in ENTITY_KEYS)


def entities_from_text(alert):
    """Finds users, hosts, IPs and hashes written in the alert's text. Each is only ever looked up exactly."""
    text = "\n".join(_strings({k: v for k, v in alert.items() if k not in ("alert_id", "rule_id")}))[:MAX_TEXT]
    emails = list(dict.fromkeys(EMAIL.findall(text)))[:MAX_FOUND]
    hashes = list(dict.fromkeys(item.lower() for item in SHA256.findall(text)))[:MAX_FOUND]
    ips = list(dict.fromkeys(IP.findall(text)))[:MAX_FOUND]
    events = set(EVENT_ID.findall(text))
    hosts = [item for item in dict.fromkeys(HOSTNAME.findall(text))
             if item not in events and any(c.isdigit() for c in item) and not NOT_A_HOST.match(item)][:MAX_FOUND]
    found = {}
    if emails:
        found["users"] = [{"upn": item} for item in emails]
    if hosts:
        found["hosts"] = [{"hostname": item} for item in hosts]
    if ips:
        found["ips"] = ips
    if hashes:
        found["files"] = [{"sha256": item} for item in hashes]
    return found


def _event_ids(value):
    """A list of event ID strings, from a list, a list of objects or text such as 'EDR-1;EDR-2'."""
    if isinstance(value, str):
        return EVENT_ID.findall(value)
    if isinstance(value, dict):
        value = [value]
    if not isinstance(value, list):
        return []
    ids = []
    for item in value:
        if isinstance(item, dict):
            item = item.get("event_id") or item.get("id")
        if isinstance(item, str) and item:
            ids.append(item)
    return ids


def normalise_alert(alert):
    """Returns (alert in the expected shape, notes in Spanish for the ticket on what had to be assumed)."""
    if not isinstance(alert, dict):
        return alert, []
    clean, rule = fill_from_catalogue(rename_fields(alert))
    notes = []
    if not rule:
        notes.append("La regla de esta alerta no está en el catálogo: se ha buscado en todas las fuentes de logs.")

    if not severity_word(clean.get("severity")):
        base = severity_word(rule.get("severidad_base")) if rule else None
        clean["severity"] = base or DEFAULT_SEVERITY
        if base:
            notes.append(f"La alerta no traía una severidad reconocible: se usa la del catálogo de reglas ({base}).")
        else:
            notes.append(f"La alerta no traía una severidad reconocible y la regla no está en el catálogo: se asume {DEFAULT_SEVERITY}.")

    if clean.get("created_at") not in (None, ""):
        moment, assumed = parse_time(clean["created_at"])
        if moment:
            clean["created_at"] = moment
            if assumed:
                notes.append("La fecha de la alerta no indicaba zona horaria: se asume UTC.")
        else:
            notes.append("No se ha podido leer la fecha de la alerta: se ha buscado en todo el periodo de los logs.")
    else:
        notes.append("La alerta no trae fecha: se ha buscado en todo el periodo de los logs.")

    if clean.get("related_events") is not None:
        clean["related_events"] = _event_ids(clean["related_events"])

    if not _has_entities(clean.get("entities")):
        found = entities_from_text(clean)
        if found:
            original = clean.get("entities")
            clean["entities"] = {**(original if isinstance(original, dict) else {}), **found}
            notes.append("La alerta no traía entidades legibles: se han deducido de su texto y conviene revisarlas.")
        else:
            notes.append("La alerta no nombra usuarios, equipos ni indicadores que se puedan consultar.")
    if not clean.get("runbook"):
        notes.append("No se ha encontrado un runbook para esta alerta.")
    return clean, notes
