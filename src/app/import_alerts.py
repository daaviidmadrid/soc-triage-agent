"""Reads alerts from JSON, JSONL or CSV text, for the alerts we receive and for the sample queue.

The request body is the file's content. File paths are never taken from a request:
load_alerts(path) is only called by the server, for the sample file.
We don't know the format we'll be given, so this accepts other wrappers and field names. Original
fields and values are always kept. Alert text may be written by an attacker, so it is only ever
stored and shown, never interpreted.
"""
import csv
import hashlib
import io
import json
import re
from pathlib import Path

from src.tools.alert_fields import known_field, rename_fields

MAX_BYTES = 2_000_000
MAX_ROWS = 1000
ALERT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,99}")
FENCE = re.compile(r"^\s*```[A-Za-z]*\s*\n(.*?)\n?\s*```\s*$", re.DOTALL)
WRAPPER_KEYS = ("alerts", "alertas", "data", "datos", "items", "results", "resultados", "records", "rows", "hits", "value")
INNER_ALERT_KEYS = ("_source", "alert", "alerta")
CONTENT_FIELDS = ("rule_id", "rule_name", "description", "severity", "entities", "related_events")
CSV_DELIMITERS = ",;\t|"


class ImportProblem(ValueError):
    """The whole file can't be read. The message is safe to show and never repeats the file's content."""


def _no_constants(name):
    raise ValueError(f"{name} is not allowed")


def _loads(text):
    # NaN and Infinity aren't valid JSON, and the API couldn't send them back.
    return json.loads(text, parse_constant=_no_constants)


def _decode(raw):
    """Text from the file's bytes, with a clear message for files that need exporting first."""
    if raw[:4] == b"PK\x03\x04":
        raise ImportProblem("Parece un Excel o un ZIP. Expórtalo a CSV o JSON e impórtalo de nuevo.")
    if raw[:5] == b"%PDF-":
        raise ImportProblem("Es un PDF. Copia las alertas a un fichero CSV o JSON e impórtalo de nuevo.")
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        try:
            text = raw.decode("utf-16")
        except UnicodeDecodeError:
            raise ImportProblem("El fichero no se puede leer como texto.") from None
        if text.strip()[:1].isascii():
            return text
        raise ImportProblem("El fichero no se puede leer como texto.")
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        if b"\x00" in raw:
            raise ImportProblem("El fichero no se puede leer como texto.") from None
        return raw.decode("cp1252", errors="replace")  # how Excel on Windows saves a Spanish CSV


def _is_alert_list(value):
    return isinstance(value, list) and any(isinstance(item, dict) for item in value)


def _wrapped_list(data, depth=0):
    """The list of alerts inside an export such as {"data": [...]} or {"hits": {"hits": [...]}}."""
    for key, value in data.items():
        if str(key).lower() in WRAPPER_KEYS:
            if _is_alert_list(value):
                return value
            if isinstance(value, dict) and depth < 2:
                found = _wrapped_list(value, depth + 1)
                if found is not None:
                    return found
    if depth == 0 and not any(known_field(key) for key in data):
        lists = [value for value in data.values() if _is_alert_list(value)]
        if len(lists) == 1:
            return lists[0]
    return None


def _unwrap(value):
    """Some tools put each alert under a key, such as {"_source": {...}}."""
    if isinstance(value, dict) and "alert_id" not in value:
        for key in INNER_ALERT_KEYS:
            if isinstance(value.get(key), dict):
                return value[key]
    return value


def _json_rows(data):
    if isinstance(data, list):
        return [(n, _unwrap(value), None) for n, value in enumerate(data, 1)]
    if isinstance(data, dict):
        inner = _wrapped_list(data)
        if inner is not None:
            return [(n, _unwrap(value), None) for n, value in enumerate(inner, 1)]
        return [(1, _unwrap(data), None)]
    raise ImportProblem("El JSON debe ser un objeto, una lista de objetos o {\"alerts\": [...]}.")


def _concatenated(text):
    """JSON objects one after another, as when several pretty-printed alerts are pasted together."""
    decoder = json.JSONDecoder(parse_constant=_no_constants)
    values, position = [], 0
    while True:
        while position < len(text) and text[position] in " \t\r\n,":
            position += 1
        if position >= len(text):
            return values
        try:
            value, position = decoder.raw_decode(text, position)
        except ValueError:
            return None
        values.append(value)


def _cell(value):
    text = value.strip()
    if text[:1] in ("{", "["):
        try:
            return _loads(text)
        except ValueError:
            pass
    return text


def _csv_rows(text):
    """Rows of a table whose header names at least one alert field, or None if it isn't one."""
    lines = [line for line in text.splitlines() if line.strip()]
    if len(lines) < 2 or lines[0].lstrip()[:1] in ("{", "["):
        return None
    delimiter = max(CSV_DELIMITERS, key=lines[0].count)
    if delimiter not in lines[0]:
        return None
    reader = csv.DictReader(io.StringIO(text.strip()), delimiter=delimiter)
    try:
        if not any(known_field(name) in ("alert_id", "rule_id", "rule_name") for name in reader.fieldnames or []):
            return None
        rows = []
        for row in reader:
            value = {str(key).strip(): _cell(cell) for key, cell in row.items() if key and isinstance(cell, str) and cell.strip()}
            rows.append((reader.line_num, value, None))
    except csv.Error:
        return None
    return rows


def _rows(text):
    """Returns (format, [(row number, value or None, problem or None)])."""
    fenced = FENCE.match(text)
    if fenced:
        text = fenced.group(1)
    try:
        data = _loads(text)
    except ValueError:
        pass
    else:
        return "json", _json_rows(data)
    rows, every_line_is_json = [], True
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            rows.append((n, _unwrap(_loads(line)), None))
        except ValueError:
            every_line_is_json = False
            rows.append((n, None, "La línea no es JSON válido."))
    if every_line_is_json:
        return "jsonl", rows
    together = _concatenated(text)
    if together:
        return "json", [row for value in together for row in _json_rows(value)]
    table = _csv_rows(text)
    if table is not None:
        return "csv", table
    return "jsonl", rows


def _prepare(value, problem, first_row, n):
    """Returns (alert in our field names, or None, and the problem with this row, or None)."""
    if problem:
        return None, problem
    if not isinstance(value, dict):
        return None, "No es un objeto JSON."
    alert = rename_fields(value)
    alert_id = alert.get("alert_id")
    if isinstance(alert_id, int) and not isinstance(alert_id, bool):
        alert_id = str(alert_id)
    if isinstance(alert_id, str):
        alert_id = re.sub(r"\s+", "-", alert_id.strip())
    if not alert_id and any(alert.get(field) for field in CONTENT_FIELDS):
        # A real alert with no ID still has to be triaged. The ID comes from its content, so importing it twice gives the same one.
        digest = hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, default=str).encode()).hexdigest()
        alert_id = f"IMP-{digest[:12]}"
    if not isinstance(alert_id, str) or not alert_id:
        return None, "Falta alert_id o no es texto."
    if not ALERT_ID.fullmatch(alert_id):
        return None, "alert_id con formato no válido: solo letras, números y . _ : -, hasta 100 caracteres."
    if alert_id in first_row:
        return None, f"alert_id repetido en el fichero (ya aparece en la fila {first_row[alert_id]})."
    first_row[alert_id] = n
    alert["alert_id"] = alert_id
    return alert, None


def parse_alerts(raw, max_bytes=MAX_BYTES, max_rows=MAX_ROWS):
    """Returns {"format", "rows", "alerts", "errors"}. Bad rows are reported, good rows are kept.

    Raises ImportProblem when nothing can be read at all.
    """
    if max_bytes is not None and len(raw) > max_bytes:
        raise ImportProblem(f"El fichero supera el máximo de {max_bytes // 1000} KB.")
    text = _decode(raw)
    if not text.strip():
        raise ImportProblem("El fichero está vacío.")
    fmt, rows = _rows(text)
    if max_rows is not None and len(rows) > max_rows:
        raise ImportProblem(f"El fichero tiene {len(rows)} filas; el máximo es {max_rows}.")
    alerts, errors, first_row = [], [], {}
    for n, value, problem in rows:
        alert, problem = _prepare(value, problem, first_row, n)
        if problem:
            errors.append({"row": n, "error": problem})
        else:
            alerts.append(alert)
    return {"format": fmt, "rows": len(rows), "alerts": alerts, "errors": errors}


def load_alerts(path):
    """Loads a server-side alerts file, such as the development sample. Returns (alerts, errors)."""
    result = parse_alerts(Path(path).read_bytes(), max_bytes=None, max_rows=None)
    return result["alerts"], result["errors"]
