"""Reads alerts from JSON or JSONL text, for the live test and for the sample queue.

The request body is the file's content. File paths are never taken from a request:
load_alerts(path) is only called by the server, for the sample file.
Alerts are kept exactly as given. Their text may be written by an attacker, so it is
only ever stored and shown, never interpreted.
"""
import json
import re
from pathlib import Path

MAX_BYTES = 2_000_000
MAX_ROWS = 1000
ALERT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,99}")


class ImportProblem(ValueError):
    """The whole file can't be read. The message is safe to show and never repeats the file's content."""


def _no_constants(name):
    raise ValueError(f"{name} is not allowed")


def _loads(text):
    # NaN and Infinity aren't valid JSON, and the API couldn't send them back.
    return json.loads(text, parse_constant=_no_constants)


def _rows(text):
    """Returns (format, [(row number, value or None, problem or None)])."""
    try:
        data = _loads(text)
    except ValueError:
        data = None
    else:
        if isinstance(data, list):
            return "json", [(n, value, None) for n, value in enumerate(data, 1)]
        if isinstance(data, dict) and isinstance(data.get("alerts"), list):
            return "json", [(n, value, None) for n, value in enumerate(data["alerts"], 1)]
        if isinstance(data, dict):
            return "json", [(1, data, None)]
        raise ImportProblem("El JSON debe ser un objeto, una lista de objetos o {\"alerts\": [...]}.")
    rows = []
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            rows.append((n, _loads(line), None))
        except ValueError:
            rows.append((n, None, "La línea no es JSON válido."))
    return "jsonl", rows


def _check(value, problem, first_row, n):
    if problem:
        return problem
    if not isinstance(value, dict):
        return "No es un objeto JSON."
    alert_id = value.get("alert_id")
    if not isinstance(alert_id, str) or not alert_id.strip():
        return "Falta alert_id o no es texto."
    if not ALERT_ID.fullmatch(alert_id):
        return "alert_id con formato no válido: solo letras, números y . _ : -, hasta 100 caracteres."
    if alert_id in first_row:
        return f"alert_id repetido en el fichero (ya aparece en la fila {first_row[alert_id]})."
    first_row[alert_id] = n
    return None


def parse_alerts(raw, max_bytes=MAX_BYTES, max_rows=MAX_ROWS):
    """Returns {"format", "rows", "alerts", "errors"}. Bad rows are reported, good rows are kept.

    Raises ImportProblem when nothing can be read at all.
    """
    if max_bytes is not None and len(raw) > max_bytes:
        raise ImportProblem(f"El fichero supera el máximo de {max_bytes // 1000} KB.")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ImportProblem("El fichero no es texto UTF-8.") from None
    if not text.strip():
        raise ImportProblem("El fichero está vacío.")
    fmt, rows = _rows(text)
    if max_rows is not None and len(rows) > max_rows:
        raise ImportProblem(f"El fichero tiene {len(rows)} filas; el máximo es {max_rows}.")
    alerts, errors, first_row = [], [], {}
    for n, value, problem in rows:
        problem = _check(value, problem, first_row, n)
        if problem:
            errors.append({"row": n, "error": problem})
        else:
            alerts.append(value)
    return {"format": fmt, "rows": len(rows), "alerts": alerts, "errors": errors}


def load_alerts(path):
    """Loads a server-side alerts file, such as the development sample. Returns (alerts, errors)."""
    result = parse_alerts(Path(path).read_bytes(), max_bytes=None, max_rows=None)
    return result["alerts"], result["errors"]
