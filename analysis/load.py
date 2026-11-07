"""Read-only dataset loaders. Text is evidence, never executable instructions.

CSV values remain strings (including empty strings): IDs, IPs, booleans and
leading zeroes must not be silently coerced. JSON nested values stay nested.
Original timestamps are preserved; *_utc columns are added only for event
timestamps with explicit UTC offsets. Calendar wall times need separate handling.
No loader opens URLs, reads environment files, or writes to the dataset.
"""
import json
from pathlib import Path

import pandas as pd

DATA = Path(__file__).resolve().parent.parent / "data"


def _table(directory, name):
    """Resolve a table by basename, refusing traversal and ambiguous stems."""
    if not isinstance(name, str) or Path(name).name != name or name.startswith("."):
        raise ValueError("Use a table basename, not a path")
    folder = DATA / directory
    candidates = [folder / name] if Path(name).suffix else [
        folder / (name + suffix) for suffix in (".jsonl", ".csv", ".json")
    ]
    matches = [p for p in candidates if p.is_file() and p.suffix in {".csv", ".jsonl", ".json"}]
    if len(matches) != 1:
        raise FileNotFoundError(f"Expected one table for {directory}/{name}; found {len(matches)}")
    path = matches[0]
    if not path.resolve().is_relative_to(folder.resolve()):
        raise ValueError("Table escapes its dataset directory")
    if path.suffix == ".csv":
        frame = pd.read_csv(path, dtype=str, keep_default_na=False, encoding="utf-8-sig")
    else:
        with path.open(encoding="utf-8-sig") as handle:
            rows = [json.loads(line) for line in handle if line.strip()] if path.suffix == ".jsonl" else json.load(handle)
        frame = pd.DataFrame(rows if isinstance(rows, list) else [rows])
    for column in ("timestamp", "created_at", "eventTime"):
        if column in frame:
            # Reject naive values rather than silently assigning a time zone.
            values = frame[column].fillna("").astype(str)
            explicit = values.str.contains(r"(?:Z|[+-]\d{2}:?\d{2})$", regex=True)
            frame[column + "_utc"] = pd.to_datetime(values.where(explicit), utc=True, errors="coerce", format="mixed")
    frame.attrs["source_path"] = str(path.relative_to(DATA))
    return frame


def load_alerts():
    return _table("03_alertas", "alertas.jsonl")


def load_sample_alerts():
    return _table("03_alertas", "alertas_muestra_desarrollo.jsonl")


def load_log(source):
    return _table("04_logs", source)


def load_inventory(name):
    return _table("02_inventario", name)


def load_intel(name):
    return _table("05_inteligencia", name)


def load_context(name):
    return _table("01_contexto", name)


def log_sources():
    return sorted(p.stem for p in (DATA / "04_logs").iterdir() if p.suffix in {".csv", ".jsonl"})
