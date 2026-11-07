"""Small, deterministic analysis helpers; no network or model calls."""
import collections
import json
import re

import numpy as np
import pandas as pd

DAY_NS = pd.Timedelta(hours=24).value


def indexed_source(frame, wanted):
    """Row positions for each wanted value, with event times and row sizes in characters."""
    ordered = frame.sort_values("timestamp_utc", kind="stable").reset_index(drop=True)
    records = raw_records(ordered)
    positions = collections.defaultdict(list)
    for row, record in enumerate(records):
        for value in {str(v).casefold() for _, v in leaves(record)} & wanted:
            positions[value].append(row)
    times = ordered.timestamp_utc.dt.tz_convert("UTC").dt.tz_localize(None).astype("datetime64[ns]").astype("int64")
    return {
        "times": times.to_numpy(),
        "sizes": np.array([len(encoded(r)) for r in records]),
        "positions": {value: np.array(rows) for value, rows in positions.items()},
    }


def context_for(center, values, index):
    """Rows and characters within 24 hours of center that hold any of the values."""
    found = [index["positions"][v] for v in values if v in index["positions"]]
    if not found:
        return 0, 0
    rows = np.unique(np.concatenate(found))
    center = pd.Timestamp(center).tz_convert("UTC").tz_localize(None).as_unit("ns").value
    times = index["times"][rows]
    keep = rows[(times >= center - DAY_NS) & (times <= center + DAY_NS)]
    return len(keep), int(index["sizes"][keep].sum())


def leaves(value, path=""):
    """Yield field paths and scalar values without interpreting their contents."""
    if isinstance(value, dict):
        for key, child in value.items():
            yield from leaves(child, f"{path}.{key}" if path else key)
    elif isinstance(value, list):
        for child in value:
            yield from leaves(child, path + "[]")
    else:
        yield path, value


def raw_records(frame):
    return frame.drop(columns=[c for c in frame if c.endswith("_utc")]).to_dict("records")


def encoded(row):
    return json.dumps(row, ensure_ascii=False, default=str)


def exact_mask(frame, values):
    """Match full scalar values, including nested JSON and email recipients."""
    wanted = {str(x).casefold() for x in values if x}
    return pd.Series([
        any(str(v).casefold() in wanted for _, v in leaves(r))
        for r in raw_records(frame)
    ], index=frame.index, dtype=bool)


def entity_values(alert):
    return {str(v) for field, v in leaves(alert["entities"])
            if v and not field.endswith("display_name")}


def change_times(changes, zone="Europe/Madrid"):
    result = changes.copy()
    for col in ("inicio", "fin"):
        result[col + "_utc"] = pd.to_datetime(result[col]).dt.tz_localize(
            zone, ambiguous="raise", nonexistent="raise").dt.tz_convert("UTC")
    return result


def change_window(times, change, calendar):
    row = calendar.set_index("id").loc[change]
    return times.between(row.inicio_utc, row.fin_utc)


def approval_refs(value):
    return set(re.findall(r"\b(?:CHG-\d{4}-\d+|FLUJO-\d+|SEC-\d+)\b", encoded(value)))


RUNBOOK_SOURCES = {
    "RB-01": ["email", "email_clicks", "proxy", "edr_events", "idp_signins", "idp_audit"],
    "RB-02": ["edr_events", "proxy", "firewall", "ad_events"],
    "RB-03": ["idp_signins", "idp_audit", "vpn", "ad_events"],
    "RB-04": ["dlp", "sql_audit", "edr_events", "email", "proxy"],
    "RB-05": ["waf", "ecom_auth", "ecom_account", "edr_events", "proxy"],
    "RB-06": ["cloudtrail", "cicd_builds"],
    "RB-07": ["ai_gateway"],
    "RB-08": ["firewall", "edr_events", "vpn"],
    "RB-09": ["proxy", "dns", "firewall", "edr_events", "ad_events"],
    "RB-10": ["cicd_builds", "cloudtrail", "proxy"],
}
