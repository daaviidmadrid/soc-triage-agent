"""search_logs() on the real data. Expected rows are computed straight from the files in
data/04_logs with each log's literal format, independently of LOG_FIELDS."""

import csv
import json
from functools import lru_cache
from pathlib import Path

import pytest

from src.tools import logs
from src.tools.logs import LOG_FIELDS, search_logs

DATA = Path(__file__).resolve().parents[1] / "data"


@lru_cache(maxsize=None)
def raw(source):
    p = DATA / "04_logs"
    if (p / f"{source}.jsonl").exists():
        with open(p / f"{source}.jsonl", encoding="utf-8") as f:
            return tuple(json.loads(l) for l in f if l.strip())
    with open(p / f"{source}.csv", encoding="utf-8") as f:
        return tuple(csv.DictReader(f))


def ids(rows):
    return {r["event_id"] for r in rows}


# One person per log format, each with another user whose username starts with theirs
# (marc.gil / marc.gil2 ...). The lambda says literally how that log writes the person.
PEOPLE = [
    ("idp_signins", "marc.gil", lambda r, n: r["user_upn"] == f"{n}@tarvia.example"),
    (
        "email",
        "marc.gil",
        lambda r, n: r["sender"] == f"{n}@tarvia.example" or f"{n}@tarvia.example" in r["recipients"],
    ),
    ("idp_audit", "marc.gil", lambda r, n: f"{n}@tarvia.example" in (r["actor_upn"], r["target"])),
    ("email_clicks", "neus.sala", lambda r, n: r["user"] == f"{n}@tarvia.example"),
    ("edr_events", "andrea.gomez", lambda r, n: r["user"] == f"TARVIA\\{n}"),
    ("proxy", "sergio.mas", lambda r, n: r["user"] == n),
    ("vpn", "sergio.mas", lambda r, n: r["user"] == n),
    ("dlp", "oriol.pons", lambda r, n: r["user"] == n),
    ("ad_events", "jordi.serra", lambda r, n: n in (r["subject"], r["target"])),
    ("sql_audit", "nuria.vidal", lambda r, n: r["user"] == n),
    ("cloudtrail", "cloud.admin", lambda r, n: r["userIdentity"].get("userName") == n),
]


@pytest.mark.parametrize("source,name,is_person", PEOPLE, ids=[p[0] for p in PEOPLE])
def test_person_in_every_log_format(source, name, is_person):
    expected = ids(r for r in raw(source) if is_person(r, name))
    assert expected, f"test data: {name} not in {source}"
    got = search_logs(source, user=f"{name}@tarvia.example")
    assert got["truncated"] is False
    assert ids(got["items"]) == expected


def test_every_source_with_user_fields_is_covered():
    with_users = {s for s, spec in LOG_FIELDS.items() if spec["user"]}
    assert with_users == {p[0] for p in PEOPLE}


@pytest.mark.parametrize("source", ["idp_signins", "edr_events", "proxy", "email"])
def test_username_prefix_does_not_leak(source):
    """laura.ferrer must not return laura.ferrer2 rows, and the other way round."""
    a = ids(search_logs(source, user="laura.ferrer@tarvia.example")["items"])
    b = ids(search_logs(source, user="laura.ferrer2@tarvia.example")["items"])
    assert b, f"laura.ferrer2 should appear in {source}"
    assert not (a & b)


def test_ip_prefix_does_not_leak_proxy():
    ip = "10.10.2.2"  # 10.10.2.20..29 and 10.10.2.2xx also exist
    expected = ids(r for r in raw("proxy") if ip in (r["src_ip"], r["dst_ip"]))
    got = search_logs("proxy", ip=ip)
    assert ids(got["items"]) == expected
    assert all(ip in (r["src_ip"], r["dst_ip"]) for r in got["items"])


def test_ip_prefix_does_not_leak_firewall():
    ip = "10.40.1.12"
    expected = ids(r for r in raw("firewall") if ip in (r["src_ip"], r["dst_ip"]))
    got = search_logs("firewall", ip=ip)
    assert ids(got["items"]) == expected and expected


def test_host_exact_and_case_insensitive():
    got = search_logs("edr_events", host="ws-bcn-1380")
    expected = ids(r for r in raw("edr_events") if r["hostname"] == "WS-BCN-1380")
    assert ids(got["items"]) == expected and expected


def test_value_exact_any_field():
    got = search_logs("email", value="<CAF8x9-bec-0001@tarvia.example>")
    assert [r["event_id"] for r in got["items"]] == ["EML-0062205"]


def test_time_window_inclusive():
    rows = [r for r in raw("idp_signins") if r["user_upn"] == "laura.ferrer2@tarvia.example"]
    t0, t1 = rows[3]["timestamp"], rows[10]["timestamp"]
    got = search_logs("idp_signins", user="laura.ferrer2@tarvia.example", desde=t0, hasta=t1)
    assert ids(got["items"]) == ids(r for r in rows if t0 <= r["timestamp"] <= t1)


def test_combined_criteria_are_anded():
    got = search_logs("idp_signins", user="laura.ferrer2@tarvia.example", ip="203.0.113.45")
    assert got["items"] and all(r["src_ip"] == "203.0.113.45" for r in got["items"])


def test_unsupported_criterion():
    got = search_logs("firewall", user="laura.ferrer2@tarvia.example")
    assert got["items"] == [] and got["unsupported"] == ["user"]


def test_cut_off_is_split_into_smaller_windows(monkeypatch):
    full = ids(search_logs("proxy", ip="10.10.2.2")["items"])
    monkeypatch.setattr(logs, "API_LIMIT", 40)
    got = search_logs("proxy", ip="10.10.2.2", desde="2026-10-01T00:00:00Z", hasta="2026-11-03T00:00:00Z")
    assert got["truncated"] is False
    assert ids(got["items"]) == full


def test_cut_off_is_reported_when_splitting_is_not_enough(monkeypatch):
    monkeypatch.setattr(logs, "API_LIMIT", 40)
    monkeypatch.setattr(logs, "MAX_SPLIT_DEPTH", 0)
    got = search_logs("proxy", ip="10.10.2.2", desde="2026-10-01T00:00:00Z", hasta="2026-11-03T00:00:00Z")
    assert got["truncated"] is True


def test_no_window_cut_off_is_reported():
    assert search_logs("dns", ip="198.18.0.7")["truncated"] is True
