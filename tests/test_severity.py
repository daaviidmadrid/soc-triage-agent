from pathlib import Path

import pytest

from src.policy import severity
from src.policy.severity import compute_severity, resolve_criticality

POLICY = Path(__file__).resolve().parents[1] / "data" / "01_contexto" / "politica_soc.md"


def policy_matrix():
    """Parse the severity table from section 2 of the policy markdown."""
    text = POLICY.read_text(encoding="utf-8")
    section = text.split("## 2.", 1)[1].split("## 3.", 1)[0]
    rows = [l for l in section.splitlines() if l.startswith("|")]
    header = [c.strip() for c in rows[0].strip("|").split("|")][1:]
    out = {}
    for line in rows[2:]:
        cells = [c.strip() for c in line.strip("|").split("|")]
        for crit, val in zip(header, cells[1:]):
            out[(cells[0], crit)] = val
    return out


CELLS = sorted(policy_matrix().items())


def test_policy_table_parsed_fully():
    assert len(CELLS) == 20  # 5 rule severities x 4 criticalities


@pytest.mark.parametrize("cell,expected", CELLS, ids=[f"{r}-{c}" for (r, c), _ in CELLS])
def test_every_matrix_cell(cell, expected):
    rule, crit = cell
    assert severity.MATRIX[rule][crit] == expected
    r = compute_severity(rule, crit)
    assert r["base"] == expected and r["final"] == expected and r["net_delta"] == 0


def test_criticality_aliases():
    assert compute_severity("low", "critica")["base"] == "medium"
    assert compute_severity("low", "critical")["base"] == "medium"
    with pytest.raises(ValueError):
        compute_severity("low", "enorme")
    with pytest.raises(ValueError):
        compute_severity("severe", "Alta")


def test_one_up():
    r = compute_severity("medium", "Media", [{"delta": 1, "reason": "ejecución confirmada"}])
    assert (r["base"], r["final"], r["net_delta"]) == ("medium", "high", 1)
    assert "ejecución confirmada" in r["reason"]


def test_cap_up_at_one_level():
    adj = [{"delta": 1, "reason": "VIP"}, {"delta": 1, "reason": "pagos"}, (1, "acceso confirmado")]
    r = compute_severity("medium", "Media", adj)
    assert r["final"] == "high" and r["net_delta"] == 1 and len(r["adjustments"]) == 3
    assert "limitado" in r["reason"]


def test_cap_down_at_one_level():
    r = compute_severity("high", "Alta", [(-1, "bloqueado"), (-1, "ruta inexistente")])
    assert r["final"] == "medium" and r["net_delta"] == -1


def test_up_and_down_cancel():
    r = compute_severity("high", "Alta", [(1, "VIP"), (-1, "bloqueado")])
    assert r["final"] == "high" and r["net_delta"] == 0


def test_sample_ticket_follows_policy_not_example():
    # ticket_ejemplo.json: low x Crítica = medium, -1 blocked, -1 path missing -> it says informational.
    # The policy caps at one level, so it is low.
    r = compute_severity("low", "Crítica", [(-1, "bloqueado por WAF"), (-1, "ruta inexistente")])
    assert r["final"] == "low"


def test_clamped_at_ends():
    assert compute_severity("critical", "Crítica", [(1, "x")])["final"] == "critical"
    assert compute_severity("informational", "Baja", [(-1, "x")])["final"] == "informational"


def test_floor_raises():
    r = compute_severity("low", "Media", runbook_floor="critical")
    assert r["base"] == "low" and r["final"] == "critical" and r["floor"] == "critical"


def test_floor_does_not_lower():
    assert compute_severity("high", "Crítica", runbook_floor="low")["final"] == "critical"


def test_floor_beyond_cap():
    r = compute_severity("low", "Media", [(1, "VIP")], runbook_floor="high")
    assert r["final"] == "high"


def test_authorised_gives_low():
    r = compute_severity("high", "Crítica", [(1, "x")], runbook_floor="high", authorised=True)
    assert r["final"] == "low" and r["authorised"] is True
    assert r["base"] == "critical"


def test_authorised_keeps_informational_base():
    assert compute_severity("low", "Baja", authorised=True)["final"] == "informational"
    assert compute_severity("informational", "Alta", authorised=True)["final"] == "low"


def test_incomplete_evidence_ignores_minus_one_but_not_plus_one():
    r = compute_severity("medium", "Media", [(-1, "bloqueado")], evidence_complete=False)
    assert r["final"] == "medium" and r["adjustments"][0]["applied"] is False
    assert "evidencia incompleta" in r["reason"]
    r = compute_severity("medium", "Media", [(1, "VIP"), (-1, "bloqueado")], evidence_complete=False)
    assert r["final"] == "high" and r["net_delta"] == 1


def test_adjustment_objects():
    class Adj:
        delta = -1
        reason = "bloqueado"
    assert compute_severity("medium", "Media", [Adj()])["final"] == "low"


# --- resolve_criticality ---

def ctx(entities=(), assets=(), users=()):
    return {"entities": [{"type": t, "value": v, "known": True} for t, v in entities],
            "assets": list(assets), "users": list(users)}


WS_ALTA = {"hostname": "WS-BCN-1001", "ip": "10.10.1.12", "criticality": "Alta"}
WS_MEDIA = {"hostname": "WS-BCN-1380", "ip": "10.10.2.141", "criticality": "Media"}
SRV = {"hostname": "WEB-ECOM01", "ip": "10.50.1.11", "criticality": "Crítica"}


def test_named_machine_first_and_most_critical():
    c = ctx([("host", "WS-BCN-1380"), ("host", "WEB-ECOM01")], [WS_MEDIA, SRV])
    assert resolve_criticality({"rule_id": "UC-EDR-002"}, c) == ("Crítica", "asset")


def test_named_machine_beats_service():
    c = ctx([("host", "WS-BCN-1380")], [WS_MEDIA])
    assert resolve_criticality({"rule_id": "UC-WEB-001"}, c) == ("Media", "asset")


def test_ip_known_to_cmdb_counts_as_machine():
    c = ctx([("ip", "10.50.1.11")], [SRV])
    assert resolve_criticality({"rule_id": "UC-NET-003"}, c) == ("Crítica", "asset")


def test_workstation_when_no_machine():
    user = {"upn": "enric.bosch@tarvia.example", "workstation": "WS-BCN-1001"}
    c = ctx([("user", user["upn"])], [WS_ALTA], [user])
    crit, src = resolve_criticality({"rule_id": "UC-IDP-001"}, c)
    assert (crit, src) == ("Alta", "workstation")


def test_workstation_beats_service():
    user = {"upn": "x@tarvia.example", "workstation": "WS-BCN-1380"}
    c = ctx([("user", user["upn"])], [WS_MEDIA], [user])
    assert resolve_criticality({"rule_id": "UC-WEB-003"}, c)[1] == "workstation"


def test_service_when_no_machine_or_workstation():
    c = ctx([("ip", "198.18.11.49")])
    assert resolve_criticality({"rule_id": "UC-WEB-001"}, c) == ("Crítica", "service")


def test_default_media():
    assert resolve_criticality({"rule_id": "UC-IDP-002"}, ctx([("user", "(12 cuentas)")])) == ("Media", "default")


def test_unknown_host_falls_through():
    c = ctx([("host", "NOT-IN-CMDB")])
    assert resolve_criticality({"rule_id": "UC-WEB-001"}, c) == ("Crítica", "service")
    assert resolve_criticality({"rule_id": "UC-OT-001"}, c) == ("Media", "default")


def test_every_mapped_service_exists():
    for service in severity.RULE_SERVICE.values():
        assert severity.service_criticality(service), service


def test_entities_as_dict_by_type():
    # Context.entities on main: {type: [{"value", "known"}]}; raw alert shape also accepted
    c = {"entities": {"host": [{"value": "WEB-ECOM01", "known": True}]}, "assets": [SRV], "users": []}
    assert resolve_criticality({"rule_id": "UC-EDR-002"}, c) == ("Crítica", "asset")
    c = {"entities": {"hosts": [{"hostname": "WEB-ECOM01"}]}, "assets": [SRV], "users": []}
    assert resolve_criticality({"rule_id": "UC-EDR-002"}, c) == ("Crítica", "asset")


def test_missing_services_file_falls_back(monkeypatch, tmp_path):
    monkeypatch.setattr(severity, "SERVICES_CSV", tmp_path / "none.csv")
    monkeypatch.setattr(severity, "_services", None)
    assert resolve_criticality({"rule_id": "UC-WEB-001"}, ctx()) == ("Media", "default")
    monkeypatch.setattr(severity, "_services", None)
