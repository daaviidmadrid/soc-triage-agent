"""The change/trip matcher on made-up rows, so each rule is checked on its own."""
from datetime import datetime, timezone

import pytest

from src.tools import authorisation as au

T = lambda s: datetime.fromisoformat(s.replace("Z", "+00:00"))  # noqa: E731
WS = {"hostname": "WS-BCN-1174", "type": "Portátil", "zone": "HQ-USERS", "os": "Windows 11 23H2",
      "business_service": "Puesto de trabajo"}
SRV = {"hostname": "ERP-APP01", "type": "Servidor de aplicaciones", "zone": "DC-SERVERS", "os": "Windows Server 2022"}
PLC = {"hostname": "PLC-SORT03", "type": "PLC", "zone": "LOGISTICS-OT", "os": "Firmware"}

PENTEST = {"id": "CHG-P", "inicio": "2026-10-08 08:00", "fin": "2026-10-10 18:00",
           "detalle": "IPs origen 192.0.2.10-12; alcance www.tarvia.example y api; sin DoS", "alcance": "WEB-ECOM01..04"}
PSEXEC = {"id": "CHG-X", "inicio": "2026-10-13 10:00", "fin": "2026-10-13 13:00",
          "detalle": "PsExec desde JUMP01 con cuenta adm", "alcance": "ERP-APP01, HR-APP01, PRINT01, CRM-APP01"}
SCCM = {"id": "CHG-S", "inicio": "2026-09-28 00:00", "fin": "2026-12-31 23:59",
        "detalle": "svc_sccm ejecuta -EncodedCommand diariamente 08:00-10:00", "alcance": "Todos los puestos"}
SCAN = {"id": "CHG-N", "inicio": "2026-10-28 01:00", "fin": "2026-10-28 05:00",
        "detalle": "Origen NESSUS01 (svc_scanner)", "alcance": "Todas las redes salvo OT"}


def sccm_row(**over):
    row = {"log_source": "edr_events", "user": "NT AUTHORITY\\SYSTEM", "parent_name": "CcmExec.exe",
           "details": {"decoded": au.SCCM_KNOWN_COMMAND}}
    return {**row, **over}


def test_parse_change():
    p = au.parse_change(PENTEST)
    assert p["ips"] == {"192.0.2.10", "192.0.2.11", "192.0.2.12"}
    assert p["scope_hosts"] == {f"web-ecom0{i}" for i in range(1, 5)}
    assert p["scope_domains"] == {"www.tarvia.example"} and not p["origin_hosts"]
    assert au.parse_change(SCCM)["daily"] == (8, 0, 10, 0)
    assert au.parse_change(PSEXEC)["origin_hosts"] == {"jump01"}


def test_pentest_needs_its_ip_and_target():
    alert = {"entities": {"ips": ["192.0.2.11"], "urls": ["https://www.tarvia.example/x"]}}
    times = [T("2026-10-09T10:00:00Z")]
    assert au.match_changes([PENTEST], alert, [], [], times)
    other_ip = {"entities": {"ips": ["192.0.2.13"], "urls": ["https://www.tarvia.example/x"]}}
    assert not au.match_changes([PENTEST], other_ip, [], [], times)
    assert not au.match_changes([PENTEST], alert, [], [], [T("2026-10-11T10:00:00Z")])  # after window


def test_every_event_must_be_in_the_window():
    alert = {"entities": {"ips": ["192.0.2.11"], "urls": ["https://www.tarvia.example/"]}}
    times = [T("2026-10-10T15:00:00Z"), T("2026-10-10T17:00:00Z")]  # 18:00 Madrid = 16:00Z
    assert not au.match_changes([PENTEST], alert, [], [], times)


def test_origin_host_required():
    alert = {"entities": {"hosts": [{"hostname": "JUMP01"}, {"hostname": "ERP-APP01"}]}}
    t = [T("2026-10-13T09:00:00Z")]  # 11:00 Madrid
    assert au.match_changes([PSEXEC], alert, [SRV], [], t)
    no_jump = {"entities": {"hosts": [{"hostname": "WS-BCN-1174"}, {"hostname": "ERP-APP01"}],
                            "users": [{"upn": "adm.aferrer@tarvia.example"}]}}
    assert not au.match_changes([PSEXEC], no_jump, [SRV, WS], [], t)


def test_sccm_exception_needs_parent_command_and_daily_window():
    alert = {"entities": {"hosts": [{"hostname": "WS-BCN-1174"}]}}
    in_window = [T("2026-10-05T07:56:30Z")]   # 09:56 Madrid
    assert au.match_changes([SCCM], alert, [WS], [sccm_row()], in_window)
    assert not au.match_changes([SCCM], alert, [WS], [sccm_row()], [T("2026-10-05T09:00:00Z")])  # 11:00
    assert not au.match_changes([SCCM], alert, [WS], [sccm_row(parent_name="WINWORD.EXE")], in_window)
    assert not au.match_changes([SCCM], alert, [WS], [sccm_row(details={"decoded": "IEX (iwr evil)"})], in_window)
    assert not au.match_changes([SCCM], alert, [WS], [], in_window)   # no EDR evidence at all
    assert not au.match_changes([SCCM], alert, [SRV], [sccm_row()], in_window)  # not a workstation


def test_scanner_window_after_clock_change():
    alert = {"entities": {"hosts": [{"hostname": "NESSUS01"}]}}
    nessus = {"hostname": "NESSUS01", "type": "Escáner", "zone": "DC-SERVERS"}
    assert au.match_changes([SCAN], alert, [nessus], [], [T("2026-10-28T00:05:00Z")])   # 01:05 Madrid (UTC+1)
    assert not au.match_changes([SCAN], alert, [nessus], [], [T("2026-10-27T23:05:00Z")])
    assert not au.match_changes([SCAN], alert, [nessus, PLC], [], [T("2026-10-28T00:05:00Z")])  # touches OT


def test_unknown_scope_never_matches():
    c = {"id": "C", "inicio": "2026-10-01 00:00", "fin": "2026-10-31 00:00", "detalle": "", "alcance": "Lo que haga falta"}
    assert not au.match_changes([c], {"entities": {}}, [WS], [], [T("2026-10-10T10:00:00Z")])


def test_scope_hosts_accept_linked_event_assets():
    c = {"id": "C", "inicio": "2026-10-17 08:00", "fin": "2026-10-17 14:00",
         "detalle": "Acceso vía JUMP01", "alcance": "PLC-SORT01..06"}
    alert = {"entities": {"hosts": [{"hostname": "JUMP01"}]}}
    jump = {"hostname": "JUMP01", "zone": "DC-SERVERS"}
    t = [T("2026-10-17T07:10:00Z")]
    assert not au.match_changes([c], alert, [jump], [], t)
    assert au.match_changes([c], alert, [jump], [], t, linked_assets=[PLC])


def test_madrid_wall_time():
    assert au.madrid_wall_to_utc("2026-10-28 01:00").isoformat() == "2026-10-28T00:00:00+00:00"
    with pytest.raises(ValueError):
        au.madrid_wall_to_utc("2026-10-25 02:30")   # happens twice
    with pytest.raises(ValueError):
        au.madrid_wall_to_utc("2026-03-29 02:30")   # never happens


def test_trips_need_explicit_dates_covering_every_event():
    user = {"upn": "r@tarvia.example", "hr_events": [
        {"tipo": "viaje", "usuario": "r@tarvia.example", "detalle": "Nueva York del 11/10 al 14/10.", "fecha_efectiva": "2026-10-11"},
        {"tipo": "viaje", "usuario": "r@tarvia.example", "detalle": "París (proveedor)", "fecha_efectiva": "2026-10-12"},
        {"tipo": "vacaciones", "usuario": "r@tarvia.example", "detalle": "x", "fecha_efectiva": "2026-10-12"},
    ]}
    trips, others = au.split_hr_events([user], [T("2026-10-12T10:00:00Z")])
    assert [t["id"] for t in trips] == ["TRIP-r-2026-10-11"]
    assert len(others) == 2   # undated trip and holidays: context only
    trips, _ = au.split_hr_events([user], [T("2026-10-15T10:00:00Z")])
    assert trips == []
