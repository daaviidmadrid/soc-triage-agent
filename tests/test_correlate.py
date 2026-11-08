"""Level 2 grouping. Real alerts from the dataset with made-up tickets, so no run of the LLM is needed.
Alert IDs appear here only to pick test cases: the code never uses them as a signal."""

import json

import pytest

from src.agent import correlate as c
from src.agent.correlate import allowed_kinds, correlate, identifiers, role

ALERTS = {}
with open(c.ALERTS_FILE, encoding="utf-8") as file:
    for line in file:
        alert = json.loads(line)
        ALERTS[alert["alert_id"]] = alert

LAURA = [
    "ALR-20261007-011785",
    "ALR-20261007-011786",
    "ALR-20261007-011787",
    "ALR-20261007-011788",
    "ALR-20261008-011789",
]
OTHER_LAURA = ["ALR-20261006-000669", "ALR-20261021-006668", "ALR-20261026-008532", "ALR-20261028-009212"]
CAMPAIGN_REPORTS = ["ALR-20261020-011910", "ALR-20261020-011905", "ALR-20261020-011903"]
LOGIN_GIVEN_AWAY = "ALR-20261020-011911"
NEWSLETTER_REPORT_BY_SAME_PERSON = "ALR-20261020-005930"


def ticket(alert_id, verdict="true_positive", severity="high", escalate=True, evidence=()):
    return {
        "ticket_id": f"TKT-{alert_id}",
        "alert_ids": [alert_id],
        "title": f"Ticket {alert_id}",
        "verdict": verdict,
        "confidence": 0.9,
        "severity": severity,
        "summary": "s",
        "evidence": [{"source": "x", "event_id": e, "finding": "f"} for e in evidence],
        "recommended_actions": [
            {"action": "escalate" if escalate else "close", "target": "N2", "requires_approval": False}
        ],
        "escalation": {"escalate": escalate, "to": "N2" if escalate else "", "reason": "r" if escalate else ""},
    }


def blocked_scan_ids(count):
    """Blocked web scans from different sources: look-alike noise."""
    found, sources = [], set()
    for alert_id, alert in ALERTS.items():
        ips = tuple((alert.get("entities") or {}).get("ips") or [])
        if alert.get("rule_id") == "UC-WEB-001" and ips and ips not in sources:
            sources.add(ips)
            found.append(alert_id)
        if len(found) == count:
            return found
    raise AssertionError("not enough scans in the dataset")


def run(spec):
    return correlate([(ALERTS[alert_id], t) for alert_id, t in spec.items()])


def incident_of(result, alert_id):
    for incident in result["incidents"]:
        if alert_id in incident["ticket"]["alert_ids"]:
            return incident
    return None


def test_laura_ferrer2_is_one_incident_without_laura_ferrer():
    spec = {alert_id: ticket(alert_id) for alert_id in LAURA}
    spec.update({alert_id: ticket(alert_id, severity="medium") for alert_id in OTHER_LAURA})
    result = run(spec)
    incident = incident_of(result, LAURA[0])
    assert sorted(incident["ticket"]["alert_ids"]) == sorted(LAURA)
    # laura.ferrer is another person with the same display name. Her alerts may form their own incident, never this one.
    assert all(result["memberships"].get(alert_id) != incident["incident_id"] for alert_id in OTHER_LAURA)


def test_the_reports_of_a_campaign_join_the_alert_where_a_login_was_given_away():
    spec = {LOGIN_GIVEN_AWAY: ticket(LOGIN_GIVEN_AWAY, severity="critical")}
    spec.update({alert_id: ticket(alert_id, severity="low", escalate=False) for alert_id in CAMPAIGN_REPORTS})
    spec[NEWSLETTER_REPORT_BY_SAME_PERSON] = ticket(
        NEWSLETTER_REPORT_BY_SAME_PERSON, verdict="false_positive", severity="low", escalate=False
    )
    result = run(spec)
    incident = incident_of(result, LOGIN_GIVEN_AWAY)
    assert set(incident["ticket"]["alert_ids"]) == {LOGIN_GIVEN_AWAY, *CAMPAIGN_REPORTS}
    assert NEWSLETTER_REPORT_BY_SAME_PERSON not in result["memberships"]
    reasons = " ".join(r for link in incident["ticket"]["group_links"] for r in link["reasons"])
    assert "mismo dominio de correo (packaging-iberia-pagos.example)" in reasons


def test_closed_campaign_reports_alone_stay_apart():
    """Reports nobody escalated are closed attacks: they join each other only through what they specifically share."""
    result = run({alert_id: ticket(alert_id, severity="low", escalate=False) for alert_id in CAMPAIGN_REPORTS})
    assert len(result["incidents"]) == 1 and result["incidents"][0]["ticket"]["escalation"]["escalate"] is False


def test_blocked_scans_from_different_sources_are_counted_not_merged():
    scans = blocked_scan_ids(6)
    result = run({alert_id: ticket(alert_id, severity="low", escalate=False) for alert_id in scans})
    assert result["incidents"] == []
    row = next(r for r in result["noise"] if r["rule_id"] == "UC-WEB-001")
    assert row["count"] == 6 and row["sources"] == 6


def test_false_positives_never_link_to_each_other():
    spec = {
        alert_id: ticket(alert_id, verdict="false_positive", severity="low", escalate=False)
        for alert_id in CAMPAIGN_REPORTS
    }
    assert run(spec)["incidents"] == []


def test_a_chain_of_low_alerts_is_escalated():
    spec = {LOGIN_GIVEN_AWAY: ticket(LOGIN_GIVEN_AWAY, severity="low", escalate=False)}
    spec.update({alert_id: ticket(alert_id, severity="low", escalate=False) for alert_id in CAMPAIGN_REPORTS[:1]})
    incident = run(spec)["incidents"][0]
    assert incident["chain"] is True
    assert incident["ticket"]["escalation"]["escalate"] is True
    assert "Cadena de 2 alertas" in incident["ticket"]["escalation"]["reason"]


def test_the_incident_takes_the_highest_severity_and_every_member_is_listed():
    spec = {LAURA[0]: ticket(LAURA[0], severity="medium"), LAURA[1]: ticket(LAURA[1], severity="critical")}
    incident = run(spec)["incidents"][0]
    assert incident["ticket"]["severity"] == "critical"
    assert incident["ticket"]["escalation"]["to"] == "N2 de guardia (teléfono)"
    assert [m["alert_id"] for m in incident["members"]] == sorted(spec, key=lambda a: ALERTS[a]["created_at"])
    assert incident["incident_id"].startswith("INC-")


def test_every_link_says_what_was_shared():
    spec = {alert_id: ticket(alert_id) for alert_id in LAURA}
    links = run(spec)["incidents"][0]["ticket"]["group_links"]
    assert links and all(link["reasons"] for link in links)
    assert all(not any("Laura Ferrer" in r for r in link["reasons"]) for link in links)


def test_the_same_grouping_twice_gives_the_same_incident():
    spec = {alert_id: ticket(alert_id) for alert_id in LAURA}
    assert (
        run(spec)["incidents"][0]["incident_id"]
        == run(dict(reversed(list(spec.items()))))["incidents"][0]["incident_id"]
    )


# The rules themselves


def test_display_names_and_shared_ips_are_never_identifiers():
    alert = {
        "alert_id": "X",
        "entities": {
            "users": [{"upn": "ana@tarvia.example", "display_name": "Ana Pérez"}],
            "ips": ["198.18.200.10", "10.1.1.1", "203.0.113.9"],
        },
    }
    found = identifiers(alert)
    assert ("account", "ana@tarvia.example") in found and ("ip", "203.0.113.9") in found
    assert not any("Ana Pérez" in value for _, value in found)
    assert ("ip", "198.18.200.10") not in found and ("ip", "10.1.1.1") not in found


def test_our_own_mail_domain_is_never_a_link():
    alert = {"alert_id": "X", "evidence": {"message_id": "<abc@tarvia.example>", "sender": "it@tarvia.example"}}
    assert not {"sender", "mail_domain"} & {kind for kind, _ in identifiers(alert)}


def test_ticket_evidence_adds_cited_events():
    assert ("event", "EVT-1") in identifiers({"alert_id": "X"}, ticket("X", evidence=["EVT-1"]))


def test_a_common_identifier_links_nothing(monkeypatch):
    spec = {alert_id: ticket(alert_id) for alert_id in LAURA[:2]}
    monkeypatch.setattr(c, "MAX_SHARED_BY", 0)
    assert run(spec)["incidents"] == []


def test_accounts_link_escalated_alerts_only_within_the_window(monkeypatch):
    alert_a = {
        "alert_id": "A",
        "created_at": "2026-10-01T00:00:00Z",
        "entities": {"users": [{"upn": "zz-test@tarvia.example"}]},
    }
    alert_b = {**alert_a, "alert_id": "B", "created_at": "2026-10-10T00:00:00Z"}
    pairs = [(alert_a, ticket("A")), (alert_b, ticket("B"))]
    assert len(correlate(pairs)["incidents"]) == 1
    monkeypatch.setattr(c, "LINK_WINDOW", c.timedelta(days=3))
    assert correlate(pairs)["incidents"] == []


def test_a_closed_alert_never_joins_by_account_alone():
    alert_a = {
        "alert_id": "A",
        "created_at": "2026-10-01T00:00:00Z",
        "entities": {"users": [{"upn": "zz-test@tarvia.example"}]},
    }
    alert_b = {**alert_a, "alert_id": "B"}
    assert (
        correlate([(alert_a, ticket("A")), (alert_b, ticket("B", verdict="false_positive", escalate=False))])[
            "incidents"
        ]
        == []
    )


@pytest.mark.parametrize(
    "first, second, close, expected",
    [
        ("escalated", "escalated", True, c.SPECIFIC | c.BROAD),
        ("escalated", "escalated", False, c.SPECIFIC),
        ("escalated", "noise", True, c.SPECIFIC),
        ("attack", "attack", True, c.SPECIFIC),
        ("attack", "attack", False, set()),
        ("attack", "noise", True, set()),
        ("noise", "noise", True, set()),
    ],
)
def test_which_links_each_pair_of_roles_allows(first, second, close, expected):
    assert allowed_kinds(first, second, close) == expected


def test_roles():
    assert role(ticket("A")) == "escalated"
    assert role(ticket("A", escalate=False)) == "attack"
    assert role(ticket("A", verdict="benign_true_positive", escalate=False)) == "noise"


def test_alerts_without_a_ticket_or_an_id_are_skipped():
    result = correlate(
        [(ALERTS[LAURA[0]], ticket(LAURA[0])), ({"rule_id": "x"}, ticket("Y")), (ALERTS[LAURA[1]], None)]
    )
    assert result["alerts"] == 1 and result["incidents"] == []


def test_new_alerts_not_in_the_history_still_count():
    new = [
        {
            "alert_id": f"NEW-{i}",
            "created_at": "2026-11-08T09:00:00Z",
            "entities": {"users": [{"upn": "zz-shared@tarvia.example"}]},
        }
        for i in range(30)
    ]
    counts = c.shared_by(new)
    assert counts[("account", "zz-shared@tarvia.example")] == 30


def test_command_line_writes_incidents_and_noise(tmp_path, capsys):
    folder = tmp_path / "run"
    folder.mkdir()
    for alert_id in LAURA:
        (folder / f"{alert_id}.json").write_text(json.dumps(ticket(alert_id)), encoding="utf-8")
    assert c.main([str(folder), "--out", str(tmp_path / "out")]) == 0
    written = sorted(path.name for path in (tmp_path / "out").iterdir())
    assert "noise.json" in written and any(name.startswith("INC-") for name in written)
    assert "5 alerts, 1 incidents" in capsys.readouterr().out
