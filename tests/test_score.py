"""score() with made-up tickets and labels only."""
import json

from eval import score as sc


def T(tid, alert_ids, verdict, severity, escalate):
    return {"ticket_id": tid, "alert_ids": alert_ids, "verdict": verdict, "severity": severity,
            "escalation": {"escalate": escalate, "to": "", "reason": ""}}


def L(aid, verdict, severity, escalate):
    return {"alert_id": aid, "verdict": verdict, "severity": severity, "escalate": escalate,
            "labelled_by": "test", "notes": ""}


TICKETS = [
    T("T1", ["A1", "A2"], "true_positive", "high", True),       # grouped ticket
    T("T2", ["A3"], "false_positive", "low", False),
    T("T3", ["A4"], "true_positive", "medium", False),          # attack not escalated
]
LABELS = [
    L("A1", "true_positive", "high", "true"),
    L("A2", "true_positive", "critical", "true"),               # severity off by one
    L("A3", "true_positive", "high", "true"),                   # attack closed
    L("A4", "true_positive", "medium", "true"),
    L("A5", "false_positive", "low", "false"),                  # no ticket
    L("A6", "true_positive", "", ""),                           # no ticket, partial label
]


def test_metrics():
    r = sc.score(TICKETS, LABELS)
    m = r["metrics"]
    assert (m["verdict"]["correct"], m["verdict"]["total"]) == (3, 4)
    assert (m["severity_exact"]["correct"], m["severity_exact"]["total"]) == (2, 4)
    assert (m["severity_within_one"]["correct"], m["severity_within_one"]["total"]) == (3, 4)
    assert (m["escalation"]["correct"], m["escalation"]["total"]) == (2, 4)
    assert r["no_ticket"] == ["A5", "A6"]


def test_missed_attacks():
    missed = {x["alert_id"]: x["reason"] for x in sc.score(TICKETS, LABELS)["missed_attacks"]}
    assert set(missed) == {"A3", "A4", "A6"}
    assert "verdict false_positive" in missed["A3"] and "not escalated" in missed["A3"]
    assert missed["A4"] == "not escalated"
    assert missed["A6"] == "no ticket"


def test_blank_label_fields_are_skipped():
    r = sc.score([T("T", ["X"], "true_positive", "low", True)], [L("X", "", "", "")])
    assert all(v["total"] == 0 and v["rate"] is None for v in r["metrics"].values())


def test_alert_in_several_tickets_reported():
    r = sc.score([T("T1", ["A"], "true_positive", "low", True), T("T2", ["A"], "false_positive", "low", False)],
                 [L("A", "true_positive", "low", "true")])
    assert r["alerts_in_several_tickets"] == ["A"]
    assert r["metrics"]["verdict"]["correct"] == 1   # first ticket counts


def test_flat_escalate_field():
    r = sc.score([{"alert_ids": ["A"], "verdict": "true_positive", "severity": "high", "escalate": False}],
                 [L("A", "true_positive", "high", "true")])
    assert r["missed_attacks"][0]["reason"] == "not escalated"


def test_load_tickets_formats(tmp_path):
    t = T("T1", ["A"], "true_positive", "low", True)
    for content in ([t], t, {"tickets": [t]}):
        p = tmp_path / "run.json"
        p.write_text(json.dumps(content))
        assert sc.load_tickets(p) == [t]


def test_load_test_set_excludes_heldout_and_adds_extras(tmp_path, monkeypatch):
    base = sc.load_test_set()
    ids = [a["alert_id"] for a in base]
    for held in sc._read_ids(sc.HELDOUT_FILE):
        assert held not in ids
    # 150 sample alerts, minus the one held-out alert in the sample, plus 33 extras
    assert len(ids) == len(set(ids)) == 150 - 1 + 33

    extra = tmp_path / "extra.txt"
    extra.write_text("# comment\nALR-20261007-011786\n\n")
    held = tmp_path / "held.txt"
    held.write_text("ALR-20261016-011821\nALR-20261005-000301\n")
    monkeypatch.setattr(sc, "EXTRA_FILE", extra)
    monkeypatch.setattr(sc, "HELDOUT_FILE", held)
    ids2 = [a["alert_id"] for a in sc.load_test_set()]
    assert "ALR-20261007-011786" in ids2 and "ALR-20261005-000301" not in ids2


def test_repo_id_files():
    held = sc._read_ids(sc.HELDOUT_FILE)
    assert held == ["ALR-20261015-011819", "ALR-20261015-011820", "ALR-20261016-011821", "ALR-20261013-011901"]
    extra = sc._read_ids(sc.EXTRA_FILE)
    assert len(extra) == len(set(extra)) == 33 and not set(extra) & set(held)
