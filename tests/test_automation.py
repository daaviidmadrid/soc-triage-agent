"""Operational integration tests. Synthetic alerts, fake provider, temporary stores only."""
import copy
import json
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import httpx
import openai
import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("APP_DB_PATH", ":memory:")
from src.app.automation import Config, Priorities, auto_close_eligible
from src.app.main import create_app
from src.app.store import Store
from src.agent import llm

UI = {"X-Tarvia-UI": "1"}
FLAGS = ("confirmed_malicious_execution", "credential_theft", "persistence", "personal_data_exposure", "economic_fraud")
CHECKS = ("citations_valid", "authorisation_valid", "evidence_complete", "not_ot", "injection_review_clear", "deterministic_eligible")


def alert(key="SYNTHETIC-A", severity="low", rule="UC-WEB-001", linked=True):
    return {"alert_id": key, "severity": severity, "rule_id": rule, "created_at": "2026-01-02T10:00:00Z",
            "entities": {"ips": ["198.51.100.220"]} if linked else {}}


def ticket(a, escalate=False):
    return {"ticket_id": "TKT-" + a["alert_id"], "alert_ids": [a["alert_id"]], "title": "Comprobación sintética", "summary": "Evidencia sintética",
            "severity": a["severity"], "verdict": "true_positive", "confidence": 1,
            "escalation": {"escalate": escalate, "to": "N2" if escalate else "", "reason": "Política"},
            "recommended_actions": [], "evidence": [{"source": "waf", "event_id": "EV-SYNTHETIC", "finding": "Bloqueado"}],
            "analysis_origin": "deterministic", "policy_flags": dict.fromkeys(FLAGS, False), "safety_checks": dict.fromkeys(CHECKS, True),
            "closed_by_rule": {"rule_id": "R2", "conditions": ["Comprobaciones deterministas completas"], "event_ids": ["EV-SYNTHETIC"]}}


def fake_triage(a, mode=None):
    yield {"type": "started"}
    yield {"type": "tool_result", "tool": "rules", "args": {"rule": "R2", "llm_calls": 0}, "event_ids": ["EV-SYNTHETIC"]}
    yield {"type": "ticket_ready", "ticket": ticket(a, a["severity"] in ("high", "critical"))}


def report_runner(calls):
    def run(alerts, **kwargs):
        calls.append([a["alert_id"] for a in alerts])
        yield {"type": "report_ready", "report": {"title": "Informe sintético", "timeline": [], "containment_plan": [{"action": "block_ioc", "status": "proposed"}]}}
    return run


def app_for(tmp_path, monkeypatch, **kwargs):
    monkeypatch.setenv("TRIAGE_MODE", "real")
    config = kwargs.pop("config", Config(pace_seconds=0))
    config.require_start = kwargs.pop("require_start", False)  # Legacy scheduler scenarios opt out of the UI start gate.
    return create_app(db_path=kwargs.pop("db_path", tmp_path / "app.sqlite"), sample_path="none", run_fn=kwargs.pop("run_fn", fake_triage),
                      report_fn=kwargs.pop("report_fn", report_runner([])), automation_config=config, **kwargs)


def eventually(fn, timeout=8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = fn()
        if value:
            return value
        time.sleep(.025)
    raise AssertionError("No se alcanzó el estado esperado")


def rows(c):
    return c.get("/api/queue").json()["alerts"]


def test_import_to_report_without_buttons_and_no_automatic_containment(tmp_path, monkeypatch):
    calls = []
    def forbidden(*args, **kwargs):
        pytest.fail("La automatización intentó aprobar o ejecutar contención")
    from src.tools import api_client
    monkeypatch.setattr(api_client, "request_approval", forbidden)
    monkeypatch.setattr(api_client, "run_containment", forbidden)
    app = app_for(tmp_path, monkeypatch, report_fn=report_runner(calls))
    with TestClient(app, headers=UI) as c:
        a = alert(severity="critical")
        assert c.post("/api/alerts/import", json=[a]).json()["imported"] == [a["alert_id"]]
        eventually(lambda: calls)
        eventually(lambda: c.get("/api/reports/TKT-SYNTHETIC-A").json().get("report"))
        assert rows(c)[0]["ticket"]["proposed"] == "escalate"
        assert rows(c)[0]["decision"] is None and rows(c)[0]["disposition"] is None
        assert c.get("/api/automation").json()["containment"] == {}
        app.state.automation.wake.set()
        time.sleep(.3)
        assert len(calls) == 1


def test_priority_duplicate_import_and_manual_worker_race(tmp_path, monkeypatch):
    seen, gate = [], threading.Event()
    def run(a, mode=None):
        seen.append(a["alert_id"])
        gate.wait(4)
        yield from fake_triage(a, mode)
    app = app_for(tmp_path, monkeypatch, run_fn=run, config=Config(auto_investigate=False, pace_seconds=0))
    with TestClient(app, headers=UI) as c:
        c.post("/api/automation/control", json={"action": "pause"})
        low, urgent = alert("LOW"), alert("URGENT", "critical")
        c.post("/api/alerts/import", json=[low, urgent])
        assert not seen
        assert not c.post("/api/alerts/import", json=[urgent]).json()["imported"]
        c.post("/api/automation/control", json={"action": "resume"})
        eventually(lambda: seen)
        assert seen == ["URGENT"]
        with ThreadPoolExecutor(8) as pool:
            starts = list(pool.map(lambda _: c.post("/api/triage/URGENT").json(), range(16)))
        assert len({s["run_id"] for s in starts}) == 1
        assert all(s["already_running"] for s in starts)
        c.post("/api/automation/control", json={"action": "pause"})
        gate.set()
        eventually(lambda: any(r["ticket"] for r in rows(c)))
        assert seen == ["URGENT"]  # Pause drains the active run without taking LOW.
        c.post("/api/automation/control", json={"action": "resume"})
        eventually(lambda: len(seen) == 2)
        assert seen == ["URGENT", "LOW"]


def test_atomic_claim_across_two_database_connections(tmp_path):
    stores = [Store(tmp_path / "claims.sqlite") for _ in range(2)]
    def claim(i):
        return stores[i % 2].claim_run(f"RUN-{i}", "SAME-SUBJECT", "real")
    with ThreadPoolExecutor(8) as pool:
        result = list(pool.map(claim, range(24)))
    assert sum(claimed for _, claimed in result) == 1
    assert len({run["run_id"] for run, _ in result}) == 1


def test_restart_recovers_only_deliberate_jobs_and_keeps_budget(tmp_path, monkeypatch):
    path = tmp_path / "restart.sqlite"
    store = Store(path)
    store.add_alerts([alert("ENROLLED"), alert("HISTORICAL")], "sample")
    store.enqueue("triage", "ENROLLED", "batch", 20, "human")
    store.claim_run("RUN-CRASH", "ENROLLED", "real", store.jobs()[0]["id"])
    store.set_operation("budget", {"epoch": "persisted", "started_at": "2026-01-01", "used": 7, "failures": 0, "blocked": None})
    with TestClient(app_for(tmp_path, monkeypatch, db_path=path), headers=UI) as c:
        eventually(lambda: next(r for r in rows(c) if r["alert_id"] == "ENROLLED")["ticket"])
        assert next(r for r in rows(c) if r["alert_id"] == "HISTORICAL")["run"] is None
        assert c.get("/api/automation").json()["budget"]["used"] == 7
        assert c.get("/api/automation").json()["budget"]["epoch"] == "persisted"


@pytest.mark.parametrize("raised", [False, True])
def test_quota_captured_in_trace_or_raised_halts_and_keeps_pending(tmp_path, monkeypatch, raised):
    calls = []
    def run(a, mode=None):
        calls.append(a["alert_id"])
        if raised:
            raise llm.LLMQuotaExhausted("Cuota sintética", attempts=1)
        yield {"type": "error", "tool": "llm", "args": {"kind": "quota", "attempts": 2}}
        t = ticket(a, True); t["verdict"] = "needs_more_info"
        yield {"type": "ticket_ready", "ticket": t}
    app = app_for(tmp_path, monkeypatch, run_fn=run)
    with TestClient(app, headers=UI) as c:
        c.post("/api/alerts/import", json=[alert("A"), alert("B")])
        eventually(lambda: c.get("/api/automation").json()["reason"])
        before = c.get("/api/automation").json()
        assert len(calls) == 1 and any(j["status"] == "pending" for j in before["jobs"])
        c.post("/api/automation/control", json={"action": "resume"})
        time.sleep(.3)
        assert len(calls) == 1
        assert c.post("/api/triage/B").status_code == 409


def provider_response():
    return SimpleNamespace(choices=[SimpleNamespace(finish_reason="stop", message=SimpleNamespace(content="{}"))], usage=None)


def test_shared_budget_counts_provider_retries_corrections_and_investigation(tmp_path, monkeypatch):
    monkeypatch.setenv("LLM_MODEL", "fake"); monkeypatch.setenv("LLM_BACKUP_MODEL", "fake"); monkeypatch.setenv("LLM_STREAM", "false")
    attempts = []
    def create(**kwargs):
        attempts.append(True)
        if len(attempts) == 1:
            raise openai.APIConnectionError(request=httpx.Request("POST", "http://fake.invalid"))
        return provider_response()
    client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))
    def ask():
        return llm.complete("synthetic system", "synthetic input", client=client, sleep=lambda _: None)
    def run(a, mode=None):
        for _ in range(2):  # Original answer and one correction.
            result = ask()
            yield {"type": "tool_result", "tool": "llm", "args": {"model": "fake", "attempts": result.attempts}}
        yield {"type": "ticket_ready", "ticket": ticket(a, True)}
    def report(alerts, **kwargs):
        ask()
        yield {"type": "report_ready", "report": {"timeline": []}}
    app = app_for(tmp_path, monkeypatch, run_fn=run, report_fn=report, config=Config(max_calls=4, pace_seconds=0))
    with TestClient(app, headers=UI) as c:
        c.post("/api/alerts/import", json=[alert(severity="critical")])
        eventually(lambda: len(attempts) == 4)
        eventually(lambda: c.get("/api/automation").json()["reason"])
        assert c.get("/api/automation").json()["budget"]["used"] == 4
        c.post("/api/alerts/import", json=[alert("NEXT", linked=False)])
        time.sleep(.3)
        assert len(attempts) == 4
        assert next(r for r in rows(c) if r["alert_id"] == "NEXT")["run"] is None
        c.post("/api/automation/control", json={"action": "pause"})
        eventually(lambda: app.state.automation._active == 0)
        assert c.post("/api/automation/control", json={"action": "reset_budget"}).json()["budget"]["used"] == 0


def test_budget_interrupts_before_an_extra_provider_attempt(tmp_path, monkeypatch):
    app = app_for(tmp_path, monkeypatch, config=Config(max_calls=1, pace_seconds=0))
    controller = app.state.automation
    controller.before_attempt()
    with pytest.raises(llm.LLMQuotaExhausted):
        controller.before_attempt()
    assert controller.status()["budget"]["used"] == 1
    assert "Presupuesto" in controller.status()["reason"]


def test_current_report_is_reused_unless_repeat_is_deliberate(tmp_path, monkeypatch):
    calls = []
    app = app_for(tmp_path, monkeypatch, report_fn=report_runner(calls))
    with TestClient(app, headers=UI) as c:
        c.post("/api/alerts/import", json=[alert(severity="critical")])
        eventually(lambda: c.get("/api/reports/TKT-SYNTHETIC-A").json().get("report"))
        eventually(lambda: app.state.automation._active == 0)
        response = c.post("/api/reports/TKT-SYNTHETIC-A").json()
        assert response["already_done"] is True and len(calls) == 1
        assert c.post("/api/reports/TKT-SYNTHETIC-A?repeat=1").status_code == 202
        eventually(lambda: len(calls) == 2)


def test_consecutive_failures_stop_claiming_without_retry_loop(tmp_path, monkeypatch):
    seen = []
    def broken(a, mode=None):
        seen.append(a["alert_id"])
        raise RuntimeError("synthetic failure")
        yield
    app = app_for(tmp_path, monkeypatch, run_fn=broken, config=Config(max_failures=2, pace_seconds=0))
    with TestClient(app, headers=UI) as c:
        c.post("/api/alerts/import", json=[alert("A"), alert("B"), alert("C")])
        eventually(lambda: c.get("/api/automation").json()["reason"])
        assert len(seen) == 2 and any(j["status"] == "pending" for j in app.state.store.jobs())
        time.sleep(.3)
        assert len(seen) == 2


def test_report_revision_invalidation_and_deduplication(tmp_path, monkeypatch):
    calls = []
    app = app_for(tmp_path, monkeypatch, report_fn=report_runner(calls))
    with TestClient(app, headers=UI) as c:
        c.post("/api/alerts/import", json=[alert("FIRST", "high", "UC-IDP-004")])
        eventually(lambda: len(calls) == 1)
        key = "TKT-FIRST"
        eventually(lambda: c.get(f"/api/reports/{key}").json().get("report"))
        c.post("/api/automation/control", json={"action": "pause"})
        c.post("/api/alerts/import", json=[alert("SECOND", "high", "UC-IDP-005")])
        assert c.get(f"/api/reports/{key}").json()["state"]["stale"] is True
        c.post("/api/automation/control", json={"action": "resume"})
        eventually(lambda: any(len(group) == 2 for group in calls))
        grouped = c.get("/api/incidents").json()["incidents"]
        assert len(grouped) == 1 and grouped[0]["chain"] is True
        count = len(calls)
        time.sleep(.4)
        assert len(calls) == count


@pytest.mark.parametrize("section,key", [("policy_flags", f) for f in FLAGS] + [("safety_checks", c) for c in CHECKS])
@pytest.mark.parametrize("missing", [True, False])
def test_auto_close_requires_each_safety_check_and_unknown_is_not_false(section, key, missing):
    t = ticket(alert())
    assert auto_close_eligible(t, correlation_current=True, incident_escalates=False)
    if missing:
        t[section].pop(key)
    else:
        t[section][key] = True if section == "policy_flags" else False
    assert not auto_close_eligible(t, correlation_current=True, incident_escalates=False)


@pytest.mark.parametrize("change", [
    {"verdict": "needs_more_info"}, {"severity": "medium"}, {"analysis_origin": "model"}, {"closed_by_rule": None},
    {"evidence": []}, {"policy_flags": None}, {"safety_checks": None}, {"escalation": {"escalate": True}},
    {"injection_flags": [{"description": "Pendiente"}]},
])
def test_auto_close_rejects_model_only_incomplete_mandatory_escalation_and_injection(change):
    t = {**ticket(alert()), **change}
    assert not auto_close_eligible(t, correlation_current=True, incident_escalates=False)


def test_auto_close_needs_current_correlation():
    assert not auto_close_eligible(ticket(alert()), correlation_current=False, incident_escalates=False)
    assert not auto_close_eligible(ticket(alert()), correlation_current=True, incident_escalates=True)


@pytest.mark.parametrize("human", [False, True])
def test_new_chain_reopens_closed_cases_preserving_origin_and_history(tmp_path, monkeypatch, human):
    monkeypatch.setattr("src.app.main.secrets.randbelow", lambda n: 0)
    app = app_for(tmp_path, monkeypatch, config=Config(auto_close=True, pace_seconds=0, sample_rate=.05))
    with TestClient(app, headers=UI) as c:
        c.post("/api/alerts/import", json=[alert("CLOSED")])
        eventually(lambda: rows(c)[0]["disposition"])
        assert rows(c)[0]["disposition"]["origin"] == "automation"
        assert rows(c)[0]["disposition"]["sampled_for_review"] is True
        assert rows(c)[0]["decision"] is None
        if human:
            c.post("/api/tickets/TKT-CLOSED/decision", json={"analyst": "Ana", "decision": "close", "reason": "Revisado"})
        c.post("/api/alerts/import", json=[alert("NEW-CHAIN", "high", "UC-IDP-004")])
        eventually(lambda: next(r for r in rows(c) if r["alert_id"] == "CLOSED")["disposition"]["state"] == "review")
        d = c.get("/api/alerts/CLOSED").json()
        assert any(h["state"] == "closed" and h["origin"] == ("human" if human else "automation") for h in d["disposition_history"])
        if human:
            assert d["decisions"][0]["analyst"] == "Ana"
        assert c.post("/api/tickets/TKT-CLOSED/decision", json={"analyst": "Ana", "decision": "reopen", "reason": "Nueva comprobación"}).status_code == 201


def test_auto_close_off_by_default_and_manual_paths_with_automation_disabled(tmp_path, monkeypatch):
    app = app_for(tmp_path, monkeypatch, config=Config(auto_triage=False, auto_investigate=False, pace_seconds=0))
    with TestClient(app, headers=UI) as c:
        c.post("/api/alerts/import", json=[alert()])
        time.sleep(.15)
        assert rows(c)[0]["run"] is None
        c.post("/api/triage/SYNTHETIC-A")
        eventually(lambda: rows(c)[0]["ticket"])
        assert rows(c)[0]["ticket"]["closed_by_rule"] == "R2"
        assert rows(c)[0]["disposition"] is None


def test_historical_batch_requires_explicit_enqueue(tmp_path, monkeypatch):
    app = app_for(tmp_path, monkeypatch)
    app.state.store.add_alerts([alert("HISTORY")], "sample")
    with TestClient(app, headers=UI) as c:
        time.sleep(.15)
        assert rows(c)[0]["run"] is None
        assert c.post("/api/automation/enqueue", json={"alert_ids": ["HISTORY"]}).status_code == 202
        eventually(lambda: rows(c)[0]["ticket"])


def test_manual_triage_can_feed_automatic_investigation_independently(tmp_path, monkeypatch):
    calls = []
    app = app_for(tmp_path, monkeypatch, report_fn=report_runner(calls), config=Config(auto_triage=False, auto_investigate=True, pace_seconds=0))
    with TestClient(app, headers=UI) as c:
        c.post("/api/alerts/import", json=[alert(severity="critical")])
        assert rows(c)[0]["run"] is None
        c.post("/api/triage/SYNTHETIC-A")
        eventually(lambda: calls)
        assert calls == [["SYNTHETIC-A"]]


def test_priority_reuses_criticality_and_does_not_use_alert_number():
    p = Priorities()
    p.assets = [{"hostname": "CRITICAL-HOST", "criticality": "Crítica"}, {"hostname": "LOW-HOST", "criticality": "Baja"}]
    a = alert(rule="UC-OTHER"); a["entities"] = {"hosts": [{"hostname": "CRITICAL-HOST"}]}
    b = copy.deepcopy(a); b["entities"]["hosts"][0]["hostname"] = "LOW-HOST"
    assert p(a) > p(b)
    assert p({**a, "alert_id": "UNRELATED-ID"}) == p(a)
