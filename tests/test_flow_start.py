"""Start gate and recovery. Tests never load credentials or call a real provider."""
import json
import os
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("APP_DB_PATH", ":memory:")
from src.app.automation import Config
from src.app.main import create_app
from src.app import runner
from src.agent.llm import LLMResult
from test_automation import UI, alert, app_for, eventually, fake_triage, report_runner, rows


def test_upload_waits_for_start_then_runs_in_queue_order(tmp_path, monkeypatch):
    seen, reports = [], []
    def run(a, mode=None):
        seen.append(a["alert_id"])
        yield from fake_triage(a, mode)
    app = app_for(tmp_path, monkeypatch, require_start=True, run_fn=run, report_fn=report_runner(reports))
    with TestClient(app, headers=UI) as c:
        c.post("/api/alerts/import", json=[alert("LOW"), alert("URGENT", "critical"), alert("MIDDLE", "medium")])
        time.sleep(.3)
        assert seen == [] and reports == []
        assert all(r["job"]["status"] == "staged" and r["run"] is None for r in rows(c))
        assert c.get("/api/alerts/URGENT").json()["job"]["status"] == "staged"
        expected = [r["alert_id"] for r in sorted(rows(c), key=lambda r: r["queue_position"])]
        assert c.post("/api/automation/start").status_code == 202
        eventually(lambda: len(seen) == 3)
        eventually(lambda: reports)
        assert seen == expected
        c.post("/api/alerts/import", json=[alert("NEXT")])
        time.sleep(.3)
        assert "NEXT" not in seen  # A subsequent upload also requires Start.
        c.post("/api/automation/start")
        eventually(lambda: "NEXT" in seen)


def test_start_checks_mock_before_claiming_and_keeps_budget(tmp_path, monkeypatch):
    app = app_for(tmp_path, monkeypatch, require_start=True, run_fn=runner.run_triage)
    def unavailable():
        raise ConnectionError("synthetic outage")
    monkeypatch.setattr("src.app.main.api_client.check_connection", unavailable)
    with TestClient(app, headers=UI) as c:
        c.post("/api/alerts/import", json=[alert()])
        before = c.get("/api/automation").json()["budget"]
        response = c.post("/api/automation/start")
        assert response.status_code == 503 and "API simulada" in response.json()["detail"]
        assert rows(c)[0]["run"] is None
        after = c.get("/api/automation").json()["budget"]
        assert (after["used"], after["failures"], after["epoch"]) == (before["used"], before["failures"], before["epoch"])


def test_start_retries_failure_stop_without_refunding_calls(tmp_path, monkeypatch):
    app = app_for(tmp_path, monkeypatch, require_start=True)
    store = app.state.store
    budget = store.operation("budget")
    store.set_operation("budget", {**budget, "used": 7, "failures": 3, "blocked": "Límite de fallos consecutivos alcanzado."})
    with TestClient(app, headers=UI) as c:
        c.post("/api/alerts/import", json=[alert()])
        assert c.post("/api/automation/start").status_code == 202
        eventually(lambda: rows(c)[0]["ticket"])
        after = c.get("/api/automation").json()["budget"]
        assert after["used"] == 7 and after["epoch"] == budget["epoch"]


def test_new_start_does_not_retry_historical_failures_already_resolved(tmp_path, monkeypatch):
    seen = []
    def run(a, mode=None):
        seen.append(a["alert_id"])
        if len(seen) == 1:
            raise RuntimeError("synthetic failure")
        yield from fake_triage(a, mode)
    app = app_for(tmp_path, monkeypatch, require_start=True, run_fn=run, config=Config(auto_investigate=False, pace_seconds=0))
    with TestClient(app, headers=UI) as c:
        c.post("/api/alerts/import", json=[alert("RESOLVED")])
        c.post("/api/automation/start")
        eventually(lambda: rows(c)[0]["job"]["status"] == "failed")
        c.post("/api/triage/RESOLVED")
        eventually(lambda: rows(c)[0]["job"]["status"] == "done")
        c.post("/api/alerts/import", json=[alert("NEW")])
        c.post("/api/automation/start")
        eventually(lambda: "NEW" in seen)
        assert seen.count("RESOLVED") == 2


@pytest.mark.parametrize("reason", ["Cuota del proveedor agotada.", "Presupuesto de llamadas consumido."])
def test_start_does_not_clear_quota_or_spent_budget(tmp_path, monkeypatch, reason):
    app = app_for(tmp_path, monkeypatch, require_start=True)
    store = app.state.store
    store.set_operation("budget", {**store.operation("budget"), "blocked": reason})
    with TestClient(app, headers=UI) as c:
        c.post("/api/alerts/import", json=[alert()])
        assert c.post("/api/automation/start").status_code == 409
        assert rows(c)[0]["run"] is None


def test_context_failure_does_not_start_investigation(tmp_path, monkeypatch):
    reports = []
    def failed(a, mode=None):
        yield {"type": "error", "tool": "build_context", "args": {"kind": "context"}, "summary": "El contexto falló (ConnectError)"}
        yield from fake_triage({**a, "severity": "high"}, mode)
    app = app_for(tmp_path, monkeypatch, require_start=True, run_fn=failed, report_fn=report_runner(reports))
    with TestClient(app, headers=UI) as c:
        c.post("/api/alerts/import", json=[alert()])
        c.post("/api/automation/start")
        eventually(lambda: rows(c)[0]["ticket"])
        time.sleep(.3)
        assert reports == []
        assert rows(c)[0]["report_state"]["status"] == "blocked"
        assert c.get("/api/automation").json()["last_error"]["tool"] == "build_context"


def install_fake_providers(monkeypatch):
    """Neutral providers for plumbing checks; no rule, prompt or verdict tuning on imported records."""
    from src.agent import triage as triage_module, investigate as investigation_module
    def triage_provider(system, user, **kwargs):
        return LLMResult(model="fake-integration", text=json.dumps({
            "title": "Prueba de integración con proveedor simulado", "verdict": "needs_more_info", "confidence": .4,
            "summary": "Salida simulada para verificar el flujo; requiere revisión humana.", "evidence": [], "escalate": True,
        }))
    def report_provider(system, user, **kwargs):
        data = json.loads(user.split("<untrusted_data>\n", 1)[1].split("\n</untrusted_data>", 1)[0])
        event_id = data["events"][0]["event_id"]
        return LLMResult(model="fake-integration", text=json.dumps({
            "title": "Informe de prueba con proveedor simulado", "patient_zero": "No determinado en esta prueba",
            "initial_access": "No determinado en esta prueba", "root_cause": "No determinada en esta prueba",
            "narrative": "Comprobación del circuito de investigación, sin evaluación de calidad del modelo.",
            "timeline": [{"event_id": event_id, "description": "Evento recuperado por el código; selección de prueba."}],
            "confidence": .4, "containment_plan": [],
        }))
    monkeypatch.setattr(triage_module, "complete", triage_provider)
    monkeypatch.setattr(investigation_module, "complete", report_provider)


def test_user_import_file_with_real_tools_and_fake_providers(tmp_path, monkeypatch):
    filename = os.environ.get("TARVIA_IMPORT_TEST_FILE")
    if not filename:
        pytest.skip("Optional integration: set TARVIA_IMPORT_TEST_FILE to the uploaded JSON/JSONL")
    install_fake_providers(monkeypatch)
    monkeypatch.setenv("TRIAGE_MODE", "real")
    monkeypatch.setenv("APP_CALL_LOG_DIR", str(tmp_path / "calls"))
    from src.tools import api_client
    def forbidden(*args, **kwargs):
        pytest.fail("The flow attempted containment/approval")
    monkeypatch.setattr(api_client, "request_approval", forbidden)
    monkeypatch.setattr(api_client, "run_containment", forbidden)
    app = create_app(db_path=tmp_path / "upload.sqlite", sample_path="none", automation_config=Config(pace_seconds=0))
    with TestClient(app, headers=UI) as c:
        imported = c.post("/api/alerts/import", content=Path(filename).read_bytes()).json()
        assert imported["imported"] and not imported["errors"]
        count = len(imported["imported"])
        assert all(r["run"] is None for r in rows(c))
        expected = [r["alert_id"] for r in sorted(rows(c), key=lambda r: r["queue_position"])]
        assert c.post("/api/automation/start").status_code == 202
        eventually(lambda: len([r for r in rows(c) if r["ticket"] and r["run"]["status"] == "done"]) == count, timeout=240)
        eventually(lambda: not any(j["status"] in ("pending", "running") for j in app.state.store.jobs()), timeout=240)
        with app.state.store._lock:
            executed = [r[0] for r in app.state.store._db.execute("SELECT alert_id FROM runs WHERE mode='real' ORDER BY rowid")]
        assert executed == expected
        assert app.state.store.latest_correlation() is not None
        reports = app.state.store.latest_reports()
        assert reports and not any(r["fallback"] for r in reports.values())
        report_jobs = [j for j in app.state.store.jobs() if j["kind"] == "report" and j["status"] == "done"]
        assert len(report_jobs) == len(reports)  # One investigation per final case, not per intermediate triage update.
        assert c.get("/api/automation").json()["reason"] is None
        assert all(not any(e["type"] == "error" for e in app.state.store.events_after(r["run"]["run_id"])) for r in rows(c))
