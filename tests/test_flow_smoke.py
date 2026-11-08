"""Smoke test of the automated flow: upload, start, tickets and report, and a person still owns containment.
Uses fake runners, so it never loads credentials or calls a real provider."""
from fastapi.testclient import TestClient

from src.tools import api_client
from test_automation import UI, alert, app_for, eventually, fake_triage, report_runner, rows


def test_flow_finishes_without_touching_containment(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("The automated flow must never approve or run containment.")

    monkeypatch.setattr(api_client, "request_approval", forbidden)
    monkeypatch.setattr(api_client, "run_containment", forbidden)
    reports = []
    app = app_for(tmp_path, monkeypatch, require_start=True, run_fn=fake_triage, report_fn=report_runner(reports))
    with TestClient(app, headers=UI) as client:
        client.post("/api/alerts/import", json=[alert("URGENT", "critical"), alert("LOW")])
        assert client.post("/api/automation/start").status_code == 202
        eventually(lambda: all(row["run"] and row["run"]["status"] == "done" for row in rows(client)))
        eventually(lambda: reports)
        assert all(row["ticket"] for row in rows(client))
        assert client.get("/api/alerts/URGENT").json()["decisions"] == []
