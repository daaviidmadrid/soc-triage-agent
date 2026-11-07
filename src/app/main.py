"""Backend for the UI. Branch: demo/backend"""
from fastapi import FastAPI, HTTPException

app = FastAPI(title="Tarvia triage")


def not_built():
    raise HTTPException(501, "not built yet")


@app.get("/api/queue")
def queue():
    not_built()


@app.post("/api/alerts/import")
def import_alerts():
    not_built()


@app.post("/api/triage/{alert_id}")
def run_triage(alert_id: str):
    not_built()


@app.get("/api/runs/{run_id}/events")
def run_events(run_id: str):
    not_built()


@app.get("/api/tickets/{ticket_id}")
def ticket(ticket_id: str):
    not_built()
