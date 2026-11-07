"""Level 4: containment that only people approve and run. Uses the test copy of the mock API from conftest,
so every executed action lands in a temporary containment log, never in data/."""
import ast
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.app.main import create_app
from src.policy import containment as policy
from src.policy.containment import actions_in, propose
from src.tools import api_client

ROOT = Path(__file__).resolve().parents[1]
UI = {"X-Tarvia-UI": "1"}
ALERTS = {}
with open(ROOT / "data" / "03_alertas" / "alertas.jsonl", encoding="utf-8") as file:
    for line in file:
        alert = json.loads(line)
        ALERTS[alert["alert_id"]] = alert

LAURA = "ALR-20261007-011786"
JENKINS = "ALR-20261006-011825"


def suggestion(action, target):
    return {"action": action, "target": target, "requires_approval": True, "justification": "prueba"}


def ticket(alert_id, *actions, affected_users=()):
    return {
        "ticket_id": f"TKT-{alert_id}", "alert_ids": [alert_id], "title": "t", "verdict": "true_positive", "confidence": 0.9,
        "severity": "critical", "summary": "s", "evidence": [], "affected": {"users": list(affected_users)},
        "recommended_actions": [{"action": "escalate", "target": "N2", "requires_approval": False}, *actions],
        "escalation": {"escalate": True, "to": "N2", "reason": "r"},
    }


LAURA_TICKET = ticket(
    LAURA,
    suggestion("Revocar todas las sesiones activas de la cuenta y forzar cambio de contraseña", "laura.ferrer2@tarvia.example"),
    suggestion("Retirar la regla de buzón de encubrimiento creada (regla '.')", "Bandeja de entrada de laura.ferrer2@tarvia.example"),
    suggestion("Bloquear el IOC 203.0.113.45 en proxy y pasarela de correo", "203.0.113.45"),
)
JENKINS_TICKET = ticket(JENKINS, suggestion("Aislar el servidor JENKINS-DEV01 de la red", "host:JENKINS-DEV01"))
OT_TICKET = ticket(JENKINS, suggestion("Aislar el equipo de la red", "10.40.16.21"))


@pytest.fixture
def app_with(tmp_path):
    def make(alert_id, ticket_data):
        app = create_app(db_path=":memory:", sample_path=tmp_path / "none.jsonl")
        store = app.state.store
        store.add_alerts([ALERTS[alert_id]], "sample")
        run_id = f"RUN-{alert_id}"
        store.create_run(run_id, alert_id, "real")
        store.save_ticket(ticket_data, run_id, alert_id, "real")
        store.finish_run(run_id, "done", 1.0, ticket_data["ticket_id"], None)
        return TestClient(app, headers=UI)
    return make


def proposals(client, ticket_id):
    response = client.get(f"/api/tickets/{ticket_id}/containment")
    assert response.status_code == 200, response.text
    return response.json()


def find(data, action, target=None):
    return next(p for p in data["proposals"] if p["action"] == action and (target is None or p["target"] == target))


def log_size(client):
    return len(client.get("/api/containment/log").json()["entries"])


# The routes, against the mock API

def test_laura_demo_runs_revoke_sessions_and_reset_password_after_approval(app_with):
    with app_with(LAURA, LAURA_TICKET) as c:
        data = proposals(c, LAURA_TICKET["ticket_id"])
        before = log_size(c)
        for action in ("revoke_sessions", "reset_password"):
            proposal = find(data, action, "laura.ferrer2@tarvia.example")
            assert proposal["approvers"] == ["N2"] and proposal["status"] == "proposed"
            approved = c.post(f"/api/containment/{proposal['proposal_id']}/approve", json={"role": "N2", "approver": "Ana Ruiz"}).json()
            assert approved["status"] == "approved"
            done = c.post(f"/api/containment/{proposal['proposal_id']}/execute")
            assert done.status_code == 200, done.text
            assert done.json()["status"] == "executed" and done.json()["result"]["result"] == "ok (simulado)"
        entries = c.get("/api/containment/log").json()["entries"]
        assert len(entries) == before + 2
        assert {(e["action"], e["target"]) for e in entries[-2:]} == {("revoke_sessions", "laura.ferrer2@tarvia.example"), ("reset_password", "laura.ferrer2@tarvia.example")}
        assert all(e["ticket_id"] == LAURA_TICKET["ticket_id"] for e in entries[-2:])
        # The mailbox rule isn't one of the 7 actions, so it stays a suggestion for a person.
        assert any("regla de buzón" in item["suggestion"] for item in data["not_proposed"])


def test_running_without_approval_is_refused(app_with):
    with app_with(LAURA, LAURA_TICKET) as c:
        proposal = find(proposals(c, LAURA_TICKET["ticket_id"]), "revoke_sessions")
        before = log_size(c)
        response = c.post(f"/api/containment/{proposal['proposal_id']}/execute")
        assert response.status_code == 409 and "Faltan aprobaciones de: N2" in response.json()["detail"]
        assert log_size(c) == before


def test_block_ioc_also_needs_a_person(app_with):
    with app_with(LAURA, LAURA_TICKET) as c:
        proposal = find(proposals(c, LAURA_TICKET["ticket_id"]), "block_ioc", "203.0.113.45")
        assert proposal["approvers"] == ["Analista SOC"]
        assert c.post(f"/api/containment/{proposal['proposal_id']}/execute").status_code == 409


def test_an_approval_is_used_once(app_with):
    with app_with(LAURA, LAURA_TICKET) as c:
        proposal = find(proposals(c, LAURA_TICKET["ticket_id"]), "revoke_sessions")
        c.post(f"/api/containment/{proposal['proposal_id']}/approve", json={"role": "N2", "approver": "Ana Ruiz"})
        before = log_size(c)
        assert c.post(f"/api/containment/{proposal['proposal_id']}/execute").status_code == 200
        again = c.post(f"/api/containment/{proposal['proposal_id']}/execute")
        assert again.status_code == 409 and "una sola vez" in again.json()["detail"]
        assert c.post(f"/api/containment/{proposal['proposal_id']}/approve", json={"role": "N2", "approver": "Otra Persona"}).status_code == 400
        assert log_size(c) == before + 1
        # Asking again rebuilds the proposals but keeps the executed state, so nothing can be approved anew.
        assert find(proposals(c, LAURA_TICKET["ticket_id"]), "revoke_sessions")["status"] == "executed"


def test_an_ot_alias_is_never_proposed(app_with):
    with app_with(JENKINS, OT_TICKET) as c:
        data = proposals(c, OT_TICKET["ticket_id"])
        assert data["proposals"] == []
        assert any("PLC-SORT01 está en la red OT" in item["reason"] for item in data["not_proposed"])


def test_a_missing_second_approver_is_refused(app_with):
    with app_with(JENKINS, JENKINS_TICKET) as c:
        proposal = find(proposals(c, JENKINS_TICKET["ticket_id"]), "isolate_host", "JENKINS-DEV01")
        assert proposal["approvers"] == ["N2", "Responsable del servicio (Director de Tecnología)"]
        pid = proposal["proposal_id"]
        before = log_size(c)
        c.post(f"/api/containment/{pid}/approve", json={"role": "N2", "approver": "Ana Ruiz"})
        response = c.post(f"/api/containment/{pid}/execute")
        assert response.status_code == 409 and "Responsable del servicio" in response.json()["detail"]
        same_person = c.post(f"/api/containment/{pid}/approve", json={"role": "Responsable del servicio (Director de Tecnología)", "approver": "ana  RUIZ"})
        assert same_person.status_code == 400 and "persona distinta" in same_person.json()["detail"]
        assert c.post(f"/api/containment/{pid}/approve", json={"role": "CISO", "approver": "Luis"}).status_code == 400
        assert log_size(c) == before
        c.post(f"/api/containment/{pid}/approve", json={"role": "Responsable del servicio (Director de Tecnología)", "approver": "Jordi Pons"})
        done = c.post(f"/api/containment/{pid}/execute").json()
        assert done["status"] == "executed"
        assert c.get("/api/containment/log").json()["entries"][-1]["target"] == "JENKINS-DEV01"


def test_a_rejected_action_can_never_run(app_with):
    with app_with(LAURA, LAURA_TICKET) as c:
        proposal = find(proposals(c, LAURA_TICKET["ticket_id"]), "revoke_sessions")
        pid = proposal["proposal_id"]
        assert c.post(f"/api/containment/{pid}/reject", json={"approver": "Ana Ruiz", "reason": "No hace falta"}).json()["status"] == "rejected"
        assert c.post(f"/api/containment/{pid}/approve", json={"role": "N2", "approver": "Ana Ruiz"}).status_code == 400
        assert c.post(f"/api/containment/{pid}/execute").status_code == 409


def test_a_refusal_from_the_mock_is_recorded(app_with, monkeypatch):
    def refuse(*_args, **_kwargs):
        raise api_client.ContainmentRefused("no human approval")
    monkeypatch.setattr(api_client, "run_containment", refuse)
    with app_with(LAURA, LAURA_TICKET) as c:
        pid = find(proposals(c, LAURA_TICKET["ticket_id"]), "revoke_sessions")["proposal_id"]
        c.post(f"/api/containment/{pid}/approve", json={"role": "N2", "approver": "Ana Ruiz"})
        assert c.post(f"/api/containment/{pid}/execute").status_code == 409
        assert find(proposals(c, LAURA_TICKET["ticket_id"]), "revoke_sessions")["status"] == "refused"


def test_containment_needs_the_ui_header_and_a_local_caller(app_with):
    with app_with(LAURA, LAURA_TICKET) as c:
        pid = find(proposals(c, LAURA_TICKET["ticket_id"]), "revoke_sessions")["proposal_id"]
        for path, body in ((f"/api/containment/{pid}/approve", {"role": "N2", "approver": "Ana"}), (f"/api/containment/{pid}/execute", None)):
            assert c.post(path, json=body, headers={"X-Tarvia-UI": ""}).status_code == 403
            assert c.post(path, json=body, headers={"Origin": "http://evil.example"}).status_code == 403


def test_unknown_ticket_and_proposal_are_404(app_with):
    with app_with(LAURA, LAURA_TICKET) as c:
        assert c.get("/api/tickets/TKT-NOPE/containment").status_code == 404
        assert c.post("/api/containment/ACT-NOPE/execute").status_code == 404


# No LLM code path reaches containment

def test_no_llm_code_path_reaches_containment():
    """The LLM's code only writes text. None of it imports the containment rules or calls the mock's approval or containment."""
    forbidden_calls = {"request_approval", "run_containment", "get_containment_log"}
    for path in sorted((ROOT / "src" / "agent").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names = [getattr(node, "module", None) or ""] + [alias.name for alias in node.names]
                assert not any("containment" in name or name in forbidden_calls for name in names), path.name
            if isinstance(node, ast.Attribute):
                assert node.attr not in forbidden_calls, path.name
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                assert "/api/containment" not in node.value and "/containment/" not in node.value, path.name


def test_only_the_execute_route_calls_the_mock():
    source = (ROOT / "src" / "app" / "main.py").read_text(encoding="utf-8")
    assert source.count("api_client.request_approval(") == 1 and source.count("api_client.run_containment(") == 1
    route = source.split('@app.post("/api/containment/{proposal_id}/execute")', 1)[1].split("@app.", 1)[0]
    assert "api_client.request_approval(" in route and "ready_to_run(proposal)" in route


# The rules, without the mock

ASSETS = {
    "WS-BCN-1380": {"hostname": "WS-BCN-1380", "type": "Portátil", "zone": "HQ-USERS", "business_service": "Puesto de trabajo"},
    "POS-T07-01": {"hostname": "POS-T07-01", "type": "TPV", "zone": "STORES", "business_service": "Cobro en tienda (PCI DSS)"},
    "WEB-ECOM01": {"hostname": "WEB-ECOM01", "type": "Frontal web", "zone": "DMZ", "business_service": "Tienda online y app (≈38% de la facturación)"},
    "DC01": {"hostname": "DC01", "type": "Controlador de dominio", "zone": "DC-SERVERS", "business_service": "Identidad y directorio activo"},
    "PLC-SORT01": {"hostname": "PLC-SORT01", "type": "PLC", "zone": "LOGISTICS-OT", "business_service": "Clasificación automática de pedidos"},
}
USERS = {
    "laura.ferrer2": {"upn": "laura.ferrer2@tarvia.example", "username": "laura.ferrer2", "account_type": "user"},
    "laura.ferrer": {"upn": "laura.ferrer@tarvia.example", "username": "laura.ferrer", "account_type": "user"},
    "svc_backup": {"upn": "svc_backup@tarvia.example", "username": "svc_backup", "account_type": "service"},
}


def lookup_asset(key):
    return ASSETS.get(str(key).upper())


def lookup_user(key):
    key = str(key).lower().split("@")[0]
    return USERS.get(key)


def built(*actions, alert=None, **ticket_fields):
    return propose({**ticket("ALR-X", *actions), **ticket_fields}, alert or {}, lookup_asset, lookup_user, run_id="R")


@pytest.mark.parametrize("host, approvers", [
    ("WS-BCN-1380", ["N2"]),
    ("POS-T07-01", ["N2", "Negocio (Directora de Operaciones)"]),
    ("WEB-ECOM01", ["N2", "Negocio (Directora de E-commerce)"]),
    ("DC01", ["N2", "Responsable del servicio (Director de Tecnología)"]),
])
def test_who_approves_an_isolation(host, approvers):
    proposals_, _ = built(suggestion("Aislar el equipo", host))
    assert proposals_[0].approvers == approvers and proposals_[0].business_impact


def test_tills_and_web_fronts_mention_sales():
    proposals_, _ = built(suggestion("Aislar", "POS-T07-01"))
    assert proposals_[0].business_impact.startswith("Impacto en ventas")


def test_ot_is_never_proposed_by_name_either():
    proposals_, refused = built(suggestion("Aislar", "PLC-SORT01"))
    assert proposals_ == [] and "red OT" in refused[0]["reason"]


@pytest.mark.parametrize("text, expected", [
    ("Revocar sesiones y forzar cambio de contraseña", ["revoke_sessions", "reset_password"]),
    ("Deshabilitar la cuenta hasta investigación", ["disable_user"]),
    ("Bloquear la cuenta de usuario", ["disable_user"]),
    ("Bloquear el IOC 203.0.113.45", ["block_ioc"]),
    ("Purgar el correo de todos los buzones", ["purge_email"]),
    ("Eliminar la regla de buzón '.'", []),
    ("Aislar el servidor", ["isolate_host"]),
    ("Desactivar las claves de acceso AWS", ["disable_access_key"]),
    ("Investigar el origen de la instalación", []),
    ("Revisar la contraseña del portal", []),
])
def test_which_action_a_suggestion_means(text, expected):
    assert actions_in(text) == expected


def test_display_names_never_pick_an_account():
    proposals_, refused = built(suggestion("Revocar sesiones de Laura Ferrer", "Laura Ferrer"))
    assert proposals_ == [] and "cuenta" in refused[0]["reason"]


def test_exact_accounts_win_and_look_alikes_stay_apart():
    proposals_, _ = built(suggestion("Revocar sesiones", "laura.ferrer2@tarvia.example"))
    assert [p.target for p in proposals_] == ["laura.ferrer2@tarvia.example"]


def test_the_only_affected_account_is_used_with_a_warning():
    proposals_, _ = built(suggestion("Forzar cambio de contraseña", "la cuenta afectada"), affected={"users": ["laura.ferrer2@tarvia.example"]})
    assert proposals_[0].target == "laura.ferrer2@tarvia.example" and proposals_[0].warnings


def test_disabling_a_service_account_warns():
    proposals_, _ = built(suggestion("Deshabilitar la cuenta", "svc_backup"))
    assert any("cuenta de servicio" in w for w in proposals_[0].warnings)


def test_internal_shared_and_own_indicators_are_never_blocked():
    _, refused = built(suggestion("Bloquear las IPs 10.10.1.5 y 198.18.200.10", "-"))
    assert len(refused) == 2
    _, refused = built(suggestion("Bloquear el dominio tarvia.example", "tarvia.example"), alert={"entities": {"domains": ["tarvia.example"]}})
    assert "dominio propio" in refused[0]["reason"]


def test_dual_use_services_need_n2_and_warn():
    proposals_, _ = built(suggestion("Bloquear el dominio mega.nz", "mega.nz"), alert={"entities": {"domains": ["mega.nz"]}})
    assert proposals_[0].approvers == ["N2"] and "uso dual" in proposals_[0].warnings[0]


def test_a_domain_must_come_from_the_alert_not_from_the_text_alone():
    _, refused = built(suggestion("Bloquear evil-made-up.example", "evil-made-up.example"))
    assert "indicador exacto" in refused[0]["reason"]


def test_purge_needs_the_message_id_from_the_alert():
    _, refused = built(suggestion("Purgar el correo", "-"))
    assert "identificador del mensaje" in refused[0]["reason"]
    proposals_, _ = built(suggestion("Purgar el correo", "-"), alert={"evidence": {"message_id": "<a@b.example>"}})
    assert proposals_[0].target == "<a@b.example>" and proposals_[0].approvers == ["Analista SOC"]


def test_decisions_and_suggestions_without_approval_are_not_containment():
    proposals_, refused = propose(ticket("ALR-X"), {}, lookup_asset, lookup_user)
    assert proposals_ == [] and refused == []


def test_the_same_action_twice_is_one_proposal_with_a_stable_id():
    first, _ = built(suggestion("Revocar sesiones", "laura.ferrer2@tarvia.example"), suggestion("Revocar sesiones activas", "laura.ferrer2@tarvia.example"))
    again, _ = built(suggestion("Revocar sesiones", "laura.ferrer2@tarvia.example"))
    assert len(first) == 1 and first[0].proposal_id == again[0].proposal_id


def test_service_rows_resolve_by_listed_host_and_by_name():
    assert policy.service_of({"hostname": "WEB-ECOM03"})["responsable"] == "Directora de E-commerce"
    assert policy.service_of({"hostname": "POS-T12-04"})["servicio"] == "Cobro en tienda (PCI DSS)"
    assert policy.service_of({"hostname": "X", "business_service": "Integración continua"})["responsable"] == "Director de Tecnología"
