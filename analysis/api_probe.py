"""Exercise an unchanged temporary API copy in process; never write to data/.

Approval requests below are synthetic test fixtures explicitly exercising the mock,
not approval of a real response proposal. No socket or external service is used.
"""
import hashlib
import importlib.util
import shutil
import tempfile
from pathlib import Path

import pandas as pd
from fastapi.testclient import TestClient

from analysis.load import DATA


def probe_api():
    source = DATA / "06_herramientas" / "mock_soc_api.py"
    before = hashlib.sha256(source.read_bytes()).hexdigest()
    observations = []
    with tempfile.TemporaryDirectory(prefix="tarvia-api-") as directory:
        root = Path(directory)
        tools = root / "06_herramientas"
        tools.mkdir()
        copied = tools / source.name
        shutil.copy2(source, copied)
        assert copied.resolve().is_relative_to(root)
        assert hashlib.sha256(copied.read_bytes()).hexdigest() == before
        # Only read-only inputs are linked. The writable tools directory is local.
        for name in ["02_inventario", "03_alertas", "04_logs", "05_inteligencia"]:
            (root / name).symlink_to(DATA / name, target_is_directory=True)
        spec = importlib.util.spec_from_file_location("tarvia_api_analysis_copy", copied)
        api = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(api)
        assert Path(api.LOGFILE).resolve().is_relative_to(root)

        with TestClient(api.app) as client:
            def record(name, response, expected):
                assert response.status_code == expected, (name, response.status_code)
                observations.append([name, response.status_code])
                return response

            def token(action, target, approver="fixture: arbitrary identity"):
                response = client.post("/approvals", json={
                    "action": action, "target": target, "approver": approver,
                    "reason": "Isolated mock contract test; no operational approval",
                })
                assert response.status_code == 200
                return response.json()["approval_token"]

            def action(name, target, approval=""):
                return client.post("/containment/" + name, json={
                    "target": target, "approval_token": approval,
                    "justification": "Isolated mock contract test", "ticket_id": "TEST-ONLY",
                })

            record("isolate without token", action("isolate_host", "TEST-HOST"), 403)
            wrong = token("disable_user", "TEST-USER")
            record("token for wrong action/target", action("isolate_host", "TEST-HOST", wrong), 403)
            record("unsupported action", action("shutdown", "TEST-HOST"), 400)
            record("block_ioc without approval", action("block_ioc", "fixture.invalid"), 200)
            record("purge_email without approval", action("purge_email", "TEST-MESSAGE"), 200)
            record("unknown host accepted", action("isolate_host", "TEST-HOST", token("isolate_host", "TEST-HOST")), 200)
            server = next(a for a in api.ASSETS if a["hostname"] == "SQL-CRM01")
            approval = token("isolate_host", server["hostname"])
            record("critical server, arbitrary single approver", action("isolate_host", server["hostname"], approval), 200)
            record("same token replayed", action("isolate_host", server["hostname"], approval), 200)
            pos = next(a for a in api.ASSETS if a["type"] == "TPV")
            record("TPV, one approver", action("isolate_host", pos["hostname"], token("isolate_host", pos["hostname"])), 200)
            ot = next(a for a in api.ASSETS if a["zone"] == "LOGISTICS-OT")
            record("OT exact hostname", action("isolate_host", ot["hostname"], token("isolate_host", ot["hostname"])), 403)
            for label, target in [("OT lowercase alias", ot["hostname"].lower()), ("OT IP alias", ot["ip"])]:
                record(label, action("isolate_host", target, token("isolate_host", target)), 200)
            # No real IOC is used, and nothing is resolved or contacted.
            record("OT IP block without approval", action("block_ioc", ot["ip"]), 200)
            record("known dual-use service global block", action("block_ioc", "mega.nz"), 200)
            record("unknown user accepted", action("disable_user", "TEST-USER", token("disable_user", "TEST-USER")), 200)
            record("unknown log source", client.get("/logs/not-a-source"), 404)
            record("unknown asset", client.get("/assets/TEST-NONEXISTENT"), 404)
            record("unknown intel is HTTP 200", client.get("/intel/fixture.invalid"), 200)
            record("logs limit above 2000", client.get("/logs/idp_audit", params={"limit":2001}), 422)
            record("negative logs limit accepted", client.get("/logs/idp_audit", params={"limit":-1}), 200)
            q = "laura.ferrer"
            response = client.get("/logs/idp_signins", params={"q":q, "limit":2000}).json()
            exact_upn = next(u["upn"] for u in api.USERS if u["username"] == q)
            search = {
                "q_rows_returned": response["count"], "truncated":response["truncated"],
                "rows_for_other_upns":sum(r["user_upn"] != exact_upn for r in response["items"]),
            }
            record("exact-size result reports truncated", client.get("/logs/idp_audit", params={"limit":len(api.logs("idp_audit"))}), 200)
            truncation = client.get("/logs/idp_audit", params={"limit":len(api.logs("idp_audit"))}).json()["truncated"]
            # q searches JSON text, where a backslash is written twice.
            domain_user = next(e["user"] for e in api.logs("edr_events")
                               if "\\" in (e.get("user") or "") and not e["user"].startswith("NT "))
            literal_rows = client.get("/logs/edr_events", params={"q":domain_user, "limit":2000}).json()["count"]
            doubled_rows = client.get("/logs/edr_events", params={"q":domain_user.replace("\\", "\\\\"), "limit":2000}).json()["count"]
            journal = client.get("/containment/log").json()
            assert len(journal) == sum(status == 200 for _, status in observations[:15])
        # Source code and original data location remain untouched by this probe.
        assert hashlib.sha256(source.read_bytes()).hexdigest() == before
        return pd.DataFrame(observations, columns=["probe", "HTTP_status"]), {
            "API_copy_identical_to_source":True,
            "writes_confined_to_temporary_copy":True,
            "synthetic_containment_log_rows":len(journal),
            "exact_size_result_truncated_flag":truncation,
            "domain_user_q_rows_typed_normally":literal_rows,
            "domain_user_q_rows_backslash_doubled":doubled_rows,
            **search,
        }
