import pytest

from src.tools import api_client
from src.tools.api_client import APIError, ContainmentRefused, NotFoundError

LAURA = "laura.ferrer2@tarvia.example"


def test_base_url_from_env(mock_api):
    assert api_client.base_url() == mock_api


def test_every_call_has_a_timeout():
    assert 0 < api_client.TIMEOUT_SECONDS <= 60


def test_list_and_get_alert():
    page = api_client.list_alerts(limit=2)
    assert page["total"] > 0 and len(page["items"]) == 2
    a = api_client.get_alert("ALR-20261007-011785")
    assert a["rule_id"] == "UC-EML-003"


def test_404_returns_none_for_lookups():
    assert api_client.get_alert("ALR-00000000-000000") is None
    assert api_client.get_asset("NO-SUCH-HOST") is None
    assert api_client.get_user("nobody@tarvia.example") is None
    assert api_client.get_sandbox("0" * 64) is None


def test_asset_by_hostname_and_ip():
    a = api_client.get_asset("WS-BCN-1380")
    assert a["hostname"] == "WS-BCN-1380"
    assert api_client.get_asset(a["ip"])["hostname"] == "WS-BCN-1380"
    assert "vulnerabilities" in a


def test_user_by_upn():
    u = api_client.get_user(LAURA)
    assert u["upn"] == LAURA and "hr_events" in u


def test_logs_pass_truncated_flag():
    r = api_client.get_logs("dns", limit=3)
    assert r["truncated"] is True and r["count"] == 3
    r = api_client.get_logs("dns", q="no-such-value-xyz", limit=3)
    assert r["truncated"] is False and r["items"] == []


def test_unknown_log_source_raises_not_found():
    with pytest.raises(NotFoundError):
        api_client.get_logs("no_such_source")


def test_intel():
    r = api_client.get_intel("203.0.113.45")
    assert r["indicator"] == "203.0.113.45" and r["geo"] is not None
    assert api_client.get_intel("unknown.example")["tip"] is None


def test_intel_on_url_is_none_because_mock_cannot_route_slashes():
    assert api_client.get_intel("https://tarvia-sso-login.example/auth/v2/sso") is None


def test_changes():
    assert any(c["id"] == "CHG-2026-1042" for c in api_client.get_changes("pentest"))


# --- containment: runs against the copy in a temp folder (see conftest) ---

def test_server_refuses_without_approval():
    # Straight to the server, bypassing our checks: the mock itself still says 403.
    with pytest.raises(APIError) as e:
        api_client._request("POST", "/containment/isolate_host",
                            json={"target": "WS-BCN-1380", "justification": "test"})
    assert e.value.status == 403


def test_containment_with_approval_and_log(mock_dir):
    ap = api_client.request_approval("isolate_host", "WS-BCN-1380", "n2.test", "test")
    assert ap["approval_token"].startswith("APR-")
    rec = api_client.run_containment("isolate_host", "WS-BCN-1380", "test",
                                     approval_token=ap["approval_token"], ticket_id="TKT-TEST")
    assert rec["result"].startswith("ok")
    assert any(r.get("ticket_id") == "TKT-TEST" for r in api_client.get_containment_log())
    assert (mock_dir / "06_herramientas" / "containment_log.jsonl").exists()


def test_every_action_needs_an_approval():
    for action, target in [("isolate_host", "WS-BCN-1380"), ("block_ioc", "bad.example"),
                           ("purge_email", "<x@bad.example>")]:
        with pytest.raises(ContainmentRefused):
            api_client.run_containment(action, target, "test")
    ap = api_client.request_approval("block_ioc", "bad.example", "n1.test")
    assert api_client.run_containment("block_ioc", "bad.example", "test",
                                      approval_token=ap["approval_token"])["action"] == "block_ioc"


def test_approval_is_single_use():
    ap = api_client.request_approval("disable_user", "test.user@tarvia.example", "n2.test")
    api_client.run_containment("disable_user", "test.user@tarvia.example", "t", approval_token=ap["approval_token"])
    with pytest.raises(ContainmentRefused):
        api_client.run_containment("disable_user", "test.user@tarvia.example", "t", approval_token=ap["approval_token"])


def test_approval_bound_to_action_and_target():
    ap = api_client.request_approval("isolate_host", "WS-BCN-1380", "n2.test")
    with pytest.raises(ContainmentRefused):
        api_client.run_containment("isolate_host", "WS-BCN-1001", "t", approval_token=ap["approval_token"])
    with pytest.raises(ContainmentRefused):
        api_client.run_containment("disable_user", "WS-BCN-1380", "t", approval_token=ap["approval_token"])


def test_host_aliases_resolve_to_one_target():
    ip = api_client.get_asset("WS-BCN-1380")["ip"]
    ap = api_client.request_approval("isolate_host", ip, "n2.test")
    assert ap["target"] == "WS-BCN-1380"
    rec = api_client.run_containment("isolate_host", "ws-bcn-1380", "t", approval_token=ap["approval_token"])
    assert rec["target"] == "WS-BCN-1380"


@pytest.mark.parametrize("alias", ["PLC-SORT01", "plc-sort01", "ip"])
def test_ot_refused_under_any_alias(alias):
    plc = api_client.get_asset("PLC-SORT01")
    assert plc and plc["zone"] == "LOGISTICS-OT"
    target = plc["ip"] if alias == "ip" else alias
    with pytest.raises(ContainmentRefused):
        api_client.request_approval("isolate_host", target, "n2.test")
    with pytest.raises(ContainmentRefused):
        api_client.run_containment("block_ioc", target, "t", approval_token="APR-whatever")


def test_unsupported_action_is_400():
    ap = api_client.request_approval("format_disk", "x", "n2.test")
    with pytest.raises(APIError) as e:
        api_client.run_containment("format_disk", "x", "test", approval_token=ap["approval_token"])
    assert e.value.status == 400
