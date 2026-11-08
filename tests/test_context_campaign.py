from src.tools import context


def fake_search(store):
    def search(source, user=None, ip=None, host=None, value=None, desde=None, hasta=None):
        items = [r for r in store.get(source, []) if (ip and r.get("dst_ip") == ip) or (ip and r.get("src_ip") == ip)
                 or (value and value in (r.get("domain"), r.get("sender"), r.get("url")))]
        return {"source": source, "items": items, "truncated": False, "unsupported": []}
    return search


ALERT = {"rule_id": "UC-EML-001", "related_events": ["EML-1"]}
ENTITIES = [{"type": "domain", "value": "bad-supplier.test"}]


def base_rows():
    return {("email", "EML-1"): {"event_id": "EML-1", "sender": "billing@bad-supplier.test", "urls": ["https://pay.phish.test/login"],
                                 "body_excerpt": "x", "log_source": "email"}}


def test_campaign_rows_follow_the_phishing_site(monkeypatch):
    store = {
        "proxy": [{"event_id": "PRX-1", "domain": "pay.phish.test", "dst_ip": "203.0.113.5", "method": "POST"}],
        "idp_signins": [{"event_id": "SIGN-1", "src_ip": "203.0.113.5", "result": "success"}],
        "email": [{"event_id": "EML-2", "sender": "billing@bad-supplier.test", "recipients": ["b@t.test"], "body_excerpt": "long"}],
        "email_clicks": [{"event_id": "CLK-1", "url": "https://pay.phish.test/login"}],
    }
    monkeypatch.setattr(context, "search_logs", fake_search(store))
    rows = base_rows()
    context._campaign_rows(ALERT, ENTITIES, rows, None, None)
    assert {k for k in rows} >= {("proxy", "PRX-1"), ("idp_signins", "SIGN-1"), ("email", "EML-2"), ("email_clicks", "CLK-1")}
    assert all(rows[k]["campaign"] for k in rows if k != ("email", "EML-1"))
    assert "body_excerpt" not in rows[("email", "EML-2")]


def test_other_rules_and_busy_ips_are_left_alone(monkeypatch):
    store = {"proxy": [{"event_id": "PRX-1", "domain": "pay.phish.test", "dst_ip": "203.0.113.5"}],
             "idp_signins": [{"event_id": f"SIGN-{i}", "src_ip": "203.0.113.5"} for i in range(context.CAMPAIGN_MAX_ROWS + 1)]}
    monkeypatch.setattr(context, "search_logs", fake_search(store))
    rows = base_rows()
    context._campaign_rows({**ALERT, "rule_id": "UC-EDR-001"}, ENTITIES, rows, None, None)
    assert list(rows) == [("email", "EML-1")]
    context._campaign_rows(ALERT, ENTITIES, rows, None, None)
    assert not any(k[0] == "idp_signins" for k in rows)
