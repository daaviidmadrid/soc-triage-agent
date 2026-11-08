"""One function per mock API endpoint.

Lookups that can miss (alert, asset, user, sandbox) return None on 404.
Any other HTTP error raises APIError with the status and the API's message.
"""
import os
from urllib.parse import quote

import httpx

DEFAULT_URL = "http://localhost:8000"
# Log searches scan a whole file on the server (up to ~1 s each), so allow some room.
TIMEOUT_SECONDS = 30.0


class APIError(Exception):
    def __init__(self, status, detail, path):
        super().__init__(f"{status} on {path}: {detail}")
        self.status = status
        self.detail = detail
        self.path = path


class NotFoundError(APIError):
    pass


def base_url():
    # Read on every call so tests and the app can point it elsewhere.
    return os.environ.get("MOCK_API_URL", DEFAULT_URL).rstrip("/")


def _seg(value):
    """Encode one path segment. Note: the mock server decodes %2F before routing,
    so a value containing '/' (a URL) can never match and comes back as 404."""
    return quote(str(value), safe="")


def _request(method, path, **kwargs):
    r = httpx.request(method, base_url() + path, timeout=TIMEOUT_SECONDS, **kwargs)
    if r.status_code >= 400:
        try:
            detail = r.json().get("detail", r.text)
        except ValueError:
            detail = r.text
        cls = NotFoundError if r.status_code == 404 else APIError
        raise cls(r.status_code, detail, path)
    return r.json()


def _get_or_none(path, **kwargs):
    try:
        return _request("GET", path, **kwargs)
    except NotFoundError:
        return None


def list_alerts(status="new", limit=50, offset=0):
    return _request("GET", "/alerts", params={"status": status, "limit": limit, "offset": offset})


def get_alert(alert_id):
    return _get_or_none(f"/alerts/{_seg(alert_id)}")


def get_asset(key):
    """Hostname or IP. None if it is not in the CMDB."""
    return _get_or_none(f"/assets/{_seg(key)}")


def get_user(key):
    """UPN or username. None if it is not in the directory."""
    return _get_or_none(f"/users/{_seg(key)}")


def get_logs(source, q="", desde="", hasta="", limit=200):
    """Raw mock search: case-insensitive substring of the JSON row.
    Returns {"count", "truncated", "items"} as the API sends it.
    An unknown source raises NotFoundError."""
    params = {"q": q, "desde": desde, "hasta": hasta, "limit": limit}
    return _request("GET", f"/logs/{_seg(source)}", params=params)


def get_intel(indicator):
    """{"indicator", "tip", "geo"}; tip/geo are None when unknown. None on 404 (URLs, see _seg)."""
    return _get_or_none(f"/intel/{_seg(indicator)}")


def get_sandbox(sha256):
    """Sandbox report, or None if the file was never submitted."""
    return _get_or_none(f"/sandbox/{_seg(sha256)}")


def get_changes(q=""):
    return _request("GET", "/changes", params={"q": q})


# --- containment ----------------------------------------------------------------
# The mock enforces less than we need (analysis section 12): block_ioc and purge_email run
# without approval, an approval token can be replayed, and OT isolation is refused only for
# the exact hostname (an alias such as the IP or lower case gets 200). So this client:
# - requires an approval issued through request_approval() for every action;
# - accepts each approval once, for the same action and target;
# - uses the CMDB hostname as the target of isolate_host, so aliases can't slip past;
# - refuses any action on an OT asset (policy section 4: only escalate).
# Who may approve (N2, service owner, business) is checked by the app, not here.
OT_ZONES = {"LOGISTICS-OT"}
_issued = {}     # approval_token -> (action, target), approvals made in this process
_used = set()    # approval tokens already spent


class ContainmentRefused(Exception):
    pass


def _containment_target(action, target):
    asset = get_asset(target)
    if asset and asset.get("zone") in OT_ZONES:
        raise ContainmentRefused(f"{target} is an OT asset ({asset['hostname']}): escalate to Operations")
    if action == "isolate_host" and asset:
        return asset["hostname"]
    return target


def request_approval(action, target, approver, reason=""):
    """Only a person's click should call this. Returns the approval with its approval_token."""
    target = _containment_target(action, target)
    body = {"action": action, "target": target, "approver": approver, "reason": reason}
    ap = _request("POST", "/approvals", json=body)
    _issued[ap["approval_token"]] = (action, target)
    return ap


def run_containment(action, target, justification, approval_token="", ticket_id=""):
    """Runs one simulated action. Raises ContainmentRefused without a matching, unused
    approval from request_approval() or on an OT target; APIError for server refusals
    (403 without approval, 400 for an unsupported action)."""
    target = _containment_target(action, target)
    if _issued.get(approval_token) != (action, target):
        raise ContainmentRefused(f"no human approval for {action} on {target}")
    if approval_token in _used:
        raise ContainmentRefused("this approval was already used")
    body = {"target": target, "justification": justification,
            "approval_token": approval_token, "ticket_id": ticket_id}
    rec = _request("POST", f"/containment/{_seg(action)}", json=body)
    _used.add(approval_token)
    return rec


def get_containment_log():
    return _request("GET", "/containment/log")
