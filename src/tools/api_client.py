"""One function per mock API endpoint. Branch: data/api-client"""


def list_alerts(status="new", limit=50, offset=0):
    raise NotImplementedError


def get_alert(alert_id):
    raise NotImplementedError


def get_asset(key):
    raise NotImplementedError


def get_user(key):
    raise NotImplementedError


def get_logs(source, q="", desde="", hasta="", limit=200):
    raise NotImplementedError


def get_intel(indicator):
    raise NotImplementedError


def get_sandbox(sha256):
    raise NotImplementedError


def get_changes(q=""):
    raise NotImplementedError


def request_approval(action, target, approver, reason=""):
    raise NotImplementedError


def run_containment(action, target, justification, approval_token="", ticket_id=""):
    raise NotImplementedError


def get_containment_log():
    raise NotImplementedError
