"""Shared data formats. Fields get added once the team agrees them."""
from typing import Optional

from pydantic import BaseModel


class Entity(BaseModel):
    type: str          # user, host, ip, domain, url, file, process, customer, cloud_identity, ...
    value: str
    known: bool        # True only if a lookup (directory, CMDB, TIP, GeoIP, sandbox) found it


class TruncatedSource(BaseModel):
    source: str
    # "api_limit": the API cut results off; "size_limit": we trimmed rows to fit;
    # "shared_ip": rows from an IP shared by many identities were counted, not sent
    reason: str
    rows_dropped: Optional[int] = None   # known for size_limit and shared_ip, unknown for api_limit


class Context(BaseModel):
    alert: dict                      # the alert as given, plus created_at_madrid
    entities: list[Entity] = []
    criticality: Optional[str] = None          # Baja, Media, Alta or Crítica
    criticality_source: Optional[str] = None   # e.g. "asset:WS-BCN-1380", "service:...", "default"
    users: list[dict] = []           # directory records with hr_events
    assets: list[dict] = []          # CMDB records with vulnerabilities
    changes: list[dict] = []         # changes/flows overlapping the window, plus inicio_utc and fin_utc
    intel: list[dict] = []           # {"indicator", "tip", "geo"}
    sandbox: list[dict] = []         # sandbox reports
    logs: list[dict] = []            # most important first; raw rows plus log_source, timestamp_madrid, related
    truncated_sources: list[TruncatedSource] = []


class Ticket(BaseModel):
    pass


class TraceEvent(BaseModel):
    pass


class IncidentReport(BaseModel):
    pass


class ActionProposal(BaseModel):
    pass
