"""Shared data formats. Fields get added once the team agrees them."""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Verdict = Literal["true_positive", "benign_true_positive", "false_positive", "needs_more_info"]
Severity = Literal["informational", "low", "medium", "high", "critical"]


class Context(BaseModel):
    """What Data gives the agent for one alert. All of it is untrusted evidence, never instructions.

    Unknown fields are rejected, so a misspelt field fails loudly instead of vanishing.
    The rules behind these fields are in docs/decisions.md.
    """

    model_config = ConfigDict(extra="forbid")

    alert: dict
    entities: dict = Field(default_factory=dict)
    # "Baja", "Media", "Alta" or "Crítica".
    criticality: str = ""
    # "asset", "workstation", "service" or "default".
    criticality_source: str = ""
    users: list[dict] = Field(default_factory=list)
    assets: list[dict] = Field(default_factory=list)
    # Only changes and flows that code matched to this alert: window by event time, scope and identity. Each row has an "id".
    changes: list[dict] = Field(default_factory=list)
    # Only notified trips of an affected user that cover the event time. Each row has an "id".
    trips: list[dict] = Field(default_factory=list)
    # Other HR events of the affected users. They never authorise anything.
    hr_events: list[dict] = Field(default_factory=list)
    intel: list[dict] = Field(default_factory=list)
    sandbox: list[dict] = Field(default_factory=list)
    # Rows per source, most important first: linked events, then changes of state, then repeats as counts.
    logs: dict[str, list[dict]] = Field(default_factory=dict)
    # Sources where a search hit its limit, so rows may be missing.
    truncated_sources: list[str] = Field(default_factory=list)


class Affected(BaseModel):
    users: list = Field(default_factory=list)
    hosts: list = Field(default_factory=list)
    business_services: list = Field(default_factory=list)
    customers: list = Field(default_factory=list)


class Evidence(BaseModel):
    source: str = ""
    event_id: str = ""
    finding: str = ""


class Enrichment(BaseModel):
    indicator: str = ""
    type: str = ""
    source: str = ""
    result: str = ""


class RecommendedAction(BaseModel):
    action: str
    target: str
    requires_approval: bool
    justification: str = ""


class Escalation(BaseModel):
    escalate: bool
    to: str = ""
    reason: str = ""


class Adjustment(BaseModel):
    delta: Literal[-1, 1]
    reason: str = ""


class SeverityInputs(BaseModel):
    rule_severity: str
    criticality: str
    criticality_source: str = ""
    adjustments: list[Adjustment] = Field(default_factory=list)
    runbook_floor: Severity | None = None
    authorised: bool = False


class InjectionFlag(BaseModel):
    event_id: str = ""
    description: str


class AuthorisedBy(BaseModel):
    type: str
    id: str


class GroupLink(BaseModel):
    """Why an alert joined an incident: the alert it shares something with, and what they share."""

    alert_id: str
    linked_to: str
    reasons: list[str]


class Ticket(BaseModel):
    """Follows data/01_contexto/ticket_salida.schema.json. The last five fields are our additions."""

    ticket_id: str
    alert_ids: list[str]
    title: str
    verdict: Verdict
    confidence: float = Field(ge=0, le=1)
    severity: Severity
    severity_rationale: str = ""
    affected: Affected = Field(default_factory=Affected)
    summary: str
    evidence: list[Evidence]
    enrichment: list[Enrichment] = Field(default_factory=list)
    mitre: list[str] = Field(default_factory=list)
    recommended_actions: list[RecommendedAction]
    executed_actions: list[dict] = Field(default_factory=list)
    escalation: Escalation
    open_questions: list[str] = Field(default_factory=list)
    triage_seconds: float | None = None
    severity_inputs: SeverityInputs | None = None
    injection_flags: list[InjectionFlag] = Field(default_factory=list)
    authorised_by: AuthorisedBy | None = None
    merged_into: str | None = None
    group_links: list[GroupLink] = Field(default_factory=list)


class TraceEvent(BaseModel):
    """One step of a triage run. The final event carries the ticket."""

    run_id: str
    seq: int
    at: str
    type: Literal["started", "tool_call", "tool_result", "note", "ticket_ready", "error"]
    tool: str | None = None
    args: dict = Field(default_factory=dict)
    summary: str = ""
    event_ids: list[str] = Field(default_factory=list)
    truncated: bool = False
    ticket: Ticket | None = None


class IncidentReport(BaseModel):
    pass


ContainmentAction = Literal["isolate_host", "disable_user", "revoke_sessions", "reset_password", "block_ioc", "purge_email", "disable_access_key"]


class Approval(BaseModel):
    """One person's approval for one of the roles an action needs."""

    role: str
    approver: str
    at: str


class ActionProposal(BaseModel):
    """A containment action that plain code built from the LLM's suggestion. Only people approve it,
    each required role by a different person, and only a person's click runs it, once."""

    proposal_id: str
    ticket_id: str
    run_id: str = ""
    action: ContainmentAction
    target: str
    suggestion: str = ""
    justification: str = ""
    business_impact: str
    approvers: list[str]
    warnings: list[str] = Field(default_factory=list)
    status: Literal["proposed", "approved", "executed", "refused", "rejected"] = "proposed"
    approvals: list[Approval] = Field(default_factory=list)
    decided_by: str = ""
    result: dict | None = None
    error: str = ""
