"""Shared data formats. Fields get added once the team agrees them."""
from pydantic import BaseModel


class Context(BaseModel):
    pass


class Ticket(BaseModel):
    pass


class TraceEvent(BaseModel):
    pass


class IncidentReport(BaseModel):
    pass


class ActionProposal(BaseModel):
    pass
