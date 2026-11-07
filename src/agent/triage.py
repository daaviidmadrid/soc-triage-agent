"""Turns one alert into a ticket. The final event carries the ticket. Branch: agent/triage"""
from typing import Iterator

from contracts.models import TraceEvent


def triage(alert: dict) -> Iterator[TraceEvent]:
    raise NotImplementedError
