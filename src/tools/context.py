"""Gathers everything known about an alert. Branch: data/context"""
from contracts.models import Context


def build_context(alert: dict) -> Context:
    raise NotImplementedError
