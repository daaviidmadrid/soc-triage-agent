"""Builds the prompt for one alert. Branch: agent/prompt"""
from contracts.models import Context


def build_prompt(context: Context) -> tuple[str, str]:
    raise NotImplementedError
