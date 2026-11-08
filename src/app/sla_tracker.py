"""Tells a real triage from a fallback ticket. Plain code only."""


def is_fallback(ticket, events):
    """A ticket code wrote because the triage couldn't finish. It isn't a triage.
    The same test as isFallback in ui/src/ticket/runState.js."""
    evidence = ticket.get("evidence") if isinstance(ticket, dict) else None
    return (ticket.get("verdict") == "needs_more_info" and not evidence
            and any(isinstance(event, dict) and event.get("type") == "error" for event in events))
