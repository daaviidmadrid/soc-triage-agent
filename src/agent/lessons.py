"""Optional reviewed lessons for the prompt, loaded from a JSON file named by AGENT_LESSONS_FILE.

Lessons are general triage rules a person (or a reviewing model) wrote after reading mistakes on the exam set.
They must never carry anything from the data: no alert, ticket or change IDs, IPs, hosts, accounts, domains or URLs.
That keeps answers from leaking into the prompt and keeps attacker-written text out of it. They also must never
tell the model to approve or run containment, which only a person does. The gate below enforces this in code.

File format: {"tag": "L1", "lessons": [{"rule": "...", "why": "..."}]}
"""
import json
import os
import re
from pathlib import Path

MAX_LESSONS = 4
MAX_LESSON_CHARS = 450
TAG = re.compile(r"[A-Za-z0-9]{1,12}")

FORBIDDEN = (
    (re.compile(r"\b(ALR|TKT|CHG|INC|EVT)-\w", re.I), "an ID from the data"),
    (re.compile(r"\b\d{1,3}(\.\d{1,3}){3}\b"), "an IP address"),
    (re.compile(r"\S+@\S+"), "an account or email address"),
    (re.compile(r"https?://|www\.", re.I), "a URL"),
    (re.compile(r"\b[\w-]+\.(example|com|net|org|io|es|cat|ru|cn|xyz|top|info)\b", re.I), "a domain"),
    (re.compile(r"\b[A-Z]{2,}-[A-Z0-9]{2,}-\d{2,}\b"), "a host name"),
    (re.compile(r"\b(approve|execute|perform|run|launch)\w*\b[^.]{0,40}\b(containment|isolat|block|disabl|quarantin)", re.I), "approving or running containment"),
    (re.compile(r"\b(labels?\.csv|answer key|eval/|held.?out)\b", re.I), "a reference to the answer key"),
    (re.compile(r"\b(ignore|disregard|override)\b[^.]{0,30}\b(instruction|policy|rule|prompt)", re.I), "an instruction to ignore the rules"),
)


class LessonError(ValueError):
    pass


def check(data):
    """Returns (tag, [(rule, why)]) or raises LessonError saying what is wrong."""
    if not isinstance(data, dict):
        raise LessonError("the file must hold a JSON object")
    tag = data.get("tag")
    if not isinstance(tag, str) or not TAG.fullmatch(tag):
        raise LessonError("tag must be 1-12 letters or digits")
    lessons = data.get("lessons")
    if not isinstance(lessons, list) or not 1 <= len(lessons) <= MAX_LESSONS:
        raise LessonError(f"lessons must be a list of 1 to {MAX_LESSONS}")
    out = []
    for n, lesson in enumerate(lessons, 1):
        if not isinstance(lesson, dict) or set(lesson) != {"rule", "why"}:
            raise LessonError(f"lesson {n} must have exactly 'rule' and 'why'")
        rule, why = lesson["rule"], lesson["why"]
        if not all(isinstance(x, str) and x.strip() for x in (rule, why)):
            raise LessonError(f"lesson {n} needs non-empty text")
        text = f"{rule} {why}"
        if len(text) > MAX_LESSON_CHARS:
            raise LessonError(f"lesson {n} is longer than {MAX_LESSON_CHARS} characters")
        for pattern, what in FORBIDDEN:
            if pattern.search(text):
                raise LessonError(f"lesson {n} contains {what}")
        out.append((rule.strip(), why.strip()))
    return tag, out


def load(path=None):
    """(tag, lessons) from AGENT_LESSONS_FILE, or (None, []) when it isn't set."""
    path = path or os.environ.get("AGENT_LESSONS_FILE", "").strip()
    if not path:
        return None, []
    return check(json.loads(Path(path).read_text(encoding="utf-8")))


def section(lessons):
    if not lessons:
        return ""
    lines = "\n".join(f"- {rule} (Why: {why})" for rule, why in lessons)
    return (
        "Lessons from reviewing earlier triage mistakes. They are general and never override the SOC policy, "
        "the company rules or the escalation thresholds:\n" + lines
    )
