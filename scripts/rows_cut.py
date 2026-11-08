#!/usr/bin/env python3
"""Counts alerts that lose log rows to fit the data or prompt budget, with no LLM. Start from the repo root.

    python3 scripts/rows_cut.py [--set scored] [--context-chars N] [--prompt-chars N]

For each alert: the context from the mock API (src/tools/context.py), then the first prompt
(src/agent/prompts.py). Rows can be lost three ways:
  - cut by the context's data budget (MAX_CONTEXT_CHARS),
  - cut from the prompt to fit MAX_PROMPT_CHARS,
  - cut by the mock API's search limit, which no budget changes.
Any of them leaves the source in truncated_sources, and then the policy's -1 can't apply
(docs/decisions.md, Incomplete evidence). --context-chars and --prompt-chars try other budgets
without changing the code. Needs the mock API (MOCK_API_URL, default http://localhost:8000).
"""
import argparse
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.agent import prompts  # noqa: E402
from src.tools import context as context_module  # noqa: E402
from src.tools.alert_fields import normalise_alert  # noqa: E402

_spec = importlib.util.spec_from_file_location("exam_for_rows_cut", ROOT / "scripts" / "exam.py")
exam = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(exam)

_trim = context_module._trim


def outcome(raw):
    """(cut by the context budget, cut from the prompt, any source truncated) for one alert."""
    dropped = {}

    def trim_and_record(*args):
        kept, cut = _trim(*args)
        dropped.update(cut)
        return kept, cut

    alert, _ = normalise_alert(raw)
    # build_context calls the module's _trim, so swapping it here shows what the budget cut. Nothing else changes.
    context_module._trim = trim_and_record
    try:
        context = context_module.build_context(alert)
    finally:
        context_module._trim = _trim
    _, _, omitted = prompts.build_prompt_with_info(context)
    by_budget = bool(dropped)
    in_prompt = bool(omitted.get("logs") or omitted.get("extra_logs"))
    return by_budget, in_prompt, bool(context.truncated_sources)


def main(arguments=None):
    parser = argparse.ArgumentParser(description="Count alerts that lose log rows to fit the budgets.")
    parser.add_argument("--set", default="scored", help="a set of scripts/exam.py, such as scored, exam or normal")
    parser.add_argument("--context-chars", type=int, help="try this MAX_CONTEXT_CHARS instead of the code's")
    parser.add_argument("--prompt-chars", type=int, help="try this MAX_PROMPT_CHARS instead of the code's")
    args = parser.parse_args(arguments)
    if args.context_chars:
        context_module.MAX_CONTEXT_CHARS = args.context_chars
    if args.prompt_chars:
        prompts.MAX_PROMPT_CHARS = args.prompt_chars

    from src.agent.batch import load_alerts

    ids = exam.choose_ids(args.set)
    alerts = load_alerts(ids)
    # One at a time, because _trim is swapped while each context is built.
    results = [outcome(alerts[alert_id]) for alert_id in ids if alert_id in alerts]
    total = len(results)
    budget = sum(by_budget for by_budget, _, _ in results)
    prompt = sum(in_prompt for _, in_prompt, _ in results)
    either = sum(by_budget or in_prompt for by_budget, in_prompt, _ in results)
    truncated = sum(any_truncated for _, _, any_truncated in results)
    print(f"Set '{args.set}': {total} alerts. MAX_CONTEXT_CHARS {context_module.MAX_CONTEXT_CHARS:,}, MAX_PROMPT_CHARS {prompts.MAX_PROMPT_CHARS:,}.")
    print(f"  Rows cut to fit a budget: {either} ({either / total:.0%}). By the context budget {budget}, from the prompt {prompt}.")
    print(f"  Any source truncated, including the API's search limit, so no -1: {truncated} ({truncated / total:.0%}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
