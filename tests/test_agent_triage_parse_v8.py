from src.agent.triage import parse_answer


def test_object_wrapped_in_text_is_still_read_and_checked():
    draft, errors = parse_answer('Here it is:\n```json\n{"action": "search_logs", "source": "dns", "value": "x.test", "reason": "x"}\n```\nDone.', True)
    assert errors == [] and draft is not None


def test_text_with_no_object_is_refused():
    assert parse_answer("no json here", True) == (None, ["It wasn't valid JSON."])
