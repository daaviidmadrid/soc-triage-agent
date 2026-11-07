import sys
from pathlib import Path
from types import SimpleNamespace

import httpx2
import openai
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.agent import llm  # noqa: E402
from src.agent.llm import LLMBlocked, LLMError, LLMQuotaExhausted, LLMUnavailable, complete  # noqa: E402

REQUEST = httpx2.Request("POST", "https://llm.test/chat/completions")


def status_error(kind, status, message="failed", headers=None):
    return kind(message, response=httpx2.Response(status, request=REQUEST, headers=headers), body=None)


def rate_limited(**options):
    return status_error(openai.RateLimitError, 429, **options)


def overloaded():
    return status_error(openai.InternalServerError, 503)


def timed_out():
    return openai.APITimeoutError(request=REQUEST)


def reply(text='{"ok": true}', finish_reason="stop", usage=True):
    choice = SimpleNamespace(finish_reason=finish_reason, message=SimpleNamespace(content=text))
    tokens = SimpleNamespace(prompt_tokens=10, completion_tokens=5) if usage else None
    return SimpleNamespace(choices=[choice], usage=tokens)


class FakeClient:
    """Plays back a list of responses or errors, and records which model each call used."""

    def __init__(self, *script):
        self.script = list(script)
        self.models = []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **request):
        self.models.append(request["model"])
        self.last_request = request
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


@pytest.fixture(autouse=True)
def settings(monkeypatch):
    monkeypatch.setenv("LLM_MODEL", "main-model")
    monkeypatch.setenv("LLM_BACKUP_MODEL", "backup-model")
    monkeypatch.setenv("LLM_API_KEY", "secret-test-key")


def no_sleep(_seconds):
    pass


def test_returns_text_model_and_tokens():
    client = FakeClient(reply())
    result = complete("system", "user", client=client, sleep=no_sleep)
    assert (result.text, result.model, result.prompt_tokens, result.completion_tokens) == ('{"ok": true}', "main-model", 10, 5)
    assert result.attempts == 1
    assert client.last_request["messages"][0] == {"role": "system", "content": "system"}
    assert client.last_request["response_format"] == {"type": "json_object"}


def test_missing_token_counts_are_allowed():
    assert complete("s", "u", client=FakeClient(reply(usage=False)), sleep=no_sleep).prompt_tokens is None


@pytest.mark.parametrize("failure", [rate_limited, overloaded, timed_out])
def test_retries_the_same_model_first(failure):
    client = FakeClient(failure(), reply())
    result = complete("s", "u", client=client, sleep=no_sleep)
    assert client.models == ["main-model", "main-model"]
    assert result.model == "main-model"
    assert result.attempts == 2


def test_rate_limit_then_backup_model():
    client = FakeClient(rate_limited(), rate_limited(), reply())
    result = complete("s", "u", client=client, sleep=no_sleep)
    assert client.models == ["main-model", "main-model", "backup-model"]
    assert result.model == "backup-model"
    assert result.attempts == 3


def test_backup_defaults_when_not_set(monkeypatch):
    monkeypatch.delenv("LLM_BACKUP_MODEL")
    client = FakeClient(overloaded(), overloaded(), reply())
    assert complete("s", "u", client=client, sleep=no_sleep).model == llm.DEFAULT_BACKUP_MODEL == "gemini-3.5-flash-lite"


def test_gives_up_after_every_model_failed():
    client = FakeClient(*[timed_out() for _ in range(4)])
    with pytest.raises(LLMUnavailable) as caught:
        complete("s", "u", client=client, sleep=no_sleep)
    assert caught.value.attempts == 4
    assert client.models == ["main-model", "main-model", "backup-model", "backup-model"]


def test_does_not_call_the_same_model_twice_as_backup(monkeypatch):
    monkeypatch.setenv("LLM_BACKUP_MODEL", "main-model")
    client = FakeClient(timed_out(), timed_out())
    with pytest.raises(LLMUnavailable):
        complete("s", "u", client=client, sleep=no_sleep)
    assert len(client.models) == 2


def daily_limit(seconds="44107s"):
    body = [{"error": {"details": [{"violations": [{"quotaId": "GenerateRequestsPerDayPerProjectPerModel-FreeTier", "quotaValue": "20"}]},
                                   {"retryDelay": seconds}]}}]
    return openai.RateLimitError("quota", response=httpx2.Response(429, request=REQUEST), body=body)


def per_minute_limit(seconds="40s"):
    body = [{"error": {"details": [{"violations": [{"quotaId": "GenerateRequestsPerMinutePerProjectPerModel-FreeTier"}]}, {"retryDelay": seconds}]}}]
    return openai.RateLimitError("quota", response=httpx2.Response(429, request=REQUEST), body=body)


@pytest.fixture
def no_exhausted_models(monkeypatch):
    monkeypatch.setattr(llm, "_exhausted", {})


def test_daily_limit_skips_retries_and_goes_to_the_backup(no_exhausted_models):
    waits = []
    client = FakeClient(daily_limit(), reply())
    result = complete("s", "u", client=client, sleep=waits.append)
    assert client.models == ["main-model", "backup-model"] and result.model == "backup-model"
    assert waits == []


def test_a_model_at_its_daily_limit_isnt_called_again(no_exhausted_models):
    first = FakeClient(daily_limit(), reply())
    complete("s", "u", client=first, sleep=no_sleep)
    second = FakeClient(reply())
    assert complete("s", "u", client=second, sleep=no_sleep).model == "backup-model"
    assert second.models == ["backup-model"]


def test_every_model_at_its_daily_limit_says_so(monkeypatch, no_exhausted_models):
    monkeypatch.setenv("LLM_BACKUP_MODEL", "main-model")
    client = FakeClient(daily_limit("7200s"))
    with pytest.raises(LLMQuotaExhausted, match="2.0 h"):
        complete("s", "u", client=client, sleep=no_sleep)
    assert len(client.models) == 1
    with pytest.raises(LLMQuotaExhausted):
        complete("s", "u", client=FakeClient(), sleep=no_sleep)


def test_per_minute_limit_waits_as_long_as_asked_then_retries(no_exhausted_models):
    waits = []
    client = FakeClient(per_minute_limit("40s"), reply())
    assert complete("s", "u", client=client, sleep=waits.append).model == "main-model"
    assert waits == [40.0]


def test_a_daily_limit_is_tried_again_once_its_time_has_passed(monkeypatch, no_exhausted_models):
    llm._exhausted["main-model"] = llm.time.monotonic() - 1
    assert complete("s", "u", client=FakeClient(reply()), sleep=no_sleep).model == "main-model"


def test_the_client_is_reused_between_calls(monkeypatch):
    made = []
    monkeypatch.setattr(llm, "load_dotenv", lambda: None)
    monkeypatch.setattr(llm, "OpenAI", lambda **options: made.append(options) or FakeClient(reply(), reply()))
    complete("s", "u", sleep=no_sleep)
    complete("s", "u", sleep=no_sleep)
    assert len(made) == 1


def test_waits_between_retries_and_caps_retry_after():
    waits = []
    client = FakeClient(rate_limited(headers={"retry-after": "999"}), reply())
    complete("s", "u", client=client, sleep=waits.append)
    assert waits == [llm.MAX_RETRY_WAIT_SECONDS]
    waits.clear()
    client = FakeClient(overloaded(), reply())
    complete("s", "u", client=client, sleep=waits.append)
    assert waits == [llm.RETRY_WAIT_SECONDS]


@pytest.mark.parametrize("finish_reason", ["content_filter", "SAFETY", "prohibited_content"])
def test_blocked_finish_reason_raises_blocked_without_retry(finish_reason):
    client = FakeClient(reply(finish_reason=finish_reason))
    with pytest.raises(LLMBlocked):
        complete("s", "u", client=client, sleep=no_sleep)
    assert len(client.models) == 1


def test_no_choices_counts_as_blocked():
    with pytest.raises(LLMBlocked):
        complete("s", "u", client=FakeClient(SimpleNamespace(choices=[], usage=None)), sleep=no_sleep)


def test_provider_error_that_mentions_safety_counts_as_blocked():
    client = FakeClient(status_error(openai.BadRequestError, 400, message="Blocked by SAFETY settings"))
    with pytest.raises(LLMBlocked):
        complete("s", "u", client=client, sleep=no_sleep)


@pytest.mark.parametrize("finish_reason", ["length", "tool_calls", "None"])
def test_other_finish_reasons_are_a_problem(finish_reason):
    with pytest.raises(LLMError) as caught:
        complete("s", "u", client=FakeClient(reply(finish_reason=finish_reason)), sleep=no_sleep)
    assert not isinstance(caught.value, LLMBlocked)


@pytest.mark.parametrize("text", ["", "   ", None])
def test_empty_answer_is_a_problem(text):
    with pytest.raises(LLMError):
        complete("s", "u", client=FakeClient(reply(text=text)), sleep=no_sleep)


def test_auth_error_stops_at_once_and_never_shows_the_key():
    client = FakeClient(status_error(openai.AuthenticationError, 401, message="Bad key secret-test-key"))
    with pytest.raises(LLMError) as caught:
        complete("s", "u", client=client, sleep=no_sleep)
    assert len(client.models) == 1
    assert "secret-test-key" not in str(caught.value)
    assert caught.value.__cause__ is None


def test_retry_logs_never_show_the_key(caplog):
    with pytest.raises(LLMUnavailable):
        complete("s", "u", client=FakeClient(*[rate_limited(message="secret-test-key") for _ in range(4)]), sleep=no_sleep)
    assert "secret-test-key" not in caplog.text


def test_key_with_a_bad_character_gives_a_clear_error_without_showing_it():
    class BadKeyClient(FakeClient):
        def _create(self, **request):
            "x".encode("ascii")
            raise UnicodeEncodeError("ascii", "secret-test-key", 0, 1, "bad character")

    with pytest.raises(LLMError) as caught:
        complete("s", "u", client=BadKeyClient(), sleep=no_sleep)
    assert "LLM_API_KEY" in str(caught.value)
    assert "secret-test-key" not in str(caught.value)


def test_missing_settings_give_clear_errors(monkeypatch):
    monkeypatch.setattr(llm, "load_dotenv", lambda: None)
    monkeypatch.delenv("LLM_API_KEY")
    with pytest.raises(LLMError, match="LLM_API_KEY"):
        complete("s", "u")
    monkeypatch.delenv("LLM_MODEL")
    with pytest.raises(LLMError, match="LLM_MODEL"):
        complete("s", "u", client=FakeClient(), sleep=no_sleep)


def test_real_client_has_a_time_limit_and_no_hidden_retries(monkeypatch):
    seen = {}
    monkeypatch.setattr(llm, "load_dotenv", lambda: None)
    monkeypatch.setattr(llm, "OpenAI", lambda **options: seen.update(options) or FakeClient(reply()))
    complete("s", "u", sleep=no_sleep)
    assert seen["timeout"] == llm.TIMEOUT_SECONDS
    assert seen["max_retries"] == 0
