"""The one place that calls the LLM. Branch: agent/llm"""
import json
import logging
import os
import re
import time
from dataclasses import dataclass
from functools import lru_cache

import openai
from dotenv import load_dotenv
from openai import OpenAI

log = logging.getLogger(__name__)

TIMEOUT_SECONDS = 60
ATTEMPTS_PER_MODEL = 2
RETRY_WAIT_SECONDS = 5
# A per-minute limit tells us how long to wait, and that can be close to a minute.
MAX_RETRY_WAIT_SECONDS = 65
DEFAULT_EXHAUSTED_SECONDS = 3600
DEFAULT_BACKUP_MODEL = "gemini-3.5-flash-lite"

RETRYABLE_ERRORS = (openai.RateLimitError, openai.InternalServerError, openai.APIConnectionError)
BLOCK_WORDS = ("content_filter", "safety", "blocked", "prohibited")
RETRY_DELAY = re.compile(r'retryDelay"?\s*:\s*"?(\d+(?:\.\d+)?)s')

# Models that hit their daily limit, and when to try them again. Retrying before then wastes time.
_exhausted = {}


@dataclass
class LLMResult:
    text: str
    model: str
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    attempts: int = 1


class LLMError(Exception):
    """The call failed. The message never contains the key."""

    def __init__(self, message, attempts=1):
        super().__init__(message)
        self.attempts = attempts


class LLMBlocked(LLMError):
    """The provider refused to answer, for example a safety filter."""


class LLMUnavailable(LLMError):
    """Every model and retry failed: rate limit, overload or timeout."""


class LLMQuotaExhausted(LLMUnavailable):
    """Every model has reached its daily limit, so trying again today won't help."""


def _hide_key(text):
    key = os.environ.get("LLM_API_KEY")
    return text.replace(key, "[key hidden]") if key else text


@lru_cache(maxsize=4)
def _client_for(factory, key, base_url):
    # One client reuses its connection, so calls don't each pay for a new secure connection.
    return factory(api_key=key, base_url=base_url, timeout=TIMEOUT_SECONDS, max_retries=0)


def _make_client():
    load_dotenv()
    if not os.environ.get("LLM_API_KEY"):
        raise LLMError("LLM_API_KEY is not set")
    return _client_for(OpenAI, os.environ["LLM_API_KEY"], os.environ.get("LLM_BASE_URL"))


def _models():
    primary = os.environ.get("LLM_MODEL")
    if not primary:
        raise LLMError("LLM_MODEL is not set")
    backup = os.environ.get("LLM_BACKUP_MODEL", DEFAULT_BACKUP_MODEL)
    return [primary] if backup == primary else [primary, backup]


def _error_body(error):
    return json.dumps(getattr(error, "body", None), default=str)


def _retry_seconds(error):
    """How long the provider asks us to wait, from its header or the retryDelay in its error, or None."""
    response = getattr(error, "response", None)
    retry_after = response.headers.get("retry-after") if response is not None else None
    try:
        return float(retry_after)
    except (TypeError, ValueError):
        found = RETRY_DELAY.search(_error_body(error))
        return float(found.group(1)) if found else None


def _is_daily_limit(error):
    return isinstance(error, openai.RateLimitError) and "perday" in _error_body(error).lower()


def _wait_seconds(error):
    seconds = _retry_seconds(error)
    return RETRY_WAIT_SECONDS if seconds is None else min(seconds, MAX_RETRY_WAIT_SECONDS)


def _read_response(response, model, attempts):
    choices = response.choices or []
    if not choices:
        raise LLMBlocked(f"{model} returned no answer", attempts)
    finish_reason = str(choices[0].finish_reason)
    if any(word in finish_reason.lower() for word in BLOCK_WORDS):
        raise LLMBlocked(f"{model} blocked the call (finish_reason {finish_reason})", attempts)
    if finish_reason != "stop":
        raise LLMError(f"{model} stopped early (finish_reason {finish_reason})", attempts)
    text = choices[0].message.content
    if not text or not text.strip():
        raise LLMError(f"{model} returned an empty answer", attempts)
    usage = response.usage
    return LLMResult(
        text=text,
        model=model,
        prompt_tokens=usage.prompt_tokens if usage else None,
        completion_tokens=usage.completion_tokens if usage else None,
        attempts=attempts,
    )


def complete(system: str, user: str, client=None, sleep=time.sleep) -> LLMResult:
    """Asks for a JSON answer. Retries, then falls back to the backup model."""
    client = client or _make_client()
    attempts = 0
    last_failure = "no attempt made"
    models = _models()
    for model in models:
        if _exhausted.get(model, 0) > time.monotonic():
            continue
        for attempt in range(ATTEMPTS_PER_MODEL):
            attempts += 1
            try:
                response = client.chat.completions.create(
                    model=model,
                    response_format={"type": "json_object"},
                    messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
                )
            except RETRYABLE_ERRORS as error:
                last_failure = f"{model}: {type(error).__name__}"
                log.warning("LLM call failed, %s", last_failure)
                if _is_daily_limit(error):
                    _exhausted[model] = time.monotonic() + (_retry_seconds(error) or DEFAULT_EXHAUSTED_SECONDS)
                    break
                if attempt + 1 < ATTEMPTS_PER_MODEL:
                    sleep(_wait_seconds(error))
            except openai.OpenAIError as error:
                message = _hide_key(str(error))[:300]
                if any(word in message.lower() for word in BLOCK_WORDS):
                    raise LLMBlocked(f"{model} blocked the call: {message}", attempts) from None
                raise LLMError(f"{model}: {type(error).__name__}: {message}", attempts) from None
            except UnicodeError:
                raise LLMError("LLM_API_KEY contains a character that can't be sent. Check it in .env", attempts) from None
            else:
                return _read_response(response, model, attempts)
    waits = [_exhausted.get(model, 0) - time.monotonic() for model in models]
    if all(wait > 0 for wait in waits):
        raise LLMQuotaExhausted(f"Daily limit reached on {', '.join(models)}. It resets in about {min(waits) / 3600:.1f} h.", attempts)
    raise LLMUnavailable(f"All models failed. Last failure: {last_failure}", attempts)
