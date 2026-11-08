"""The one place that calls the LLM. Branch: agent/llm"""
import json
import logging
import os
import re
import time
from dataclasses import dataclass
from functools import lru_cache
from types import SimpleNamespace

import openai
from dotenv import load_dotenv
from openai import OpenAI

log = logging.getLogger(__name__)

# Some models reason before they answer, which can take minutes on a busy shared server.
TIMEOUT_SECONDS = float(os.environ.get("LLM_TIMEOUT_SECONDS", 300))
ATTEMPTS_PER_MODEL = 2
RETRY_WAIT_SECONDS = 5
# A per-minute limit tells us how long to wait, and that can be close to a minute.
MAX_RETRY_WAIT_SECONDS = 65
DEFAULT_EXHAUSTED_SECONDS = 3600
DEFAULT_BACKUP_MODEL = "gemini-3.5-flash-lite"


class StreamCut(Exception):
    """The connection broke in the middle of a streamed answer."""


RETRYABLE_ERRORS = (openai.RateLimitError, openai.InternalServerError, openai.APIConnectionError, StreamCut)
BLOCK_WORDS = ("content_filter", "safety", "blocked", "prohibited")
RETRY_DELAY = re.compile(r'retryDelay"?\s*:\s*"?(\d+(?:\.\d+)?)s')
THINKING = re.compile(r"<think>.*?</think>\s*", re.DOTALL)
THINKING_TEXT = re.compile(r"<think>(.*?)</think>", re.DOTALL)

# Models that hit their daily limit, and when to try them again. Retrying before then wastes time.
_exhausted = {}


@dataclass
class LLMResult:
    text: str
    model: str
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    attempts: int = 1
    # What the model wrote while reasoning, when the provider sends it. Kept only for the call log, never parsed.
    reasoning: str = ""


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
    message = choices[0].message
    content = message.content or ""
    text = THINKING.sub("", content)
    if not text.strip():
        raise LLMError(f"{model} returned an empty answer", attempts)
    usage = response.usage
    reasoning = "\n".join(part for part in (_reasoning_of(message), *THINKING_TEXT.findall(content)) if part)
    return LLMResult(
        text=text,
        model=model,
        prompt_tokens=usage.prompt_tokens if usage else None,
        completion_tokens=usage.completion_tokens if usage else None,
        attempts=attempts,
        reasoning=reasoning,
    )


def _reasoning_of(item):
    """Providers name the reasoning field differently: vLLM uses reasoning_content, others reasoning."""
    for name in ("reasoning_content", "reasoning"):
        value = getattr(item, name, None)
        if isinstance(value, str) and value:
            return value
    return ""


def _use_streaming():
    return os.environ.get("LLM_STREAM", "true").strip().lower() != "false"


def _thinking_on(thinking=None):
    """An explicit True or False from the caller wins. Otherwise LLM_ENABLE_THINKING=false turns reasoning off."""
    if thinking is not None:
        return bool(thinking)
    return os.environ.get("LLM_ENABLE_THINKING", "").strip().lower() != "false"


def _json_mode():
    """JSON mode is off by default since v8: with reasoning on, the UAB server's JSON mode often returned just {} after
    a complete reasoning, which cost a full retry (6-7 calls in 90). LLM_JSON_MODE=1 turns it back on."""
    if os.environ.get("LLM_JSON_MODE", "0").strip() == "1":
        return {"response_format": {"type": "json_object"}}
    return {}


def _extra_options(thinking=None):
    """Streaming is on by default because the UAB's server cuts a silent connection after 60 s, and a model
    reasons silently for minutes. LLM_STREAM=false turns it off. LLM_ENABLE_THINKING=false turns off reasoning
    on models that support it, such as the UAB's ornith; a caller can pass thinking=True to keep it on for one call."""
    options = {}
    if _use_streaming():
        options.update(stream=True, stream_options={"include_usage": True})
    if not _thinking_on(thinking):
        options["extra_body"] = {"chat_template_kwargs": {"enable_thinking": False}}
    return options


def _read_stream(stream, model, attempts):
    """Puts a streamed answer back together, then checks it like any other answer."""
    parts, thoughts, finish_reason, usage, choices = [], [], None, None, False
    try:
        for chunk in stream:
            usage = getattr(chunk, "usage", None) or usage
            if chunk.choices:
                choices = True
                delta = chunk.choices[0].delta
                parts.append(delta.content or "")
                thoughts.append(_reasoning_of(delta))
                finish_reason = chunk.choices[0].finish_reason or finish_reason
    except openai.OpenAIError:
        raise
    except Exception as error:
        raise StreamCut(type(error).__name__) from None
    answer = SimpleNamespace(finish_reason=finish_reason, message=SimpleNamespace(content="".join(parts), reasoning_content="".join(thoughts)))
    return _read_response(SimpleNamespace(choices=[answer] if choices else [], usage=usage), model, attempts)


def complete(system: str, user: str, client=None, sleep=time.sleep, thinking=None) -> LLMResult:
    """Asks for a JSON answer. Retries, then falls back to the backup model.

    thinking=None follows LLM_ENABLE_THINKING; True or False overrides it for this call only."""
    client = client or _make_client()
    attempts = 0
    last_failure = "no attempt made"
    models = _models()
    extra = _extra_options(thinking)
    for model in models:
        if _exhausted.get(model, 0) > time.monotonic():
            continue
        for attempt in range(ATTEMPTS_PER_MODEL):
            attempts += 1
            try:
                response = client.chat.completions.create(
                    model=model,
                    **_json_mode(),
                    messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
                    **extra,
                )
                return _read_stream(response, model, attempts) if extra.get("stream") else _read_response(response, model, attempts)
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
    waits = [_exhausted.get(model, 0) - time.monotonic() for model in models]
    if all(wait > 0 for wait in waits):
        raise LLMQuotaExhausted(f"Daily limit reached on {', '.join(models)}. It resets in about {min(waits) / 3600:.1f} h.", attempts)
    raise LLMUnavailable(f"All models failed. Last failure: {last_failure}", attempts)
