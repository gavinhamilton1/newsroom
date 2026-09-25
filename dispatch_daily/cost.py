"""Anthropic client construction, retries and the per-run spend cap."""

from __future__ import annotations

import json
import logging
from collections import defaultdict
from dataclasses import dataclass, field

import anthropic
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential

from . import config

log = logging.getLogger(__name__)


class BudgetExceeded(RuntimeError):
    """Estimated Anthropic spend for this run went over the configured ceiling."""


@dataclass
class CostTracker:
    ceiling_usd: float
    tokens: dict[str, list[int]] = field(default_factory=lambda: defaultdict(lambda: [0, 0]))

    def record(self, model: str, usage) -> None:
        """Add a response's usage, then abort the run if the estimate exceeds the ceiling."""
        in_tok = (
            (usage.input_tokens or 0)
            + (getattr(usage, "cache_creation_input_tokens", 0) or 0)
            + (getattr(usage, "cache_read_input_tokens", 0) or 0)
        )
        self.tokens[model][0] += in_tok
        self.tokens[model][1] += usage.output_tokens or 0
        if self.total_usd > self.ceiling_usd:
            raise BudgetExceeded(
                f"estimated spend ${self.total_usd:.2f} exceeds ceiling ${self.ceiling_usd:.2f}"
            )

    def cost_for(self, model: str) -> float:
        in_price, out_price = config.MODEL_PRICES.get(model, (0.0, 0.0))
        in_tok, out_tok = self.tokens.get(model, [0, 0])
        return (in_tok * in_price + out_tok * out_price) / 1_000_000

    @property
    def total_usd(self) -> float:
        return sum(self.cost_for(m) for m in self.tokens)

    def summary(self) -> str:
        parts = [
            f"{m}: {t[0]:,} in / {t[1]:,} out = ${self.cost_for(m):.4f}"
            for m, t in self.tokens.items()
        ]
        return f"Anthropic spend ${self.total_usd:.4f} ({'; '.join(parts) or 'no calls'})"


def _retryable_api_error(exc: BaseException) -> bool:
    if isinstance(exc, anthropic.APITimeoutError | anthropic.APIConnectionError):
        return True
    if isinstance(exc, anthropic.APIStatusError):
        return exc.status_code == 429 or exc.status_code >= 500
    return False


# The SDK's own retries are turned off (max_retries=0) so this is the only retry policy.
api_retry = retry(
    retry=retry_if_exception(_retryable_api_error),
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=2, min=2, max=30),
    reraise=True,
)


def make_client(settings: config.Settings) -> anthropic.Anthropic:
    kwargs = {"max_retries": 0, "timeout": 300.0}
    if settings.anthropic_api_key:
        kwargs["api_key"] = settings.anthropic_api_key
    return anthropic.Anthropic(**kwargs)


class ModelOutputError(RuntimeError):
    """The model refused, ran out of tokens or returned unusable output."""


@api_retry
def _stream_final(client: anthropic.Anthropic, **kwargs) -> anthropic.types.Message:
    # Streaming keeps long Opus calls clear of HTTP timeouts; we only need the final message.
    with client.messages.stream(**kwargs) as stream:
        return stream.get_final_message()


def call_structured(
    client: anthropic.Anthropic,
    tracker: CostTracker,
    *,
    system: str,
    user: str,
    schema: dict,
    max_tokens: int,
) -> dict:
    """One writing-model call that must return JSON matching `schema`.

    Opus 5.5 rejects forced tool_choice and sampling parameters, so this uses structured
    outputs (output_config.format) and effort. Thinking is always on for that model.
    """
    kwargs: dict = {
        "model": config.WRITE_MODEL,
        "max_tokens": max_tokens,
        "system": system,
        "messages": [{"role": "user", "content": user}],
        "output_config": {
            "effort": config.WRITE_EFFORT,
            "format": {"type": "json_schema", "schema": schema},
        },
    }
    if config.WRITE_MODEL_ACCEPTS_TEMPERATURE:
        kwargs["extra_body"] = {"temperature": config.WRITE_TEMPERATURE}
    message = _stream_final(client, **kwargs)
    tracker.record(config.WRITE_MODEL, message.usage)
    if message.stop_reason == "refusal":
        details = getattr(message, "stop_details", None)
        raise ModelOutputError(f"model refused (category={getattr(details, 'category', None)})")
    if message.stop_reason == "max_tokens":
        raise ModelOutputError("model output hit max_tokens")
    text = "".join(b.text for b in message.content if b.type == "text")
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ModelOutputError(f"model returned invalid JSON: {exc}") from exc
