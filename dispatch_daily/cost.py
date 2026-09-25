"""Anthropic client construction, retries and the per-run spend cap."""

from __future__ import annotations

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
