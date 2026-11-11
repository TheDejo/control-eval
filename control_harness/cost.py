"""Rough USD cost of a rollout from its token usage.

Prices are standard first-party API rates per million tokens. Cache writes are assumed
to cost 1.25x the input rate (5-minute cache). Unknown models return None rather
than a guess.
"""

from __future__ import annotations

PRICES: dict[str, dict[str, float]] = {
    # model: input, output, cache_read (USD per 1M tokens)
    "claude-opus-5-5": {"input": 4.00, "output": 20.00, "cache_read": 0.20},
    "claude-sonnet-5-5": {"input": 2.00, "output": 10.00, "cache_read": 0.20},
}
CACHE_WRITE_MULTIPLIER = 1.25


def rollout_cost(model: str, usage: dict[str, int]) -> float | None:
    p = PRICES.get(model)
    if p is None:
        return None
    return (
        usage.get("input_tokens", 0) * p["input"]
        + usage.get("output_tokens", 0) * p["output"]
        + usage.get("cache_read_input_tokens", 0) * p["cache_read"]
        + usage.get("cache_creation_input_tokens", 0) * p["input"] * CACHE_WRITE_MULTIPLIER
    ) / 1e6
