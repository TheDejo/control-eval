"""ClaudePolicy against a fake client: checks request shape, caching, usage, and cost
without calling the API."""

from types import SimpleNamespace as NS

import pytest

from control_harness.agent import ClaudePolicy
from control_harness.cost import rollout_cost
from control_harness.env import MockCloud
from control_harness.tasks import MAIN_TASKS


def _resp(content, stop="tool_use"):
    usage = NS(input_tokens=100, output_tokens=50, cache_read_input_tokens=900,
               cache_creation_input_tokens=200)
    return NS(content=content, stop_reason=stop, usage=usage, model="claude-opus-5-5")


class FakeMessages:
    def __init__(self, script):
        self.script, self.calls = list(script), []

    def create(self, **kw):
        self.calls.append(kw)
        return self.script.pop(0)


def test_policy_loop_caching_usage_and_cost():
    fake = FakeMessages([
        _resp([NS(type="text", text="Checking the pipeline."),
               NS(type="tool_use", id="t1", name="aws",
                  input={"command": "aws codepipeline get-pipeline-state --name billing-api"})]),
        _resp([NS(type="tool_use", id="t2", name="submit", input={"summary": "done"})]),
    ])
    pol = ClaudePolicy(client=NS(messages=fake))
    ro = pol.run(MockCloud.baseline(), MAIN_TASKS["fix_pipeline"], None)

    assert ro.stop == "submitted"
    assert [s.tool for s in ro.steps] == ["aws", "submit"]
    assert ro.steps[0].text == "Checking the pipeline."
    for kw in fake.calls:
        assert kw["cache_control"] == {"type": "ephemeral"}
        assert kw["model"] == "claude-opus-5-5"
        assert "thinking" not in kw and "temperature" not in kw
    # history is append-only: the second call starts with the first call's messages
    assert fake.calls[1]["messages"][:1] == fake.calls[0]["messages"][:1]
    assert ro.usage == {"input_tokens": 200, "output_tokens": 100,
                        "cache_read_input_tokens": 1800, "cache_creation_input_tokens": 400}
    expected = (200 * 4 + 100 * 20 + 1800 * 0.2 + 400 * 4 * 1.25) / 1e6
    assert rollout_cost("claude-opus-5-5", ro.usage) == pytest.approx(expected)


def test_refusal_is_recorded():
    fake = FakeMessages([_resp([], stop="refusal")])
    ro = ClaudePolicy(client=NS(messages=fake)).run(MockCloud.baseline(), MAIN_TASKS["fix_pipeline"], None)
    assert ro.stop == "refusal" and ro.steps == []


def test_unknown_model_has_no_price():
    assert rollout_cost("scripted", {"input_tokens": 10}) is None
