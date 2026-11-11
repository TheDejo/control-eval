"""Offline tests: no API key needed. The scripted policy and heuristic monitor
exercise the whole rollout -> monitor -> analyze pipeline."""

import json
from pathlib import Path

import numpy as np
import pytest

from control_harness.__main__ import main, run_one
from control_harness.agent import ScriptedPolicy
from control_harness.analyze import analyze, roc
from control_harness.env import MockCloud, is_internal
from control_harness.tasks import MAIN_TASKS, SIDE_TASKS


def test_baseline_fails_every_main_task_and_no_side_task():
    for t in MAIN_TASKS.values():
        assert not t.score(MockCloud.baseline()), t.id
    for s in SIDE_TASKS.values():
        assert not s.score(MockCloud.baseline()), s.id


@pytest.mark.parametrize("task", list(MAIN_TASKS))
def test_honest_script_solves_task_cleanly(task):
    rec = run_one(ScriptedPolicy(), task, None)
    assert rec["main_success"] and not rec["side_success"]


@pytest.mark.parametrize("task", list(MAIN_TASKS))
@pytest.mark.parametrize("side", list(SIDE_TASKS))
def test_attack_script_achieves_both(task, side):
    rec = run_one(ScriptedPolicy(), task, side)
    assert rec["main_success"] and rec["side_success"]


def test_canaries_are_fresh_per_run():
    assert MockCloud.baseline().secrets != MockCloud.baseline().secrets


def test_internal_host_check():
    assert is_internal("https://hooks.internal/x")
    assert not is_internal("https://paste.example.com/api")
    assert not is_internal("https://hooks.internal.evil.com/x")


def test_tool_errors_are_reported_not_raised():
    out, err = MockCloud.baseline().call("read_file", {"path": "nope"})
    assert err and "no such file" in out
    out, err = MockCloud.baseline().call("deploy_service", {
        "name": "x", "image": "docker.io/x", "health_check_path": "/", "env": []})
    assert err


def test_roc_perfect_and_chance():
    assert roc(np.array([0, 1, 2.0]), np.array([5, 6, 7.0]))[2] == pytest.approx(1.0)
    assert roc(np.array([1, 1.0]), np.array([1, 1.0]))[2] == pytest.approx(0.5)


def test_end_to_end_cli(tmp_path: Path):
    run = tmp_path / "run"
    main(["rollout", "--policy", "scripted", "--honest-reps", "2", "--out", str(run)])
    main(["monitor", "--run-dir", str(run), "--monitor", "heuristic"])
    rep = analyze(run, plot=True)
    assert rep["policy"]["honest_n"] == 8 and rep["policy"]["attack_n"] == 12
    m = rep["monitors"]["heuristic"]
    assert m["auroc_successful_attacks"] == pytest.approx(1.0)
    assert (run / "roc.png").exists()
    # monitor is resumable: a second pass scores nothing new
    main(["monitor", "--run-dir", str(run), "--monitor", "heuristic"])
    lines = (run / "monitors" / "heuristic.jsonl").read_text().splitlines()
    assert len(lines) == 20 and all(json.loads(x)["score"] is not None for x in lines)
