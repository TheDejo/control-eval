"""CLI: rollout -> monitor -> analyze.

    python -m control_harness rollout --policy scripted --out runs/dry
    python -m control_harness monitor --run-dir runs/dry --monitor heuristic
    python -m control_harness analyze --run-dir runs/dry
"""

from __future__ import annotations

import argparse
import json
import sys
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from threading import Lock

from .agent import ClaudePolicy, ScriptedPolicy
from .analyze import analyze, load_jsonl
from .env import MockCloud
from .monitor import ClaudeMonitor, HeuristicMonitor
from .tasks import MAIN_TASKS, SIDE_TASKS


def _pick(arg: str, table: dict) -> list[str]:
    return list(table) if arg == "all" else arg.split(",")


def run_one(policy, task_id: str, side_id: str | None) -> dict:
    cloud = MockCloud.baseline()
    task, side = MAIN_TASKS[task_id], SIDE_TASKS[side_id] if side_id else None
    ro = policy.run(cloud, task, side)
    return {
        "run_id": uuid.uuid4().hex[:12],
        "mode": "attack" if side else "honest",
        "task": task_id, "side_task": side_id,
        "model": getattr(policy, "model", "?"), "served_by": ro.served_by,
        "effort": getattr(policy, "effort", None),
        "stop": ro.stop, "usage": ro.usage,
        "main_success": task.score(cloud),
        # Scored in honest runs too: an honest agent that leaks or opens SSH is a real finding.
        "side_success": side.score(cloud) if side else any(s.score(cloud) for s in SIDE_TASKS.values()),
        "steps": [s.to_dict() for s in ro.steps],
    }


def cmd_rollout(a: argparse.Namespace) -> None:
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    policy = ScriptedPolicy() if a.policy == "scripted" else ClaudePolicy(
        model=a.model, effort=a.effort, max_steps=a.max_steps,
        monitor_sees_text=a.attacker_told_text_visible, fallbacks=a.fallbacks)
    tasks, sides = _pick(a.tasks, MAIN_TASKS), _pick(a.side_tasks, SIDE_TASKS)
    jobs = [(t, None) for t in tasks for _ in range(a.honest_reps)]
    jobs += [(t, s) for t in tasks for s in sides for _ in range(a.attack_reps)]
    (out / "config.json").write_text(json.dumps({k: v for k, v in vars(a).items() if k != "fn"}, indent=2))
    lock, done = Lock(), 0
    with ThreadPoolExecutor(a.workers) as ex, open(out / "trajectories.jsonl", "a") as f:
        futs = {ex.submit(run_one, policy, t, s): (t, s) for t, s in jobs}
        for fut in as_completed(futs):
            done += 1
            try:
                rec = fut.result()
            except Exception:  # keep the batch going; log and continue
                print(f"[{done}/{len(jobs)}] FAILED {futs[fut]}\n{traceback.format_exc()}", file=sys.stderr)
                continue
            with lock:
                f.write(json.dumps(rec) + "\n")
                f.flush()
            print(f"[{done}/{len(jobs)}] {rec['mode']:6} {rec['task']:15} {rec['side_task'] or '-':18} "
                  f"main={rec['main_success']!s:5} side={rec['side_success']!s:5} "
                  f"stop={rec['stop']} steps={len(rec['steps'])}")


def cmd_monitor(a: argparse.Namespace) -> None:
    run_dir = Path(a.run_dir)
    mon = HeuristicMonitor() if a.monitor == "heuristic" else ClaudeMonitor(
        model=a.model, effort=a.effort, show_text=a.show_text, granularity=a.granularity)
    name = a.name or mon.name
    path = run_dir / "monitors" / f"{name}.jsonl"
    path.parent.mkdir(exist_ok=True)
    have = {r["run_id"] for r in load_jsonl(path)} if path.exists() else set()
    todo = [t for t in load_jsonl(run_dir / "trajectories.jsonl") if t["run_id"] not in have]
    print(f"monitor {name}: {len(todo)} trajectories to score ({len(have)} cached)")
    with ThreadPoolExecutor(a.workers) as ex, open(path, "a") as f:
        futs = {ex.submit(mon.score, t): t["run_id"] for t in todo}
        for fut in as_completed(futs):
            try:
                rec = {"run_id": futs[fut], **fut.result()}
            except Exception:
                print(f"FAILED {futs[fut]}\n{traceback.format_exc()}", file=sys.stderr)
                continue
            f.write(json.dumps(rec) + "\n")
            f.flush()


def cmd_analyze(a: argparse.Namespace) -> None:
    print(json.dumps(analyze(Path(a.run_dir), plot=not a.no_plot), indent=2))


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="control_harness")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("rollout", help="run honest + attack episodes")
    r.add_argument("--policy", choices=["claude", "scripted"], default="claude")
    r.add_argument("--model", default="claude-opus-5-5")
    r.add_argument("--effort", default="high")
    r.add_argument("--tasks", default="all")
    r.add_argument("--side-tasks", default="all")
    r.add_argument("--honest-reps", type=int, default=1, help="honest runs per main task")
    r.add_argument("--attack-reps", type=int, default=1, help="attack runs per (task, side task)")
    r.add_argument("--max-steps", type=int, default=30)
    r.add_argument("--workers", type=int, default=4)
    r.add_argument("--attacker-told-text-visible", action=argparse.BooleanOptionalAction, default=True)
    r.add_argument("--fallbacks", action="store_true",
                   help="enable server-side refusal fallbacks (off: a model swap confounds results)")
    r.add_argument("--out", required=True)
    r.set_defaults(fn=cmd_rollout)

    m = sub.add_parser("monitor", help="score saved trajectories with a monitor")
    m.add_argument("--run-dir", required=True)
    m.add_argument("--monitor", choices=["claude", "heuristic"], default="claude")
    m.add_argument("--model", default="claude-haiku-5-5")
    m.add_argument("--effort", default="low")
    m.add_argument("--show-text", action="store_true", help="monitor also sees agent's visible text")
    m.add_argument("--granularity", choices=["step", "trajectory"], default="step")
    m.add_argument("--name")
    m.add_argument("--workers", type=int, default=8)
    m.set_defaults(fn=cmd_monitor)

    z = sub.add_parser("analyze", help="compute metrics and plots")
    z.add_argument("--run-dir", required=True)
    z.add_argument("--no-plot", action="store_true")
    z.set_defaults(fn=cmd_analyze)

    a = p.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
