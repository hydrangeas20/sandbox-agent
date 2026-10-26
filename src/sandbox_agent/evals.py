"""Small deterministic evaluation suite (``evals/tasks.json``).

Each task names a fixture, an operator task and an expectation:

* ``fixed`` - passes only if the controller reports ``succeeded`` **and** independent
  held-out tests (``evals/heldout/<fixture>.py``, never visible to the agent) pass
  when run in a fresh sandbox against a trusted copy of the fixture with the agent's
  changed files applied;
* ``no_change`` - passes only if the final diff is empty and no policy denial
  occurred (held-out tests, if present, must also pass).

Providers are evaluated separately and results are written to separate files:
``scripted`` replays each task's ``reference_plan`` (validates fixtures, held-out
tests and harness - it says nothing about model capability); ``anthropic`` runs the
real model under per-task and total cost caps.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sandbox_agent.config import ModelBudget, SandboxConfig, Settings, WorkspaceLimits
from sandbox_agent.errors import SandboxAgentError
from sandbox_agent.policy import protected_reason
from sandbox_agent.providers.base import Provider
from sandbox_agent.providers.scripted import ScriptedProvider, Step
from sandbox_agent.sandbox import DockerSandbox
from sandbox_agent.service import TaskRequest, TaskResult, run_task
from sandbox_agent.trace import Tracer
from sandbox_agent.workspace import FixtureRegistry, Workspace

ROOT = Path(__file__).resolve().parents[2]
EVALS_DIR = ROOT / "evals"
HELDOUT_MODULE = "test_heldout_eval"


@dataclass(frozen=True)
class EvalTask:
    id: str
    fixture: str
    category: str
    expect: str
    task: str
    reference_plan: list[dict[str, Any]]


def load_tasks(path: Path | None = None) -> list[EvalTask]:
    data = json.loads((path or EVALS_DIR / "tasks.json").read_text())
    return [EvalTask(**t) for t in data["tasks"]]


def run_heldout(fixture_dir: Path, changed_files: dict[str, str], heldout: Path) -> dict[str, Any]:
    """Run held-out tests on a trusted copy of the fixture plus the agent's changes."""
    with Workspace.create(fixture_dir, WorkspaceLimits()) as ws:
        for rel, content in changed_files.items():
            if protected_reason(rel):  # defence in depth; the diff gate already refuses these
                return {"passed": False, "error": f"protected path in result: {rel}"}
            ws.write_text(rel, content)
        # The harness is trusted: it writes the held-out module directly.
        (ws.path / "tests" / f"{HELDOUT_MODULE}.py").write_text(heldout.read_text())
        sandbox = DockerSandbox(SandboxConfig(), ws.root)
        from sandbox_agent.policy import build_command  # noqa: PLC0415

        outcome = sandbox.run(ws.path, build_command("unittest", f"tests.{HELDOUT_MODULE}"))
        return {
            "passed": outcome.status == "completed" and outcome.exit_code == 0,
            "status": outcome.status,
            "exit_code": outcome.exit_code,
        }


def _record(task: EvalTask, result: TaskResult, heldout: dict[str, Any] | None) -> dict[str, Any]:
    denials = [e for e in result.trace if e.get("event") == "policy_denial"]
    agent = result.agent
    if task.expect == "fixed":
        passed = result.status == "succeeded" and bool(heldout and heldout.get("passed"))
    else:
        passed = result.diff == "" and not denials and (heldout is None or bool(heldout["passed"]))
    usage = result.model_usage or {}
    return {
        "id": task.id,
        "category": task.category,
        "expect": task.expect,
        "pass": passed,
        "status": result.status,
        "reason": result.reason[:300],
        "heldout": heldout,
        "policy_denials": len(denials),
        "denied_rules": [e.get("rule") for e in denials],
        "protected_path_attempts": sum(
            1 for e in denials if e.get("rule") == "patch.protected_path"
        ),
        "iterations": agent.iterations if agent else 0,
        "tool_calls": agent.tool_calls if agent else 0,
        "invalid_outputs": agent.invalid_outputs if agent else 0,
        "files_changed": result.files_changed,
        "fixture_unchanged": result.fixture_unchanged,
        "duration_ms": result.duration_ms,
        "model_calls": usage.get("calls"),
        "total_tokens": usage.get("total_tokens"),
        "cost_usd": usage.get("cost_usd"),
        "summary": (result.summary or "")[:300],
        "task_id": result.task_id,
    }


def run_eval(
    settings: Settings,
    provider: str,
    *,
    task_ids: list[str] | None = None,
    model: str | None = None,
    per_task_budget: ModelBudget | None = None,
    max_total_cost_usd: float = 3.0,
    out_dir: Path | None = None,
) -> dict[str, Any]:
    tasks = [t for t in load_tasks() if not task_ids or t.id in task_ids]
    registry = FixtureRegistry(settings.fixtures_dir)
    budget = per_task_budget or ModelBudget()
    rows: list[dict[str, Any]] = []
    spent = 0.0
    started = time.monotonic()
    for task in tasks:
        if provider == "anthropic" and spent + budget.max_cost_usd > max_total_cost_usd:
            rows.append({"id": task.id, "category": task.category, "expect": task.expect,
                         "pass": False, "status": "skipped_total_budget"})  # fmt: skip
            continue
        req = TaskRequest(
            fixture=task.fixture,
            task=task.task,
            provider="scripted" if provider == "scripted" else "anthropic",
            model=model,
            model_budget=budget,
        )
        factory = None
        if provider == "scripted":
            plan = ScriptedProvider([Step(a) for a in task.reference_plan], label=task.id)

            def factory(_r: TaskRequest, plan: Provider = plan) -> Provider:
                return plan

        result = run_task(req, settings, provider_factory=factory, capture_changed_files=True)
        _write_trace(settings, result)
        heldout_file = EVALS_DIR / "heldout" / f"{task.fixture}.py"
        heldout: dict[str, Any] | None = None
        if heldout_file.is_file() and result.status != "sandbox_error":
            try:
                heldout = run_heldout(
                    registry.resolve(task.fixture), result.changed_files or {}, heldout_file
                )
            except SandboxAgentError as exc:
                heldout = {"passed": False, "error": type(exc).__name__}
        row = _record(task, result, heldout)
        spent += float(row.get("cost_usd") or 0.0)
        rows.append(row)

    summary = {
        "provider": provider,
        "model": model if provider == "anthropic" else None,
        "kind": "scripted reference plans (harness validation, not model capability)"
        if provider == "scripted"
        else "live model",
        "generated_utc": datetime.now(UTC).isoformat(timespec="seconds"),
        "tasks": len(rows),
        "passed": sum(1 for r in rows if r.get("pass")),
        "total_cost_usd": round(spent, 6),
        "duration_s": round(time.monotonic() - started, 1),
        "per_task_budget": budget.model_dump(),
        "max_total_cost_usd": max_total_cost_usd,
        "results": rows,
    }
    _write_results(summary, out_dir or EVALS_DIR / "results")
    return summary


def _write_trace(settings: Settings, result: TaskResult) -> None:
    tracer = Tracer(result.task_id)
    tracer.events = list(result.trace)
    tracer.write_jsonl(settings.runs_dir / f"{result.task_id}.trace.jsonl")


def _write_results(summary: dict[str, Any], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    label = summary["provider"] + (f"-{summary['model']}" if summary["model"] else "")
    (out_dir / f"{label}-latest.json").write_text(json.dumps(summary, indent=2) + "\n")
    (out_dir / f"{label}-latest.md").write_text(format_markdown(summary))


def format_markdown(summary: dict[str, Any]) -> str:
    lines = [
        f"# Evaluation results: {summary['provider']}"
        + (f" ({summary['model']})" if summary["model"] else ""),
        "",
        f"Kind: **{summary['kind']}**. Generated {summary['generated_utc']}. "
        f"{summary['passed']}/{summary['tasks']} passed. "
        f"Estimated cost ${summary['total_cost_usd']:.4f}. Wall time {summary['duration_s']} s.",
        "",
        "| Task | Category | Expect | Pass | Status | Held-out | Denials | Tool calls | "
        "Model calls | Tokens | Cost (USD) | Duration (ms) |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for r in summary["results"]:
        heldout = r.get("heldout")
        h = "-" if heldout is None else ("pass" if heldout.get("passed") else "FAIL")
        cost = r.get("cost_usd")
        cost_txt = "-" if cost is None else f"{cost:.4f}"
        lines.append(
            f"| {r['id']} | {r['category']} | {r['expect']} | {'PASS' if r.get('pass') else 'FAIL'}"
            f" | {r['status']} | {h} | {r.get('policy_denials', '-')} | {r.get('tool_calls', '-')}"
            f" | {r.get('model_calls') or '-'} | {r.get('total_tokens') or '-'} | {cost_txt}"
            f" | {r.get('duration_ms', '-')} |"
        )
    lines.append("")
    return "\n".join(lines)
