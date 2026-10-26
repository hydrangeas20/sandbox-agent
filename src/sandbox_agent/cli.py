"""Command-line interface.

sandbox-agent fixtures
sandbox-agent preflight
sandbox-agent run --fixture paginator --task "..." [--provider scripted|anthropic] [--json]
sandbox-agent demo
sandbox-agent serve [--port 8000]
"""

from __future__ import annotations

import argparse
import json
import signal
import sys
import tempfile
from pathlib import Path
from typing import Any

from sandbox_agent.config import ModelBudget, SandboxConfig, Settings
from sandbox_agent.errors import SandboxAgentError
from sandbox_agent.sandbox import DockerSandbox
from sandbox_agent.service import TaskRequest, TaskResult, run_task
from sandbox_agent.workspace import FixtureRegistry

DEMO_TASK = (
    "paginate() returns the wrong items: page 1 of 25 items with per_page=10 "
    "starts at item 11. Find and fix the bug, then make sure the test suite passes."
)


def _print_result(result: TaskResult, trace_path: Path | None) -> None:
    agent = result.agent
    print(f"task_id        {result.task_id}")
    print(f"fixture        {result.fixture}  (provider: {result.provider})")
    print(f"status         {result.status.upper()}  — {result.reason}")
    if agent is not None:
        print(
            f"budget used    iterations={agent.iterations} tool_calls={agent.tool_calls} "
            f"policy_denials={agent.policy_denials} invalid_outputs={agent.invalid_outputs}"
        )
    tests = result.final_tests
    print(
        f"final tests    passed={tests.passed} tests_run={tests.tests_run} "
        f"failures={tests.failures or 0}"
    )
    print(f"files changed  {', '.join(result.files_changed) or '(none)'}")
    print(f"fixture intact {result.fixture_unchanged}  sha256={result.fixture_sha256_after[:16]}…")
    print(f"duration       {result.duration_ms} ms")
    if result.model_usage:
        u = result.model_usage
        print(
            f"model usage    {u['model']}: calls={u['calls']} tokens={u['total_tokens']} "
            f"est_cost=${u['cost_usd']:.4f} (cap ${u['budget']['max_cost_usd']:.2f})"
        )
    if trace_path:
        print(f"trace          {trace_path}  ({len(result.trace)} events)")
    print()
    print("--- tool calls ---")
    for e in result.trace:
        if e["event"] == "tool_end":
            detail = e.get("result") or {}
            flag = "ok " if e.get("ok") else "ERR"
            rule = f" denied={e['denied_rule']}" if e.get("denied_rule") else ""
            print(f"  [{flag}] {e['tool']:<11} {e.get('duration_ms', 0):>5} ms  {detail}{rule}")
    if result.diff:
        print()
        print("--- diff ---")
        print(result.diff.rstrip())


def _write_trace(result: TaskResult, settings: Settings, out: str | None) -> Path:
    path = Path(out) if out else settings.runs_dir / f"{result.task_id}.trace.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as fh:
        for event in result.trace:
            fh.write(json.dumps(event, sort_keys=True) + "\n")
    return path


def cmd_run(args: argparse.Namespace, settings: Settings) -> int:
    model_budget = ModelBudget(
        **{
            k: v
            for k, v in {
                "max_cost_usd": getattr(args, "max_cost_usd", None),
                "max_model_calls": getattr(args, "max_model_calls", None),
            }.items()
            if v is not None
        }
    )
    req = TaskRequest(
        fixture=args.fixture,
        task=args.task,
        provider=args.provider,
        scenario=args.scenario,
        model=getattr(args, "model", None),
        model_budget=model_budget,
    )
    sandbox_config = SandboxConfig(timeout_s=args.timeout) if args.timeout else None
    result = run_task(req, settings, sandbox_config=sandbox_config)
    trace_path = _write_trace(result, settings, args.trace_out)
    if args.json:
        print(result.model_dump_json(indent=2))
    else:
        _print_result(result, trace_path)
    return 0 if result.status == "succeeded" and result.fixture_unchanged else 1


def cmd_demo(args: argparse.Namespace, settings: Settings) -> int:
    print("Sandbox Coding Agent — offline demo (scripted provider, Docker sandbox)\n")
    print(f"task: {DEMO_TASK}\n")
    args.fixture, args.task, args.provider = "paginator", DEMO_TASK, "scripted"
    args.scenario = args.scenario or None
    return cmd_run(args, settings)


def cmd_preflight(args: argparse.Namespace, settings: Settings) -> int:
    with tempfile.TemporaryDirectory(prefix="sandbox-agent-preflight-") as tmp:
        info = DockerSandbox(SandboxConfig(), Path(tmp)).preflight()
    print(json.dumps(info, indent=2))
    return 0


def cmd_fixtures(args: argparse.Namespace, settings: Settings) -> int:
    for name in FixtureRegistry(settings.fixtures_dir).names():
        print(name)
    return 0


def cmd_serve(args: argparse.Namespace, settings: Settings) -> int:
    import uvicorn  # noqa: PLC0415

    from sandbox_agent.api import create_app  # noqa: PLC0415

    uvicorn.run(create_app(settings), host="127.0.0.1", port=args.port)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sandbox-agent", description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="run one task against a named fixture")
    run.add_argument("--fixture", required=True)
    run.add_argument("--task", required=True)
    run.add_argument("--provider", choices=["scripted", "anthropic"], default="scripted")
    run.add_argument("--scenario", default=None, help="scripted scenario (default: fixture name)")
    run.add_argument("--json", action="store_true", help="print the full TaskResult as JSON")
    run.add_argument("--trace-out", default=None, help="trace JSONL path (default: runs/)")
    run.add_argument("--timeout", type=float, default=None, help="per-command sandbox timeout (s)")
    run.add_argument("--model", default=None, help="model id for --provider anthropic")
    run.add_argument("--max-cost-usd", type=float, default=None, help="per-task cost cap")
    run.add_argument("--max-model-calls", type=int, default=None, help="per-task model calls")
    run.set_defaults(func=cmd_run)

    demo = sub.add_parser("demo", help="one-command offline demo on the paginator fixture")
    demo.add_argument("--json", action="store_true")
    demo.add_argument("--trace-out", default=None)
    demo.add_argument("--scenario", default=None)
    demo.add_argument("--timeout", type=float, default=None)
    demo.set_defaults(func=cmd_demo)

    sub.add_parser("preflight", help="check Docker isolation prerequisites").set_defaults(
        func=cmd_preflight
    )
    sub.add_parser("fixtures", help="list fixture repositories").set_defaults(func=cmd_fixtures)
    serve = sub.add_parser("serve", help="run the HTTP API on 127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.set_defaults(func=cmd_serve)
    return parser


def _terminate(signum: int, _frame: object) -> None:
    # Unwind normally so `finally` blocks remove the container and the workspace (SR-04).
    raise SystemExit(128 + signum)


def main(argv: list[str] | None = None) -> int:
    signal.signal(signal.SIGTERM, _terminate)
    signal.signal(signal.SIGHUP, _terminate)
    args = build_parser().parse_args(argv)
    settings = Settings.from_env()
    try:
        code: Any = args.func(args, settings)
    except SandboxAgentError as exc:
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    return int(code)


if __name__ == "__main__":
    raise SystemExit(main())
