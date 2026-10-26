"""Controller budgets, error states, cancellation and status semantics (no Docker)."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

import pytest

from sandbox_agent.agent import AgentController
from sandbox_agent.config import AgentBudget, WorkspaceLimits
from sandbox_agent.errors import ProviderError, SandboxIsolationError
from sandbox_agent.providers.anthropic import AnthropicProvider, parse_response
from sandbox_agent.providers.base import Transcript, Turn
from sandbox_agent.providers.scripted import (
    LoopingProvider,
    ScriptedProvider,
    Step,
    paginator_fix_script,
)
from sandbox_agent.sandbox import ContainerCommand, RunOutcome
from sandbox_agent.tools import ToolContext, ToolExecutor
from sandbox_agent.trace import Tracer
from sandbox_agent.workspace import Workspace
from tests.fakes import FakeRunner, outcome

FAIL = outcome(1, "Ran 6 tests in 0.01s\n\nFAILED (failures=2)\n")
PASS = outcome(0, "Ran 6 tests in 0.01s\n\nOK\n")
FINISH = {"tool": "finish", "args": {"summary": "done"}}
RUN = {"tool": "run_tests", "args": {"command": "unittest"}}
PATCH = {
    "tool": "apply_patch",
    "args": {
        "edits": [
            {
                "path": "paginator/core.py",
                "old": "    start = page * per_page\n",
                "new": "    start = (page - 1) * per_page\n",
            }
        ]
    },
}


@pytest.fixture
def ws(fixtures_dir: Path, tmp_path: Path) -> Workspace:
    return Workspace.create(fixtures_dir / "paginator", WorkspaceLimits(), base_dir=tmp_path)


def controller(
    ws: Workspace,
    provider: Any,
    runner: Any = None,
    budget: AgentBudget | None = None,
    **kw: Any,
) -> AgentController:
    tools = ToolExecutor(ToolContext(workspace=ws, runner=runner or FakeRunner([FAIL, PASS])))
    return AgentController(provider, tools, budget or AgentBudget(), Tracer("cid-test"), **kw)


def scripted(*raws: Any) -> ScriptedProvider:
    return ScriptedProvider([Step(r) for r in raws])


def test_paginator_script_succeeds_with_fake_runner(ws: Workspace) -> None:
    res = controller(ws, paginator_fix_script()).run("fix pagination")
    assert res.status == "succeeded", res
    assert res.patches_applied == 1
    assert res.final_tests_passed is True
    assert res.tool_calls == 5


def test_script_diverges_if_world_differs(ws: Workspace) -> None:
    """If the 'buggy' suite already passes, the scripted plan must not claim a fix."""
    res = controller(ws, paginator_fix_script(), FakeRunner([PASS, PASS])).run("fix")
    assert res.status == "failed"
    assert res.summary is not None
    assert "diverged" in res.summary


def test_finish_without_patch_is_failure(ws: Workspace) -> None:
    res = controller(ws, scripted(RUN, FINISH), FakeRunner([PASS])).run("t")
    assert res.status == "failed"
    assert "without applying a patch" in res.reason


def test_finish_after_patch_without_tests_is_failure(ws: Workspace) -> None:
    res = controller(ws, scripted(PATCH, FINISH)).run("t")
    assert res.status == "failed"


def test_selector_only_pass_is_not_success(ws: Workspace) -> None:
    sel = {"tool": "run_tests", "args": {"command": "unittest", "selector": "tests.test_core"}}
    res = controller(ws, scripted(PATCH, sel, FINISH), FakeRunner([PASS])).run("t")
    assert res.status == "failed"


def test_tests_before_patch_do_not_count(ws: Workspace) -> None:
    res = controller(ws, scripted(RUN, PATCH, FINISH), FakeRunner([PASS])).run("t")
    assert res.status == "failed"


def test_failing_tests_after_patch_is_failure(ws: Workspace) -> None:
    res = controller(ws, scripted(PATCH, RUN, FINISH), FakeRunner([FAIL])).run("t")
    assert res.status == "failed"
    assert res.final_tests_passed is False


def test_iteration_budget(ws: Workspace) -> None:
    provider = LoopingProvider({"tool": "list_files", "args": {}})
    res = controller(ws, provider, budget=AgentBudget(max_iterations=5, max_tool_calls=50)).run("t")
    assert res.status == "budget_exhausted"
    assert "max_iterations" in res.reason
    assert provider.calls == 5


def test_tool_call_budget(ws: Workspace) -> None:
    provider = LoopingProvider({"tool": "list_files", "args": {}})
    res = controller(ws, provider, budget=AgentBudget(max_iterations=50, max_tool_calls=3)).run("t")
    assert res.status == "budget_exhausted"
    assert "max_tool_calls" in res.reason
    assert res.tool_calls == 3


def test_wall_clock_budget(ws: Workspace) -> None:
    ticks = iter(float(i) for i in range(0, 10_000, 10))
    provider = LoopingProvider({"tool": "list_files", "args": {}})
    res = controller(
        ws,
        provider,
        budget=AgentBudget(max_wall_clock_s=25, max_iterations=100, max_tool_calls=100),
        clock=lambda: next(ticks),
    ).run("t")
    assert res.status == "budget_exhausted"
    assert "wall_clock" in res.reason


def test_cancellation_before_start(ws: Workspace) -> None:
    cancel = threading.Event()
    cancel.set()
    provider = LoopingProvider({"tool": "list_files", "args": {}})
    res = controller(ws, provider, cancel=cancel).run("t")
    assert res.status == "cancelled"
    assert provider.calls == 0


def test_cancellation_mid_run_stops_before_tool(ws: Workspace) -> None:
    cancel = threading.Event()
    runner = FakeRunner()

    class CancelOnSecondCall:
        name = "cancelling"
        calls = 0

        def next_action(self, transcript: Transcript) -> Any:
            self.calls += 1
            if self.calls == 2:
                cancel.set()
            return RUN

    res = controller(ws, CancelOnSecondCall(), runner, cancel=cancel).run("t")
    assert res.status == "cancelled"
    assert len(runner.calls) == 1


INVALID_OUTPUTS: list[Any] = [
    "rm -rf /",
    None,
    42,
    [],
    {},
    {"tool": ""},
    {"tool": "read file"},
    {"tool": "x" * 100},
    {"tool": "list_files", "args": "not-a-dict"},
    {"tool": "list_files", "args": {}, "sudo": True},
    {"error": "model refused"},
]


@pytest.mark.parametrize("bad", INVALID_OUTPUTS, ids=[repr(b)[:30] for b in INVALID_OUTPUTS])
def test_invalid_provider_output_is_error_state(ws: Workspace, bad: Any) -> None:
    res = controller(ws, scripted(bad, bad, bad)).run("t")
    assert res.status == "provider_error"
    assert res.invalid_outputs == 3
    assert res.tool_calls == 0


def test_invalid_output_recovers(ws: Workspace) -> None:
    res = controller(ws, scripted("garbage", PATCH, RUN, FINISH), FakeRunner([PASS])).run("t")
    assert res.status == "succeeded"
    assert res.invalid_outputs == 1


def test_provider_exception_counts_as_invalid(ws: Workspace) -> None:
    class Broken:
        name = "broken"

        def next_action(self, transcript: Transcript) -> Any:
            raise ProviderError("HTTP 529 overloaded")

    res = controller(ws, Broken()).run("t")
    assert res.status == "provider_error"


def test_policy_denials_abort(ws: Workspace) -> None:
    bad = {"tool": "read_file", "args": {"path": "../../etc/passwd"}}
    res = controller(ws, scripted(bad, bad, bad, bad)).run("t")
    assert res.status == "policy_aborted"
    assert res.policy_denials == 3


def test_sandbox_failure_is_fail_closed(ws: Workspace) -> None:
    class FailingRunner:
        def run(self, workspace_dir: Path, command: ContainerCommand) -> RunOutcome:
            raise SandboxIsolationError("isolation verification failed: network mode")

    res = controller(ws, scripted(RUN, FINISH), FailingRunner()).run("t")
    assert res.status == "sandbox_error"


def test_observations_are_bounded(ws: Workspace) -> None:
    provider = scripted({"tool": "read_file", "args": {"path": "paginator/core.py"}}, FINISH)
    ctl = controller(ws, provider, budget=AgentBudget(max_observation_chars=300))
    transcript_holder: list[Transcript] = []
    original = provider.next_action

    def spy(t: Transcript) -> Any:
        transcript_holder.append(t)
        return original(t)

    provider.next_action = spy  # type: ignore[method-assign]
    ctl.run("t")
    obs = [t for t in transcript_holder[-1].turns if t.role == "observation"]
    assert len(json.dumps(obs[0].content)) < 600


# ---------------------------------------------------------------------- anthropic adapter


def test_anthropic_requires_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(ProviderError):
        AnthropicProvider()


def test_anthropic_request_and_parsing_with_stub_transport() -> None:
    captured: dict[str, Any] = {}

    def transport(body: dict[str, Any], headers: dict[str, str], timeout: float) -> dict[str, Any]:
        captured["body"], captured["headers"], captured["timeout"] = body, headers, timeout
        return {
            "content": [
                {"type": "text", "text": "Run tests first."},
                {"type": "tool_use", "id": "toolu_1", "name": "run_tests", "input": RUN["args"]},
            ]
        }

    provider = AnthropicProvider(api_key="sk-ant-test-KEY", transport=transport)
    t = Transcript(task="fix it")
    t.add(Turn("action", {"tool": "list_files", "args": {}}, "toolu_0"))
    t.add(Turn("observation", {"tool": "list_files", "ok": True, "output": {}}, "toolu_0"))
    raw = provider.next_action(t)
    assert raw == {
        "tool": "run_tests",
        "args": {"command": "unittest"},
        "call_id": "toolu_1",
        "thought": "Run tests first.",
    }
    body = json.dumps(captured["body"])
    assert "sk-ant-test-KEY" not in body
    assert captured["headers"]["x-api-key"] == "sk-ant-test-KEY"
    assert {tool["name"] for tool in captured["body"]["tools"]} >= {"run_tests", "apply_patch"}
    assert "UNTRUSTED TOOL OUTPUT" in body
    assert captured["timeout"] == 60.0
    assert captured["body"]["messages"][1]["content"][0]["type"] == "tool_use"


@pytest.mark.parametrize(
    "response",
    [
        {},
        {"content": "text"},
        {"content": [{"type": "text", "text": "no tool"}]},
        {"content": [{"type": "tool_use", "name": "a"}, {"type": "tool_use", "name": "b"}]},
    ],
)
def test_anthropic_bad_responses_yield_invalid_raw(response: dict[str, Any]) -> None:
    raw = parse_response(response)
    assert "error" in raw
