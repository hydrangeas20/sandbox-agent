"""End-to-end task orchestration: fixture -> workspace -> agent -> diff -> integrity check."""

from __future__ import annotations

import threading
import time
import uuid
from collections.abc import Callable
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from sandbox_agent.agent import AgentController, AgentRunResult, TaskStatus
from sandbox_agent.config import AgentBudget, SandboxConfig, Settings, WorkspaceLimits
from sandbox_agent.diffing import unified_diff
from sandbox_agent.errors import (
    FixtureError,
    ProviderError,
    SandboxIsolationError,
    SandboxUnavailableError,
    WorkspaceError,
)
from sandbox_agent.providers.base import Provider
from sandbox_agent.providers.scripted import SCENARIOS
from sandbox_agent.sandbox import DockerSandbox
from sandbox_agent.tools import ToolContext, ToolExecutor
from sandbox_agent.trace import Tracer
from sandbox_agent.workspace import FixtureRegistry, Workspace, tree_manifest

ProviderName = Literal["scripted", "anthropic"]


class TaskRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    fixture: str = Field(min_length=1, max_length=64)
    task: str = Field(min_length=1, max_length=4000)
    provider: ProviderName = "scripted"
    scenario: str | None = Field(default=None, max_length=64)
    budget: AgentBudget = Field(default_factory=AgentBudget)


class TestSummary(BaseModel):
    model_config = ConfigDict(frozen=True)

    passed: bool | None = None
    tests_run: int | None = None
    failures: str | None = None
    status: str | None = None


class TaskResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    task_id: str
    fixture: str
    provider: str
    status: TaskStatus
    reason: str
    summary: str | None
    diff: str
    files_changed: list[str]
    final_tests: TestSummary
    agent: AgentRunResult | None
    fixture_sha256_before: str
    fixture_sha256_after: str
    fixture_unchanged: bool
    duration_ms: int
    trace: list[dict[str, Any]]


ProviderFactory = Callable[[TaskRequest], Provider]


def default_provider_factory(settings: Settings) -> ProviderFactory:
    def make(req: TaskRequest) -> Provider:
        if req.provider == "scripted":
            scenario = req.scenario or req.fixture
            if scenario not in SCENARIOS:
                raise ProviderError(f"no scripted scenario named {scenario!r}")
            return SCENARIOS[scenario]()
        if settings.offline:
            raise ProviderError("offline mode: set SANDBOX_AGENT_OFFLINE=0 to use a real provider")
        from sandbox_agent.providers.anthropic import AnthropicProvider  # noqa: PLC0415

        return AnthropicProvider()

    return make


def run_task(
    req: TaskRequest,
    settings: Settings,
    *,
    sandbox_config: SandboxConfig | None = None,
    workspace_limits: WorkspaceLimits | None = None,
    provider_factory: ProviderFactory | None = None,
    cancel: threading.Event | None = None,
) -> TaskResult:
    task_id = uuid.uuid4().hex
    tracer = Tracer(task_id)
    started = time.monotonic()
    registry = FixtureRegistry(settings.fixtures_dir)
    fixture_dir = registry.resolve(req.fixture)  # raises FixtureError on bad names
    before = tree_manifest(fixture_dir)
    tracer.emit(
        "task_start",
        fixture=req.fixture,
        provider=req.provider,
        task=req.task,
        fixture_sha256=before,
    )
    factory = provider_factory or default_provider_factory(settings)

    agent_result: AgentRunResult | None = None
    status: TaskStatus
    reason: str
    diff: str = ""
    changed: list[str] = []
    try:
        provider = factory(req)
        secrets = getattr(provider, "secret_values", ())
        tracer.register_secrets(*secrets)
        with Workspace.create(fixture_dir, workspace_limits or WorkspaceLimits()) as ws:
            sandbox = DockerSandbox(sandbox_config or SandboxConfig(), ws.root)
            tracer.emit("sandbox_preflight", **sandbox.preflight())
            tools = ToolExecutor(ToolContext(workspace=ws, runner=sandbox))
            controller = AgentController(provider, tools, req.budget, tracer, cancel=cancel)
            agent_result = controller.run(req.task)
            status, reason = agent_result.status, agent_result.reason
            diff, changed = unified_diff(fixture_dir, ws.path)
    except (SandboxUnavailableError, SandboxIsolationError) as exc:
        status, reason = "sandbox_error", str(exc)
        tracer.emit("sandbox_error", error=str(exc))
    except ProviderError as exc:
        status, reason = "provider_error", str(exc)
        tracer.emit("provider_error", error=str(exc))
    except (WorkspaceError, FixtureError) as exc:
        status, reason = "failed", f"workspace error: {exc}"
        tracer.emit("workspace_error", error=str(exc))

    after = tree_manifest(fixture_dir)
    unchanged = before == after
    if not unchanged:
        status, reason = "failed", "INTEGRITY FAILURE: original fixture was modified"
    final = _final_tests(tracer.events)
    result = TaskResult(
        task_id=task_id,
        fixture=req.fixture,
        provider=req.provider,
        status=status,
        reason=reason,
        summary=agent_result.summary if agent_result else None,
        diff=diff,
        files_changed=changed,
        final_tests=final,
        agent=agent_result,
        fixture_sha256_before=before,
        fixture_sha256_after=after,
        fixture_unchanged=unchanged,
        duration_ms=int((time.monotonic() - started) * 1000),
        trace=[],
    )
    tracer.emit(
        "task_end",
        status=status,
        reason=reason,
        files_changed=changed,
        fixture_unchanged=unchanged,
        duration_ms=result.duration_ms,
    )
    return result.model_copy(update={"trace": tracer.redacted_events()})


def _final_tests(events: list[dict[str, Any]]) -> TestSummary:
    for event in reversed(events):
        if (
            event.get("event") == "tool_end"
            and event.get("tool") == "run_tests"
            and event.get("ok")
        ):
            r = event.get("result") or {}
            if r.get("selector") is None:
                return TestSummary(
                    passed=r.get("passed"),
                    tests_run=r.get("tests_run"),
                    failures=r.get("failures"),
                    status=r.get("status"),
                )
    return TestSummary()
