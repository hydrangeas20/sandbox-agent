"""End-to-end task orchestration: fixture -> workspace -> agent -> diff -> integrity check."""

from __future__ import annotations

import threading
import time
import uuid
from collections.abc import Callable
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from sandbox_agent.agent import AgentController, AgentRunResult, TaskStatus
from sandbox_agent.config import (
    AgentBudget,
    ModelBudget,
    SandboxConfig,
    Settings,
    WorkspaceLimits,
)
from sandbox_agent.diffing import diff_policy_violations, unified_diff
from sandbox_agent.errors import (
    FixtureError,
    PolicyViolation,
    ProviderError,
    SandboxIsolationError,
    SandboxUnavailableError,
    WorkspaceError,
)
from sandbox_agent.policy import protected_reason
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
    model: str | None = Field(default=None, max_length=64, pattern=r"^[a-z0-9][a-z0-9.\-]*$")
    model_budget: ModelBudget = Field(default_factory=ModelBudget)


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
    #: Final contents of changed files (only with ``capture_changed_files=True``; used by
    #: the evaluation harness to run held-out tests on the agent's result).
    changed_files: dict[str, str] | None = None
    #: Real-model usage (tokens, estimated cost, latency); ``None`` for scripted runs.
    model_usage: dict[str, Any] | None = None
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
        from sandbox_agent.providers.anthropic import (  # noqa: PLC0415
            DEFAULT_MODEL,
            AnthropicProvider,
        )

        return AnthropicProvider(model=req.model or DEFAULT_MODEL, budget=req.model_budget)

    return make


def run_task(  # noqa: PLR0915 - linear orchestration with explicit fail-closed branches
    req: TaskRequest,
    settings: Settings,
    *,
    sandbox_config: SandboxConfig | None = None,
    workspace_limits: WorkspaceLimits | None = None,
    provider_factory: ProviderFactory | None = None,
    cancel: threading.Event | None = None,
    capture_changed_files: bool = False,
) -> TaskResult:
    task_id = uuid.uuid4().hex
    tracer = Tracer(task_id)
    reaped_workspaces = Workspace.reap_stale()
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
        reaped_workspaces=reaped_workspaces,
    )
    factory = provider_factory or default_provider_factory(settings)

    agent_result: AgentRunResult | None = None
    status: TaskStatus
    reason: str
    provider_label: str = req.provider
    provider: Provider | None = None
    diff: str = ""
    changed: list[str] = []
    changed_files: dict[str, str] | None = None
    try:
        provider = factory(req)
        provider_label = provider.name
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
            if capture_changed_files:
                changed_files = _read_changed(ws, changed)
            violations = diff_policy_violations(fixture_dir, ws.path, changed)
            if violations:
                status = "policy_aborted"
                reason = "DIFF POLICY VIOLATION: " + "; ".join(violations)
                tracer.emit("diff_policy_violation", violations=violations)
    except (SandboxUnavailableError, SandboxIsolationError) as exc:
        status, reason = "sandbox_error", str(exc)
        tracer.emit("sandbox_error", error=str(exc))
    except ProviderError as exc:
        status, reason = "provider_error", str(exc)
        tracer.emit("provider_error", error=str(exc))
    except (WorkspaceError, FixtureError) as exc:
        status, reason = "failed", f"workspace error: {exc}"
        tracer.emit("workspace_error", error=str(exc))
    except Exception as exc:
        status, reason = "failed", f"internal error ({type(exc).__name__})"
        tracer.emit("internal_error", error_type=type(exc).__name__)

    after = tree_manifest(fixture_dir)
    unchanged = before == after
    if not unchanged:
        status, reason = "failed", "INTEGRITY FAILURE: original fixture was modified"
    final = _final_tests(tracer.events)
    result = TaskResult(
        task_id=task_id,
        fixture=req.fixture,
        provider=provider_label,
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
        model_usage=_model_usage(provider),
        changed_files=changed_files,
        trace=[],
    )
    tracer.emit(
        "task_end",
        status=status,
        reason=reason,
        files_changed=changed,
        fixture_unchanged=unchanged,
        duration_ms=result.duration_ms,
        resources=_resource_summary(tracer.events),
        model_usage=result.model_usage,
    )
    return result.model_copy(update={"trace": tracer.redacted_events()})


def _read_changed(ws: Workspace, changed: list[str]) -> dict[str, str]:
    files: dict[str, str] = {}
    for rel in changed:
        if protected_reason(rel):
            continue
        try:
            files[rel] = ws.read_text(rel)
        except PolicyViolation:
            continue  # deleted/non-regular: reported by the diff gate instead
    return files


def _model_usage(provider: Provider | None) -> dict[str, Any] | None:
    summary = getattr(provider, "usage_summary", None)
    if not callable(summary):
        return None
    value = summary()
    return value if isinstance(value, dict) else None


def _resource_summary(events: list[dict[str, Any]]) -> dict[str, Any]:
    runs = [e for e in events if e.get("event") == "tool_end" and e.get("resources")]
    return {
        "sandbox_runs": len(runs),
        "sandbox_ms": sum(int(e.get("duration_ms") or 0) for e in runs),
        "timeouts": sum(1 for e in runs if e["resources"].get("timed_out")),
        "oom_kills": sum(1 for e in runs if e["resources"].get("oom_killed")),
        "sigkills": sum(1 for e in runs if e["resources"].get("killed")),
        "output_bytes": sum(
            int(e["resources"].get("stdout_bytes", 0)) + int(e["resources"].get("stderr_bytes", 0))
            for e in runs
        ),
        "policy_denials": sum(1 for e in events if e.get("event") == "policy_denial"),
    }


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
