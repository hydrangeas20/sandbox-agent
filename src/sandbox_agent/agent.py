"""Bounded, provider-neutral agent controller.

The controller owns every budget and the final status. The model can only
propose one :class:`AgentAction` per iteration; it cannot extend budgets,
declare success, or reach anything but :class:`ToolExecutor`.
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, ValidationError

from sandbox_agent.config import AgentBudget
from sandbox_agent.errors import ProviderError
from sandbox_agent.providers.base import AgentAction, Provider, Transcript, Turn
from sandbox_agent.tools import ToolExecutor, ToolResult
from sandbox_agent.trace import Tracer

TaskStatus = Literal[
    "succeeded",
    "failed",
    "budget_exhausted",
    "policy_aborted",
    "cancelled",
    "provider_error",
    "sandbox_error",
]


class AgentRunResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    status: TaskStatus
    reason: str
    iterations: int
    tool_calls: int
    policy_denials: int
    invalid_outputs: int
    patches_applied: int
    final_tests_passed: bool | None
    summary: str | None


class AgentController:
    def __init__(
        self,
        provider: Provider,
        tools: ToolExecutor,
        budget: AgentBudget,
        tracer: Tracer,
        *,
        cancel: threading.Event | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.provider = provider
        self.tools = tools
        self.budget = budget
        self.tracer = tracer
        self.cancel = cancel or threading.Event()
        self.clock = clock

    # One linear loop with explicit exits is deliberately kept in a single function:
    # every budget check and terminal state is visible in one place for review.
    def run(self, task: str) -> AgentRunResult:  # noqa: PLR0911, PLR0912, PLR0915
        b = self.budget
        transcript = Transcript(task=task)
        started = self.clock()
        iterations = tool_calls = denials = invalid = patches = 0
        # Success requires a *full-suite* pass recorded after the most recent patch.
        tests_passed_since_patch: bool | None = None

        def done(status: TaskStatus, reason: str, summary: str | None = None) -> AgentRunResult:
            result = AgentRunResult(
                status=status,
                reason=reason,
                iterations=iterations,
                tool_calls=tool_calls,
                policy_denials=denials,
                invalid_outputs=invalid,
                patches_applied=patches,
                final_tests_passed=tests_passed_since_patch,
                summary=summary,
            )
            self.tracer.emit("agent_end", **result.model_dump())
            return result

        self.tracer.emit("agent_start", provider=self.provider.name, budget=b.model_dump())
        while True:
            if self.cancel.is_set():
                return done("cancelled", "cancellation requested")
            if iterations >= b.max_iterations:
                return done("budget_exhausted", f"max_iterations={b.max_iterations} reached")
            if self.clock() - started > b.max_wall_clock_s:
                return done("budget_exhausted", f"max_wall_clock_s={b.max_wall_clock_s} exceeded")
            iterations += 1

            t0 = self.clock()
            try:
                raw = self.provider.next_action(transcript)
                action = AgentAction.model_validate(raw)
            except (ProviderError, ValidationError) as exc:
                invalid += 1
                message = _describe_invalid(exc)
                self.tracer.emit(
                    "invalid_provider_output",
                    iteration=iterations,
                    error=message,
                    duration_ms=_ms(self.clock() - t0),
                )
                transcript.add(Turn("invalid", {"error": message}))
                if invalid > b.max_invalid_outputs:
                    return done("provider_error", f"{invalid} invalid provider outputs")
                continue
            self.tracer.emit(
                "provider_action",
                iteration=iterations,
                tool=action.tool,
                args=action.args,
                thought=action.thought,
                duration_ms=_ms(self.clock() - t0),
            )

            if self.cancel.is_set():
                return done("cancelled", "cancellation requested")

            call_id = action.call_id or f"call_{iterations}"
            transcript.add(Turn("action", {"tool": action.tool, "args": action.args}, call_id))

            if action.tool == "finish":
                result = self.tools.execute("finish", action.args)
                if not result.ok:
                    self._observe(transcript, result, call_id, iterations, 0)
                    invalid += 1
                    if invalid > b.max_invalid_outputs:
                        return done("provider_error", "invalid finish arguments")
                    continue
                summary = str(result.output.get("summary", ""))
                if patches > 0 and tests_passed_since_patch is True:
                    return done("succeeded", "full test suite passed after last patch", summary)
                if patches == 0:
                    return done("failed", "finished without applying a patch", summary)
                return done("failed", "finished without a passing full test run", summary)

            if tool_calls >= b.max_tool_calls:
                return done("budget_exhausted", f"max_tool_calls={b.max_tool_calls} reached")
            tool_calls += 1

            t1 = self.clock()
            self.tracer.emit("tool_start", iteration=iterations, tool=action.tool, call_id=call_id)
            result = self.tools.execute(action.tool, action.args)
            elapsed = _ms(self.clock() - t1)
            self._observe(transcript, result, call_id, iterations, elapsed)

            if result.ok and action.tool == "apply_patch":
                patches += 1
                tests_passed_since_patch = None
            elif result.ok and action.tool == "run_tests":
                if result.output.get("selector") is None:
                    tests_passed_since_patch = bool(result.output.get("passed"))
            elif result.error_kind == "policy_denial":
                denials += 1
                self.tracer.emit(
                    "policy_denial",
                    iteration=iterations,
                    tool=action.tool,
                    rule=result.denied_rule,
                    detail=result.error,
                )
                if denials >= b.max_policy_denials:
                    return done("policy_aborted", f"{denials} policy denials")
            elif result.error_kind == "execution_error" and action.tool == "run_tests":
                return done("sandbox_error", result.error or "sandbox failure")

    def _observe(
        self, transcript: Transcript, result: ToolResult, call_id: str, iteration: int, ms: int
    ) -> None:
        payload = result.model_dump(exclude_none=True)
        text = json.dumps(payload)
        limit = self.budget.max_observation_chars
        if len(text) > limit:
            payload = {
                "tool": result.tool,
                "ok": result.ok,
                "truncated_observation": text[:limit],
            }
        resources = result.output.get("resources") if result.ok else None
        self.tracer.emit(
            "tool_end",
            iteration=iteration,
            tool=result.tool,
            call_id=call_id,
            ok=result.ok,
            error_kind=result.error_kind,
            denied_rule=result.denied_rule,
            duration_ms=ms,
            resources=resources,
            result=_summarize(result),
        )
        transcript.add(Turn("observation", payload, call_id))


def _ms(seconds: float) -> int:
    return int(seconds * 1000)


def _describe_invalid(exc: Exception) -> str:
    if isinstance(exc, ValidationError):
        errs = exc.errors()[:3]
        return "; ".join(f"{'.'.join(map(str, e['loc'])) or '<root>'}: {e['msg']}" for e in errs)
    return str(exc)[:500]


def _summarize(result: ToolResult) -> dict[str, Any]:
    """Compact, trace-friendly view of a result (full file contents are not traced)."""
    out = result.output
    if not result.ok:
        return {"error": (result.error or "")[:500]}
    if result.tool == "read_file":
        return {"path": out.get("path"), "total_lines": out.get("total_lines")}
    if result.tool == "search":
        return {"matches": len(out.get("matches", [])), "truncated": out.get("truncated")}
    if result.tool == "list_files":
        return {"entries": len(out.get("entries", []))}
    if result.tool == "run_tests":
        keys = ("command", "selector", "passed", "status", "exit_code", "tests_run", "failures")
        return {k: out.get(k) for k in keys}
    return dict(out)
