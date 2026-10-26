"""Structured tool contracts.

Every tool has a Pydantic input model (``extra="forbid"``) and returns a
:class:`ToolResult`. There is deliberately **no** shell or exec tool: the only
way to run code is ``run_tests``, which maps an allowlisted command *name* to a
fixed argv executed in the sandbox.

Error classes are distinct so the controller can budget them separately:

* ``policy_denial`` - the request was understood and refused (path, command,
  unknown tool, size limit). Counts toward ``max_policy_denials``.
* ``invalid_arguments`` - arguments failed schema validation.
* ``execution_error`` - the tool could not complete (e.g. sandbox failure).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from sandbox_agent.config import PatchLimits
from sandbox_agent.errors import PolicyViolation, SandboxAgentError
from sandbox_agent.patch import Edit, apply_patch
from sandbox_agent.policy import ALLOWED_COMMANDS, build_command
from sandbox_agent.sandbox import ContainerCommand, RunOutcome
from sandbox_agent.workspace import Workspace

ErrorKind = Literal["policy_denial", "invalid_arguments", "execution_error"]


class _Args(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ListFilesArgs(_Args):
    path: str = Field(default=".", max_length=255, description="Directory relative to repo root.")


class ReadFileArgs(_Args):
    path: str = Field(max_length=255, description="File path relative to repo root.")
    start_line: int = Field(default=1, ge=1, le=1_000_000)
    max_lines: int = Field(default=400, ge=1, le=2000)


class SearchArgs(_Args):
    query: str = Field(min_length=1, max_length=200, description="Literal substring (not regex).")
    path: str = Field(default=".", max_length=255)


class ApplyPatchArgs(_Args):
    edits: list[Edit] = Field(min_length=1, max_length=200)


class RunTestsArgs(_Args):
    command: str = Field(max_length=64, description=f"One of: {sorted(ALLOWED_COMMANDS)}")
    selector: str | None = Field(default=None, max_length=255)


class FinishArgs(_Args):
    summary: str = Field(max_length=2000)


class ToolResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    tool: str
    ok: bool
    output: dict[str, Any] = Field(default_factory=dict)
    error_kind: ErrorKind | None = None
    error: str | None = None
    denied_rule: str | None = None


class CommandRunner(Protocol):
    def run(self, workspace_dir: Path, command: ContainerCommand) -> RunOutcome: ...


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    args_model: type[_Args]

    def json_schema(self) -> dict[str, Any]:
        return self.args_model.model_json_schema()


TOOL_SPECS: dict[str, ToolSpec] = {
    spec.name: spec
    for spec in (
        ToolSpec("list_files", "List files under a directory of the repository.", ListFilesArgs),
        ToolSpec("read_file", "Read a UTF-8 text file (line-numbered slice).", ReadFileArgs),
        ToolSpec("search", "Find a literal substring in repository text files.", SearchArgs),
        ToolSpec(
            "apply_patch",
            "Apply exact-match edits: each `old` must occur exactly once in `path`.",
            ApplyPatchArgs,
        ),
        ToolSpec(
            "run_tests",
            "Run an allowlisted test command inside the isolated sandbox.",
            RunTestsArgs,
        ),
        ToolSpec(
            "finish", "Stop and report a summary. Status is decided by test results.", FinishArgs
        ),
    )
}

_RAN = re.compile(r"^Ran (\d+) tests? in", re.MULTILINE)
_FAILED = re.compile(r"^FAILED \(([^)]*)\)", re.MULTILINE)


@dataclass
class ToolContext:
    workspace: Workspace
    runner: CommandRunner
    patch_limits: PatchLimits = field(default_factory=PatchLimits)
    tail_chars: int = 4000


class ToolExecutor:
    """Validates and dispatches tool calls. Never raises for model-caused errors."""

    def __init__(self, ctx: ToolContext) -> None:
        self.ctx = ctx

    def execute(self, name: str, raw_args: dict[str, Any]) -> ToolResult:
        spec = TOOL_SPECS.get(name)
        if spec is None:
            return ToolResult(
                tool=name,
                ok=False,
                error_kind="policy_denial",
                denied_rule="tool.unknown",
                error=f"unknown tool {name!r}; available: {sorted(TOOL_SPECS)}",
            )
        try:
            args = spec.args_model.model_validate(raw_args)
        except ValidationError as exc:
            return ToolResult(
                tool=name,
                ok=False,
                error_kind="invalid_arguments",
                error=_short_validation_error(exc),
            )
        try:
            output = getattr(self, f"_tool_{name}")(args)
        except PolicyViolation as exc:
            return ToolResult(
                tool=name,
                ok=False,
                error_kind="policy_denial",
                denied_rule=exc.rule,
                error=str(exc),
            )
        except SandboxAgentError as exc:
            return ToolResult(tool=name, ok=False, error_kind="execution_error", error=str(exc))
        return ToolResult(tool=name, ok=True, output=output)

    # ------------------------------------------------------------------ tools

    def _tool_list_files(self, args: ListFilesArgs) -> dict[str, Any]:
        entries = self.ctx.workspace.list_entries(args.path)
        limit = self.ctx.workspace.limits.max_search_results
        return {
            "entries": [{"path": e.path, "kind": e.kind, "size": e.size} for e in entries[:limit]],
            "truncated": len(entries) > limit,
        }

    def _tool_read_file(self, args: ReadFileArgs) -> dict[str, Any]:
        lines = self.ctx.workspace.read_text(args.path).splitlines()
        start = args.start_line - 1
        chunk = lines[start : start + args.max_lines]
        numbered = "\n".join(f"{start + i + 1:>5}| {line}" for i, line in enumerate(chunk))
        return {
            "path": args.path,
            "content": numbered,
            "total_lines": len(lines),
            "truncated": start + args.max_lines < len(lines),
        }

    def _tool_search(self, args: SearchArgs) -> dict[str, Any]:
        ws = self.ctx.workspace
        limit = ws.limits.max_search_results
        matches: list[dict[str, Any]] = []
        skipped = 0
        for entry in ws.list_entries(args.path):
            if entry.kind != "file":
                continue
            if entry.size > ws.limits.max_file_bytes:
                skipped += 1
                continue
            try:
                text = ws.read_text(entry.path)
            except PolicyViolation:
                skipped += 1
                continue
            for lineno, line in enumerate(text.splitlines(), start=1):
                if args.query in line:
                    matches.append({"path": entry.path, "line": lineno, "text": line[:200]})
                    if len(matches) >= limit:
                        return {"matches": matches, "truncated": True, "skipped_files": skipped}
        return {"matches": matches, "truncated": False, "skipped_files": skipped}

    def _tool_apply_patch(self, args: ApplyPatchArgs) -> dict[str, Any]:
        result = apply_patch(self.ctx.workspace, list(args.edits), self.ctx.patch_limits)
        return result.model_dump()

    def _tool_run_tests(self, args: RunTestsArgs) -> dict[str, Any]:
        command = build_command(args.command, args.selector)
        outcome = self.ctx.runner.run(self.ctx.workspace.path, command)
        combined = outcome.stderr + outcome.stdout
        ran = _RAN.search(combined)
        failed = _FAILED.search(combined)
        passed = outcome.status == "completed" and outcome.exit_code == 0
        return {
            "command": args.command,
            "selector": args.selector,
            "passed": passed,
            "status": outcome.status,
            "exit_code": outcome.exit_code,
            "tests_run": int(ran.group(1)) if ran else None,
            "failures": failed.group(1) if failed else None,
            "duration_ms": outcome.duration_ms,
            "stdout_tail": outcome.stdout[-self.ctx.tail_chars :],
            "stderr_tail": outcome.stderr[-self.ctx.tail_chars :],
            "output_truncated": outcome.stdout_truncated or outcome.stderr_truncated,
            "resources": {
                "container": outcome.container,
                "timed_out": outcome.status == "timeout",
                "oom_killed": outcome.status == "oom_killed",
                "stdout_bytes": outcome.stdout_bytes_total,
                "stderr_bytes": outcome.stderr_bytes_total,
            },
        }

    def _tool_finish(self, args: FinishArgs) -> dict[str, Any]:
        return {"summary": args.summary}


def _short_validation_error(exc: ValidationError) -> str:
    parts = []
    for err in exc.errors()[:5]:
        loc = ".".join(str(p) for p in err["loc"]) or "<root>"
        parts.append(f"{loc}: {err['msg']}")
    return "; ".join(parts)
