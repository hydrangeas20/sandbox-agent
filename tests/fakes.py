"""Test doubles. FakeRunner records commands and returns canned outcomes; it executes nothing."""

from __future__ import annotations

from pathlib import Path

from sandbox_agent.sandbox import ContainerCommand, RunOutcome


def outcome(exit_code: int = 0, stderr: str = "Ran 1 test in 0.001s\n\nOK\n") -> RunOutcome:
    return RunOutcome(
        status="completed",
        exit_code=exit_code,
        stdout="",
        stderr=stderr,
        stdout_truncated=False,
        stderr_truncated=False,
        stdout_bytes_total=0,
        stderr_bytes_total=len(stderr),
        duration_ms=5,
        container="fake",
    )


class FakeRunner:
    def __init__(self, outcomes: list[RunOutcome] | None = None) -> None:
        self.calls: list[tuple[Path, ContainerCommand]] = []
        self._outcomes = list(outcomes or [])

    def run(self, workspace_dir: Path, command: ContainerCommand) -> RunOutcome:
        self.calls.append((workspace_dir, command))
        return self._outcomes.pop(0) if self._outcomes else outcome()
