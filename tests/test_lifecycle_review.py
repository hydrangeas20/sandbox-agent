"""Deterministic (no Docker) checks for terminal-state attribution (PR #6 review, SA-02)."""

from __future__ import annotations

import subprocess
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from sandbox_agent.config import SandboxConfig
from sandbox_agent.errors import SandboxIsolationError
from sandbox_agent.sandbox import DockerSandbox, RunControl, RunOutcome, classify_outcome


class FakeProc:
    """Stands in for `docker start --attach`: exits after `exit_after` seconds (or never)."""

    def __init__(self, exit_after: float | None, on_wait: Any = None) -> None:
        self._exit_at = None if exit_after is None else time.monotonic() + exit_after
        self._on_wait = on_wait
        self.returncode: int | None = None

    def _exited(self) -> bool:
        if self._exit_at is not None and time.monotonic() >= self._exit_at:
            self.returncode = 0
        return self.returncode is not None

    def poll(self) -> int | None:
        self._exited()
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        if self._on_wait is not None:
            self._on_wait()
        if self._exited():
            return 0
        if self._exit_at is not None and timeout is not None:
            remaining = self._exit_at - time.monotonic()
            if remaining <= timeout:
                time.sleep(max(remaining, 0))
                self.returncode = 0
                return 0
        if timeout is not None:
            time.sleep(timeout)
        raise subprocess.TimeoutExpired("docker", timeout or 0)


@pytest.fixture
def sandbox(tmp_path: Path) -> DockerSandbox:
    return DockerSandbox(SandboxConfig(timeout_s=5.0), tmp_path, docker_bin="/bin/true")


def wait(sandbox: DockerSandbox, proc: FakeProc, control: RunControl) -> tuple[bool, bool]:
    return sandbox._wait(proc, time.monotonic(), control)  # type: ignore[arg-type]


# ---------------------------------------------------------------- precedence in _wait


def test_exit_already_observed_beats_a_pending_cancel(sandbox: DockerSandbox) -> None:
    cancel = threading.Event()
    cancel.set()
    proc = FakeProc(exit_after=0.0)  # finished before the host looked
    assert wait(sandbox, proc, RunControl(cancel=cancel)) == (False, False)


def test_exit_already_observed_beats_an_expired_deadline(sandbox: DockerSandbox) -> None:
    proc = FakeProc(exit_after=0.0)
    deadline = time.monotonic() - 1
    assert wait(sandbox, proc, RunControl(deadline=deadline)) == (False, False)


def test_cancel_while_running_is_cancelled(sandbox: DockerSandbox) -> None:
    cancel = threading.Event()
    cancel.set()
    assert wait(sandbox, FakeProc(exit_after=None), RunControl(cancel=cancel)) == (False, True)


def test_deadline_while_running_is_a_timeout(sandbox: DockerSandbox) -> None:
    deadline = time.monotonic() + 0.15
    assert wait(sandbox, FakeProc(exit_after=None), RunControl(deadline=deadline)) == (True, False)


def test_exit_and_cancel_in_the_same_wait_slice_is_completion(sandbox: DockerSandbox) -> None:
    """The process exits during the slice in which cancellation is requested."""
    cancel = threading.Event()
    proc = FakeProc(exit_after=0.02, on_wait=cancel.set)
    assert wait(sandbox, proc, RunControl(cancel=cancel)) == (False, False)


def test_cancel_during_a_slice_is_seen_on_the_next_one(sandbox: DockerSandbox) -> None:
    cancel = threading.Event()
    proc = FakeProc(exit_after=None, on_wait=cancel.set)
    started = time.monotonic()
    assert wait(sandbox, proc, RunControl(cancel=cancel)) == (False, True)
    assert time.monotonic() - started < 1.0


# ---------------------------------------------------------------- classification


GOOD_REPORT = {"exit_code": 0, "signal": None, "deadline": False, "oom_kills": 0}


@pytest.mark.parametrize(
    ("flags", "report", "expected"),
    [
        ({}, GOOD_REPORT, "completed"),
        ({"cancelled": True}, GOOD_REPORT, "cancelled"),  # host stop decided first wins
        ({"timed_out": True, "cancelled": False}, GOOD_REPORT, "timeout"),
        ({}, {**GOOD_REPORT, "deadline": True}, "timeout"),
        ({}, {**GOOD_REPORT, "output_limit": True, "signal": 9}, "output_limit"),
        ({"budget_tripped": True}, None, "output_limit"),
        ({"docker_oom": True}, None, "oom_killed"),
        ({}, {**GOOD_REPORT, "exit_code": None, "signal": 9, "oom_kills": 1}, "oom_killed"),
    ],
)
def test_documented_precedence(flags: dict[str, bool], report: Any, expected: str) -> None:
    base = {"timed_out": False, "cancelled": False, "budget_tripped": False, "docker_oom": False}
    assert classify_outcome(**{**base, **flags}, exit_code=0, report=report) == expected


def test_success_requires_the_supervisor_report() -> None:
    with pytest.raises(SandboxIsolationError):
        classify_outcome(
            timed_out=False, cancelled=False, budget_tripped=False, docker_oom=False,
            exit_code=0, report=None,
        )  # fmt: skip


# ---------------------------------------------------------------- outcome model


def test_not_started_outcome_carries_no_execution_evidence() -> None:
    out = RunOutcome.not_started("cancelled", container="c")
    assert out.started is False
    assert out.attestation is None
    assert out.exit_report is None
    assert out.exit_code is None
    assert (out.stdout, out.stderr, out.stdout_bytes_total) == ("", "", 0)
