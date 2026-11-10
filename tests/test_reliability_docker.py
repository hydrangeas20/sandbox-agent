"""Docker-backed execution reliability: cancellation, deadlines, concurrent isolation."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from sandbox_agent.config import AgentBudget, SandboxConfig, Settings
from sandbox_agent.providers.scripted import ScriptedProvider, Step
from sandbox_agent.sandbox import ContainerCommand, DockerSandbox, RunControl
from sandbox_agent.service import TaskRequest, run_task

pytestmark = pytest.mark.docker

DOCKER = shutil.which("docker") or "docker"
SLEEP = ContainerCommand(argv=("python3", "-c", "import time; time.sleep(60)"))
HANG = {"tool": "run_tests", "args": {"command": "unittest", "selector": "tests.test_hang"}}
FINISH = {"tool": "finish", "args": {"summary": "done"}}


def managed() -> list[str]:
    out = subprocess.run(
        [DOCKER, "ps", "-aq", "--filter", "label=sandbox-agent.managed=1"],
        capture_output=True,
        text=True,
        check=True,
    )
    return out.stdout.split()


def workspaces() -> set[str]:
    return {p.name for p in Path(tempfile.gettempdir()).glob("sandbox-agent-*")}


@pytest.fixture
def ws(tmp_path: Path) -> Path:
    path = tmp_path / "wsroot" / "ws"
    path.mkdir(parents=True)
    return path


@pytest.fixture
def settings(fixtures_dir: Path, tmp_path: Path) -> Settings:
    return Settings(fixtures_dir=fixtures_dir, runs_dir=tmp_path / "runs", offline=True)


# ---------------------------------------------------------------- sandbox level


def test_cancel_stops_a_running_container_promptly(ws: Path) -> None:
    sandbox = DockerSandbox(SandboxConfig(timeout_s=30.0), ws.parent)
    cancel = threading.Event()
    threading.Timer(1.5, cancel.set).start()
    started = time.monotonic()
    out = sandbox.run(ws, SLEEP, RunControl(cancel=cancel))
    elapsed = time.monotonic() - started
    assert out.status == "cancelled", out.status
    assert out.exit_code is None
    assert 1.4 <= elapsed < 6, f"took {elapsed:.1f}s against a 30 s timeout"
    assert managed() == []


def test_cancel_set_before_start_never_runs_the_workload(ws: Path) -> None:
    sandbox = DockerSandbox(SandboxConfig(timeout_s=30.0), ws.parent)
    cancel = threading.Event()
    cancel.set()
    out = sandbox.run(ws, SLEEP, RunControl(cancel=cancel))
    assert out.status == "cancelled"
    assert out.started is False  # the container was never started (see SA-01 tests)
    assert out.attestation is None
    assert managed() == []


def test_caller_deadline_earlier_than_timeout_stops_the_run(ws: Path) -> None:
    sandbox = DockerSandbox(SandboxConfig(timeout_s=30.0), ws.parent)
    started = time.monotonic()
    out = sandbox.run(ws, SLEEP, RunControl(deadline=started + 1.5))
    elapsed = time.monotonic() - started
    assert out.status == "timeout", out.status
    assert 1.4 <= elapsed < 6, f"took {elapsed:.1f}s against a 30 s timeout"
    assert managed() == []


def test_concurrent_runs_are_isolated(tmp_path: Path) -> None:
    """Parallel runs see only their own workspace and leave nothing behind."""
    n = 4
    dirs = []
    for i in range(n):
        d = tmp_path / f"root{i}" / "ws"
        d.mkdir(parents=True)
        (d / "token.txt").write_text(f"token-{i}\n")
        dirs.append(d)
    code = (
        "import os\n"
        "print(open('/workspace/token.txt').read().strip(), sorted(os.listdir('/workspace')))\n"
    )

    def one(d: Path) -> str:
        sandbox = DockerSandbox(SandboxConfig(timeout_s=30.0), d.parent)
        out = sandbox.run(d, ContainerCommand(argv=("python3", "-c", code)))
        assert out.status == "completed", out.status
        assert out.exit_report is not None
        return out.stdout.strip()

    with ThreadPoolExecutor(max_workers=n) as pool:
        results = list(pool.map(one, dirs))
    assert results == [f"token-{i} ['token.txt']" for i in range(n)]
    assert managed() == []


# ---------------------------------------------------------------- task level


def test_task_cancelled_during_a_hanging_test_run(settings: Settings) -> None:
    before = workspaces()
    cancel = threading.Event()
    threading.Timer(2.0, cancel.set).start()
    started = time.monotonic()
    result = run_task(
        TaskRequest(fixture="hostile", task="run the hanging test"),
        settings,
        sandbox_config=SandboxConfig(timeout_s=30.0),
        provider_factory=lambda _r: ScriptedProvider([Step(HANG), Step(FINISH)]),
        cancel=cancel,
    )
    elapsed = time.monotonic() - started
    assert result.status == "cancelled", (result.status, result.reason)
    assert elapsed < 10, f"cancellation took {elapsed:.1f}s against a 30 s timeout"
    assert result.fixture_unchanged
    assert managed() == []
    assert workspaces() <= before


def test_wall_clock_budget_bounds_a_hanging_test_run(settings: Settings) -> None:
    started = time.monotonic()
    result = run_task(
        TaskRequest(
            fixture="hostile",
            task="run the hanging test",
            budget=AgentBudget(max_wall_clock_s=4.0),
        ),
        settings,
        sandbox_config=SandboxConfig(timeout_s=30.0),
        provider_factory=lambda _r: ScriptedProvider([Step(HANG), Step(FINISH)]),
    )
    elapsed = time.monotonic() - started
    assert result.status == "budget_exhausted", (result.status, result.reason)
    assert "max_wall_clock_s" in result.reason
    assert elapsed < 12, f"wall-clock budget of 4 s overrun: {elapsed:.1f}s"
    assert managed() == []
