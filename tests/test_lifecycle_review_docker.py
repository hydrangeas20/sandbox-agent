"""Docker-backed lifecycle review (PR #6 review: SA-01, SA-02 and cleanup paths).

SA-01: a run whose cancellation (or deadline) is already due must never start the
container, so no untrusted instruction can execute. SA-02: a stop that races with the
workload's own exit is attributed by a documented precedence and never reports
success without a valid supervisor exit report.
"""

from __future__ import annotations

import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

import pytest

import sandbox_agent.sandbox as sb
from sandbox_agent.config import SandboxConfig
from sandbox_agent.errors import SandboxIsolationError, SandboxUnavailableError
from sandbox_agent.sandbox import ContainerCommand, DockerSandbox, RunControl

pytestmark = pytest.mark.docker

DOCKER = shutil.which("docker") or "docker"
MARKER = "UNTRUSTED-RAN"
# The workload's first action is an observable effect: one line on stdout.
MARK_THEN_SLEEP = ContainerCommand(
    argv=("python3", "-c", f"import sys; sys.stdout.write('{MARKER}\\n'); sys.stdout.flush()\n"
          "import time; time.sleep(5)")
)  # fmt: skip
EXIT_AT_ONCE = ContainerCommand(argv=("python3", "-c", "print('done')"))


def managed() -> list[str]:
    out = subprocess.run(
        [DOCKER, "ps", "-aq", "--filter", "label=sandbox-agent.managed=1"],
        capture_output=True,
        text=True,
        check=True,
    )
    return out.stdout.split()


@pytest.fixture
def ws(tmp_path: Path) -> Path:
    path = tmp_path / "wsroot" / "ws"
    path.mkdir(parents=True)
    return path


@pytest.fixture
def record(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Record every docker CLI verb; make `kill` slow, like a loaded daemon.

    The slow kill makes the pre-fix behaviour deterministic: if the container is ever
    started, the workload has a full second to execute before it is stopped.
    """
    verbs: list[str] = []
    original_cli = DockerSandbox._cli

    def cli(self: DockerSandbox, *args: str, **kw: Any) -> Any:
        verbs.append(args[0])
        if args[0] == "kill":
            time.sleep(1.0)
        return original_cli(self, *args, **kw)

    original_popen = subprocess.Popen

    def popen(argv: list[str], *a: Any, **kw: Any) -> Any:
        verbs.append(f"{argv[1]} {argv[2]}")  # e.g. "start --attach"
        return original_popen(argv, *a, **kw)

    monkeypatch.setattr(DockerSandbox, "_cli", cli)
    monkeypatch.setattr(sb.subprocess, "Popen", popen)
    return verbs


def box(ws: Path, timeout_s: float = 20.0) -> DockerSandbox:
    return DockerSandbox(SandboxConfig(timeout_s=timeout_s), ws.parent)


# ---------------------------------------------------------------- SA-01 pre-start


def test_sa01_precancelled_run_executes_nothing(ws: Path, record: list[str]) -> None:
    cancel = threading.Event()
    cancel.set()
    out = box(ws).run(ws, MARK_THEN_SLEEP, RunControl(cancel=cancel))
    assert MARKER not in out.stdout, "untrusted workload executed after cancellation"
    assert "start --attach" not in record
    assert "create" not in record  # nothing is even created
    assert out.status == "cancelled"
    assert out.started is False
    assert out.attestation is None
    assert managed() == []


def test_sa01_cancel_during_creation_never_starts(
    ws: Path, record: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    cancel = threading.Event()
    slow_cli = DockerSandbox._cli  # the recording wrapper installed by `record`

    def cli(self: DockerSandbox, *args: str, **kw: Any) -> Any:
        result = slow_cli(self, *args, **kw)
        if args[0] == "create":
            cancel.set()  # cancellation arrives while the container is being created
        return result

    monkeypatch.setattr(DockerSandbox, "_cli", cli)
    out = box(ws).run(ws, MARK_THEN_SLEEP, RunControl(cancel=cancel))
    assert MARKER not in out.stdout
    assert "start --attach" not in record
    assert "rm" in record  # the created container is still removed
    assert out.status == "cancelled"
    assert out.started is False
    assert managed() == []


def test_sa01_deadline_already_passed_starts_nothing(ws: Path, record: list[str]) -> None:
    out = box(ws).run(ws, MARK_THEN_SLEEP, RunControl(deadline=time.monotonic() - 1))
    assert MARKER not in out.stdout
    assert "create" not in record
    assert out.status == "timeout"
    assert out.started is False
    assert managed() == []


def test_sa01_deadline_passing_during_creation_never_starts(
    ws: Path, record: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    slow_cli = DockerSandbox._cli
    deadline = time.monotonic() + 0.2

    def cli(self: DockerSandbox, *args: str, **kw: Any) -> Any:
        result = slow_cli(self, *args, **kw)
        if args[0] == "create":
            time.sleep(max(0.0, deadline - time.monotonic()) + 0.05)
        return result

    monkeypatch.setattr(DockerSandbox, "_cli", cli)
    out = box(ws).run(ws, MARK_THEN_SLEEP, RunControl(deadline=deadline))
    assert MARKER not in out.stdout
    assert "start --attach" not in record
    assert "rm" in record
    assert out.status == "timeout"
    assert out.started is False
    assert managed() == []


def test_sa01_cancel_right_after_start_reports_cancelled(
    ws: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cancellation during execution, possibly before PID 1 attested, is `cancelled`.

    Before the fix this path crashed with a pydantic ValidationError (attestation None)
    in roughly 40% of runs.
    """
    original_popen = subprocess.Popen
    cancel = threading.Event()

    def popen(argv: list[str], *a: Any, **kw: Any) -> Any:
        proc = original_popen(argv, *a, **kw)
        if argv[1] == "start":
            cancel.set()  # immediately after the container is started
        return proc

    monkeypatch.setattr(sb.subprocess, "Popen", popen)
    statuses = []
    for _ in range(10):
        cancel.clear()
        out = box(ws).run(ws, MARK_THEN_SLEEP, RunControl(cancel=cancel))
        statuses.append(out.status)
        assert out.started is True
        assert out.exit_code is None
    assert statuses == ["cancelled"] * 10
    assert managed() == []


# ---------------------------------------------------------------- SA-02 attribution


@pytest.mark.parametrize("delay", [0.0, 0.05, 0.1, 0.2, 0.3, 0.5])
def test_sa02_near_simultaneous_exit_and_cancel(ws: Path, delay: float) -> None:
    """Whatever wins the race, success is reported only with a valid exit report."""
    cancel = threading.Event()
    timer = threading.Timer(delay, cancel.set)
    timer.start()
    try:
        out = box(ws).run(ws, EXIT_AT_ONCE, RunControl(cancel=cancel))
    finally:
        timer.cancel()
    assert out.status in {"completed", "cancelled"}, out.status
    if out.status == "completed":
        assert out.exit_report is not None
        assert out.exit_report["exit_code"] == 0
        assert out.exit_code == 0
        assert out.attestation
    else:
        assert out.exit_code is None
    assert managed() == []


def test_sa02_cancel_after_completion_is_completed(ws: Path) -> None:
    cancel = threading.Event()
    out = box(ws).run(ws, EXIT_AT_ONCE, RunControl(cancel=cancel))
    cancel.set()
    assert out.status == "completed"
    assert out.exit_report is not None


# ---------------------------------------------------------------- cleanup and failures


def test_daemon_failure_during_stop_reaps_the_cli_and_removes_the_container(
    ws: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    procs: list[subprocess.Popen[bytes]] = []
    original_popen = subprocess.Popen
    original_cli = DockerSandbox._cli

    def popen(argv: list[str], *a: Any, **kw: Any) -> Any:
        proc = original_popen(argv, *a, **kw)
        procs.append(proc)
        return proc

    def cli(self: DockerSandbox, *args: str, **kw: Any) -> Any:
        if args[0] == "kill":
            raise SandboxUnavailableError("docker kill failed: timed out")
        return original_cli(self, *args, **kw)

    monkeypatch.setattr(sb.subprocess, "Popen", popen)
    monkeypatch.setattr(DockerSandbox, "_cli", cli)
    cancel = threading.Event()
    threading.Timer(1.0, cancel.set).start()
    with pytest.raises(SandboxUnavailableError):
        box(ws).run(ws, MARK_THEN_SLEEP, RunControl(cancel=cancel))
    attach = [p for p in procs if p.args[1] == "start"]
    assert attach, "docker start was never invoked"
    assert attach[0].returncode is not None, "docker start --attach left running/unreaped"
    assert managed() == []


def test_inspect_failure_after_run_fails_closed_and_cleans_up(
    ws: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_inspect = DockerSandbox._inspect
    calls = {"n": 0}

    def inspect(self: DockerSandbox, container_id: str) -> Any:
        calls["n"] += 1
        if calls["n"] == 2:  # the post-run state inspection
            raise SandboxIsolationError("docker inspect failed: daemon unavailable")
        return original_inspect(self, container_id)

    monkeypatch.setattr(DockerSandbox, "_inspect", inspect)
    with pytest.raises(SandboxIsolationError, match="inspect failed") as info:
        box(ws).run(ws, EXIT_AT_ONCE)
    diag = info.value.diagnostics
    assert diag is not None
    assert diag["phase"] == "post_run_inspect"
    assert diag["cleanup"] == "removed"
    assert managed() == []


def test_unexpected_exception_while_parsing_still_removes_the_container(
    ws: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*_a: Any, **_kw: Any) -> Any:
        raise RuntimeError("unexpected")

    monkeypatch.setattr(sb, "_take_marker", boom)
    with pytest.raises(RuntimeError):
        box(ws).run(ws, EXIT_AT_ONCE)
    assert managed() == []


def test_pid1_assumption_enforced_when_docker_injects_an_init(
    ws: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With `--init`, tini is PID 1 and the entrypoint is not: attestation must refuse."""
    original = DockerSandbox.build_create_args

    def with_init(self: DockerSandbox, *a: Any, **kw: Any) -> list[str]:
        args = original(self, *a, **kw)
        return [args[0], "--init", *args[1:]]  # "create", "--init", ...

    monkeypatch.setattr(DockerSandbox, "build_create_args", with_init)
    with pytest.raises(SandboxIsolationError, match="attestation failed") as info:
        box(ws).run(ws, MARK_THEN_SLEEP)
    # SA-03: an attestation failure carries bounded diagnostics, including which check.
    diag = info.value.diagnostics
    assert diag is not None
    assert diag["phase"] == "attestation"
    assert diag["attestation"]["status"] == "failed"
    assert "expected 1" in diag["attestation"]["detail"]  # "entrypoint is pid N, expected 1"
    assert diag["exit_code"] == 121
    assert diag["state"]["Status"] == "exited"
    assert len(diag["container_id"]) == 12
    assert "attest-failed" in diag["stderr_head"]
    assert diag["cleanup"] == "removed"
    assert MARKER not in str(info.value)  # the workload never ran
    assert len(str(info.value)) < 2600
    assert managed() == []


def test_external_kill_of_pid1_fails_closed_with_diagnostics(
    ws: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Something outside the sandbox SIGKILLs PID 1 mid-run: never a success."""
    original_popen = subprocess.Popen

    def popen(argv: list[str], *a: Any, **kw: Any) -> Any:
        proc = original_popen(argv, *a, **kw)
        if argv[1] == "start":
            container_id = argv[-1]
            threading.Timer(
                1.0, subprocess.run, args=([DOCKER, "kill", container_id],),
                kwargs={"capture_output": True, "check": False},
            ).start()  # fmt: skip
        return proc

    monkeypatch.setattr(sb.subprocess, "Popen", popen)
    with pytest.raises(SandboxIsolationError, match="exit report") as info:
        box(ws).run(ws, MARK_THEN_SLEEP)
    diag = info.value.diagnostics
    assert diag is not None
    assert diag["phase"] == "exit_evidence"
    assert diag["exit_report"] == "missing"
    assert diag["attestation"]["status"] == "present"
    assert diag["exit_code"] == 137
    assert "stderr_head" not in diag  # the workload ran: no output in diagnostics
    assert MARKER not in str(info.value)
    assert diag["cleanup"] == "removed"
    assert managed() == []
