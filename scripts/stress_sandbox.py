"""Bounded stress run for sandbox start-up, attestation and lifecycle (SA-03).

Runs each scenario a fixed number of times against the real Docker sandbox, checks the
evidence invariants on every run, and records any failure with its diagnostics:

    uv run python scripts/stress_sandbox.py --runs 50 --out runs/stress.json

Invariants:

* a ``completed`` outcome has a valid attestation and a valid exit report;
* a not-started outcome (``started: false``) has no output and no attestation;
* nothing is reported as ``completed`` when PID 1 was killed from outside;
* no managed container is left behind.

Counts are bounded (``--runs`` <= 500 per scenario). Nothing here uses the network or a
paid service.
"""

from __future__ import annotations

import argparse
import json
import multiprocessing
import platform
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from collections import Counter
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from sandbox_agent.config import SandboxConfig
from sandbox_agent.errors import SandboxAgentError, SandboxIsolationError
from sandbox_agent.sandbox import ContainerCommand, DockerSandbox, RunControl, RunOutcome

DOCKER = shutil.which("docker") or "docker"
PY = "python3"
COMMANDS = {
    "rapid_exit": "print(1)",
    "binary_unterminated": (
        "import os\nos.write(1, bytes(range(256)) * 64)\n"
        "os.write(2, b'\\xff\\xfe no newline at end')"
    ),
    "unterminated_stdout": "import sys; sys.stdout.write('no newline'); sys.stdout.flush()",
    "sleep": "import time; time.sleep(5)",
}


def environment() -> dict[str, Any]:
    def run(*args: str) -> str:
        try:
            return subprocess.run(
                args, capture_output=True, text=True, check=False, timeout=30
            ).stdout.strip()
        except (OSError, subprocess.TimeoutExpired) as exc:
            return f"error: {exc}"

    return {
        "kernel": platform.release(),
        "python": sys.version.split()[0],
        "cpus": multiprocessing.cpu_count(),
        "docker": run(
            DOCKER,
            "info",
            "--format",
            "{{.ServerVersion}} cgroup=v{{.CgroupVersion}} driver={{.CgroupDriver}} "
            "storage={{.Driver}} runtime={{.DefaultRuntime}}",
        ),
        "image": run(DOCKER, "image", "inspect", "--format", "{{.Id}}", "sandbox-agent-runner:0.1"),
    }


def managed() -> list[str]:
    out = subprocess.run(
        [DOCKER, "ps", "-aq", "--filter", "label=sandbox-agent.managed=1"],
        capture_output=True, text=True, check=False,
    )  # fmt: skip
    return out.stdout.split()


class Recorder:
    def __init__(self) -> None:
        self.outcomes: Counter[str] = Counter()
        self.failures: list[dict[str, Any]] = []
        self.violations: list[str] = []
        self.lock = threading.Lock()

    def record(self, name: str, fn: Callable[[], RunOutcome], expect: set[str]) -> None:
        try:
            out = fn()
        except SandboxIsolationError as exc:
            key = f"SandboxIsolationError:{(exc.diagnostics or {}).get('phase', 'unknown')}"
            with self.lock:
                self.outcomes[key] += 1
                if key not in expect:
                    self.failures.append({"scenario": name, "error": str(exc)[:2500]})
            return
        except SandboxAgentError as exc:
            with self.lock:
                self.outcomes[type(exc).__name__] += 1
                self.failures.append({"scenario": name, "error": str(exc)[:1000]})
            return
        problems = []
        if out.status == "completed" and (not out.attestation or out.exit_report is None):
            problems.append("completed without attestation/exit report")
        if not out.started and (out.stdout or out.stderr or out.attestation):
            problems.append("not-started run has output or attestation")
        key = out.status if out.started else f"{out.status}(not started)"
        with self.lock:
            self.outcomes[key] += 1
            self.violations += [f"{name}: {p}" for p in problems]
            if key not in expect:
                self.failures.append({"scenario": name, "status": key, "exit": out.exit_code})


def scenarios(box: DockerSandbox, ws: Path, runs: int, rec: Recorder) -> None:
    def cmd(key: str) -> ContainerCommand:
        return ContainerCommand(argv=(PY, "-c", COMMANDS[key]))

    for key in ("rapid_exit", "binary_unterminated", "unterminated_stdout"):
        for _ in range(runs):
            rec.record(key, lambda k=key: box.run(ws, cmd(k)), {"completed"})

    def concurrent_round() -> None:
        dirs = []
        for i in range(4):
            d = Path(tempfile.mkdtemp(prefix="stress-", dir="/tmp")) / f"ws{i}"
            d.mkdir()
            dirs.append(d)
        with ThreadPoolExecutor(max_workers=4) as pool:
            for d in dirs:
                b = DockerSandbox(box.config, d.parent)
                pool.submit(
                    rec.record,
                    "concurrent",
                    lambda b=b, d=d: b.run(d, cmd("binary_unterminated")),
                    {"completed"},
                )

    for _ in range(max(1, runs // 4)):
        concurrent_round()

    def cancel_after(delay: float) -> RunOutcome:
        cancel = threading.Event()
        threading.Timer(delay, cancel.set).start()
        return box.run(ws, cmd("sleep"), RunControl(cancel=cancel))

    # Delays chosen to land during creation, around start, and while running.
    delays = (0.05, 0.2, 0.4, 0.6)
    for i in range(runs):
        rec.record(
            "cancel_during_startup",
            lambda d=delays[i % 4]: cancel_after(d),
            {"cancelled", "cancelled(not started)"},
        )

    def external_kill() -> RunOutcome:
        original = subprocess.Popen

        def popen(argv: list[str], *a: Any, **kw: Any) -> Any:
            proc = original(argv, *a, **kw)
            if len(argv) > 2 and argv[1] == "start":
                kill = [DOCKER, "kill", argv[-1]]
                threading.Timer(
                    0.5, subprocess.run, args=(kill,), kwargs={"capture_output": True}
                ).start()
            return proc

        subprocess.Popen = popen  # type: ignore[misc]
        try:
            return box.run(ws, cmd("sleep"))
        finally:
            subprocess.Popen = original  # type: ignore[misc]

    for _ in range(max(1, runs // 5)):
        rec.record(
            "external_kill_pid1",
            external_kill,
            {"SandboxIsolationError:exit_evidence", "SandboxIsolationError:attestation"},
        )


def _burn(stop: Any) -> None:
    while not stop.is_set():
        pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--runs", type=int, default=25, help="runs per scenario (<= 500)")
    parser.add_argument("--cpu-load", type=int, default=0, help="busy processes during the run")
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args()
    if not 1 <= args.runs <= 500 or not 0 <= args.cpu_load <= 32:
        parser.error("--runs must be 1..500 and --cpu-load 0..32")

    stop = multiprocessing.Event()
    burners = [multiprocessing.Process(target=_burn, args=(stop,)) for _ in range(args.cpu_load)]
    for p in burners:
        p.start()
    started = time.monotonic()
    rec = Recorder()
    try:
        ws = Path(tempfile.mkdtemp(prefix="stress-", dir="/tmp")) / "ws"
        ws.mkdir()
        box = DockerSandbox(SandboxConfig(timeout_s=20.0), ws.parent)
        scenarios(box, ws, args.runs, rec)
    finally:
        stop.set()
        for p in burners:
            p.join()
    leftovers = managed()
    summary = {
        "environment": environment(),
        "runs_per_scenario": args.runs,
        "cpu_load_processes": args.cpu_load,
        "duration_s": round(time.monotonic() - started, 1),
        "outcomes": dict(sorted(rec.outcomes.items())),
        "unexpected": rec.failures,
        "invariant_violations": rec.violations,
        "leftover_containers": leftovers,
    }
    text = json.dumps(summary, indent=2)
    print(text)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text + "\n")
    return 1 if rec.failures or rec.violations or leftovers else 0


if __name__ == "__main__":
    raise SystemExit(main())
