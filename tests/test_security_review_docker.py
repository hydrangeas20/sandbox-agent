"""Docker-backed regressions for the Phase 2 security review (docs/SECURITY_REVIEW.md)."""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from sandbox_agent.config import SandboxConfig
from sandbox_agent.errors import SandboxIsolationError
from sandbox_agent.sandbox import ContainerCommand, DockerSandbox, RunOutcome

pytestmark = pytest.mark.docker

DOCKER = shutil.which("docker") or "docker"
LABEL = "label=sandbox-agent.managed=1"


@pytest.fixture
def ws(tmp_path: Path) -> Path:
    path = tmp_path / "wsroot" / "ws"
    path.mkdir(parents=True)
    return path


def run_py(ws: Path, code: str, **cfg: Any) -> RunOutcome:
    sandbox = DockerSandbox(SandboxConfig(**{"timeout_s": 15.0, **cfg}), ws.parent)
    return sandbox.run(ws, ContainerCommand(argv=("python3", "-c", code)))


def managed(*extra: str) -> list[str]:
    out = subprocess.run(
        [DOCKER, "ps", "-q", "--filter", LABEL, *extra], capture_output=True, text=True, check=True
    )
    return out.stdout.split()


SYSCALL_PROBE = """
import ctypes, json, os, platform
libc = ctypes.CDLL(None, use_errno=True)
def call(fn):
    ctypes.set_errno(0); r = fn(); return [r, ctypes.get_errno()]
nr = {"x86_64": 239, "aarch64": 236}[platform.machine()]  # get_mempolicy
print(json.dumps({
    "unshare_userns": call(lambda: libc.unshare(0x10000000)),
    "keyctl": call(lambda: libc.syscall(
        250 if platform.machine() == "x86_64" else 219, 0, 0, 0, 0, 0)),
    "canary": call(lambda: libc.syscall(nr, 0, 0, 0, 0, 0)),
}))
"""


# ============================================================ SR-01 seccomp


def test_sr01_pinned_profile_is_enforced(ws: Path) -> None:
    out = run_py(ws, SYSCALL_PROBE)
    assert out.status == "completed", out
    r = json.loads(out.stdout.strip().splitlines()[-1])
    assert r["unshare_userns"] == [-1, 1]  # EPERM: user namespaces blocked
    assert r["keyctl"] == [-1, 1]
    assert r["canary"] == [-1, 1729]  # only our pinned profile returns this errno
    assert out.attestation["seccomp_canary_errno"] == 1729


def _tamper_seccomp(monkeypatch: pytest.MonkeyPatch, replacement: str) -> None:
    real = DockerSandbox.build_create_args

    def tampered(self: DockerSandbox, *a: Any, **k: Any) -> list[str]:
        args = real(self, *a, **k)
        if any(x.startswith("seccomp=") for x in args):
            return [replacement if x.startswith("seccomp=") else x for x in args]
        return [args[0], "--security-opt", replacement, *args[1:]]

    monkeypatch.setattr(DockerSandbox, "build_create_args", tampered)
    # Simulate a verifier bug or daemon that silently ignores the profile: the
    # runtime attestation inside the container is the remaining line of defence.
    monkeypatch.setattr(DockerSandbox, "verify", lambda self, *a, **k: None)


@pytest.mark.parametrize("profile", ["allow_all", "unconfined"])
def test_sr01_runtime_attestation_catches_weak_seccomp(
    ws: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, profile: str
) -> None:
    if profile == "allow_all":
        path = tmp_path / "allow.json"
        path.write_text('{"defaultAction":"SCMP_ACT_ALLOW"}')
        replacement = f"seccomp={path}"
    else:
        replacement = "seccomp=unconfined"
    _tamper_seccomp(monkeypatch, replacement)
    marker = "UNTRUSTED-CODE-RAN"
    with pytest.raises(SandboxIsolationError, match="attestation"):
        run_py(ws, f"print({marker!r})")
    assert managed("-a") == []


# ============================================================ SR-02 environment


@pytest.fixture(scope="module")
def evil_env_image(tmp_path_factory: pytest.TempPathFactory) -> str:
    ctx = tmp_path_factory.mktemp("evilimg")
    base = SandboxConfig().image
    (ctx / "Dockerfile").write_text(
        f"FROM {base}\nENV LD_PRELOAD=/tmp/evil.so PYTHONPATH=/tmp/inject "
        "AWS_SECRET_ACCESS_KEY=baked-into-image\n"
    )
    tag = "sandbox-agent-evilenv:test"
    subprocess.run([DOCKER, "build", "-q", "-t", tag, str(ctx)], check=True, capture_output=True)
    return tag


def test_sr02_image_with_extra_env_fails_closed(ws: Path, evil_env_image: str) -> None:
    with pytest.raises(SandboxIsolationError, match="env"):
        run_py(ws, "print('ran')", image=evil_env_image)
    with pytest.raises(SandboxIsolationError, match="env"):
        DockerSandbox(SandboxConfig(image=evil_env_image), ws.parent).preflight()


def test_sr02_container_env_is_exactly_configured(ws: Path) -> None:
    out = run_py(ws, "import os, json; print(json.dumps(dict(os.environ)))")
    env = json.loads(out.stdout.strip().splitlines()[-1])
    assert env == dict(SandboxConfig().env)


# ============================================================ SR-04 orphaned containers


def test_sr04_container_stops_when_host_process_dies(ws: Path, tmp_path: Path) -> None:
    script = tmp_path / "orphan.py"
    script.write_text(
        "import sys, pathlib\n"
        "from sandbox_agent.sandbox import DockerSandbox, ContainerCommand\n"
        "from sandbox_agent.config import SandboxConfig\n"
        "ws = pathlib.Path(sys.argv[1])\n"
        "DockerSandbox(SandboxConfig(timeout_s=3), ws.parent).run(ws, "
        "ContainerCommand(argv=('python3', '-c', 'while True: pass')))\n"
    )
    proc = subprocess.Popen([sys.executable, str(script), str(ws)])
    deadline = time.monotonic() + 30
    while not managed() and time.monotonic() < deadline:
        time.sleep(0.2)
    assert managed(), "container never started"
    os.kill(proc.pid, signal.SIGKILL)
    proc.wait()
    # In-container watchdog (PID 1) enforces timeout_s + grace without the host.
    deadline = time.monotonic() + 30
    while managed() and time.monotonic() < deadline:
        time.sleep(0.5)
    assert managed() == [], "container kept running after the host process died"
    # Its owner (the killed process) is gone, so the next controller reaps it at once.
    assert len(managed("-a")) == 1
    assert DockerSandbox(SandboxConfig(), ws.parent).reap_stale() == 1
    assert managed("-a") == []


def test_sr04_pid1_watchdog_cannot_be_killed_or_traced(ws: Path) -> None:
    code = """
import ctypes, json, os, signal
r = {}
try: os.kill(1, signal.SIGKILL); r["kill1"] = "sent"
except OSError as e: r["kill1"] = e.errno
libc = ctypes.CDLL(None, use_errno=True)
r["ptrace_attach"] = [libc.ptrace(16, 1, 0, 0), ctypes.get_errno()]
for p in ("/proc/1/mem", "/proc/1/environ"):
    try: open(p, "rb").read(1); r[p] = "read"
    except OSError as e: r[p] = e.errno
print(json.dumps(r))
"""
    out = run_py(ws, code)
    assert out.status == "completed", out
    r = json.loads(out.stdout.strip().splitlines()[-1])
    assert r["ptrace_attach"][0] == -1
    assert r["/proc/1/mem"] != "read"
    assert r["/proc/1/environ"] != "read"
    # Signals to the namespace init are ignored by the kernel; the watchdog survived
    # and produced its exit report.
    assert out.exit_report is not None


# ============================================================ SR-05 output budget


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_sr05_output_flood_is_stopped_early(ws: Path, stream: str) -> None:
    started = time.monotonic()
    out = run_py(
        ws, f"import sys\nb = 'Z' * (1 << 20)\nwhile True: sys.{stream}.write(b)", timeout_s=20
    )
    elapsed = time.monotonic() - started
    assert out.status == "output_limit", out.status
    assert elapsed < 10, f"flood ran {elapsed:.1f}s"
    total = out.stdout_bytes_total + out.stderr_bytes_total
    assert total < 4 * SandboxConfig().max_total_output_bytes
    assert managed("-a") == []


# ============================================================ SR-13 OOM evidence


def test_sr13_oom_kill_is_attributed_with_cgroup_evidence(ws: Path) -> None:
    out = run_py(
        ws,
        "b = []\nwhile True:\n"
        "    b.append(bytearray(32 << 20)); b[-1][::4096] = b'1' * len(b[-1][::4096])",
    )
    assert out.status == "oom_killed", out
    assert out.exit_report is not None
    assert out.exit_report["signal"] == signal.SIGKILL
    assert out.exit_report["oom_kills"] >= 1
    assert out.exit_report["memory_limit"] == SandboxConfig().memory_bytes


def test_sr13_unrelated_sigkill_is_not_called_oom(ws: Path) -> None:
    out = run_py(ws, "import os, signal\nos.kill(os.getpid(), signal.SIGKILL)")
    assert out.status == "killed", out
    assert out.exit_code == 137
    assert out.exit_report is not None
    assert out.exit_report["oom_kills"] == 0


# ============================================================ SR-04 controller termination (CLI)


def _start_hanging_cli(tmp_path: Path, timeout_s: int) -> subprocess.Popen[bytes]:
    env = {**os.environ, "SANDBOX_AGENT_RUNS": str(tmp_path / "runs")}
    cmd = [sys.executable, "-m", "sandbox_agent.cli", "run", "--fixture", "hostile"]
    cmd += ["--scenario", "hang", "--task", "x", "--timeout", str(timeout_s)]
    proc = subprocess.Popen(cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.monotonic() + 60
    while not managed() and time.monotonic() < deadline:
        assert proc.poll() is None, "controller exited before starting a container"
        time.sleep(0.2)
    assert managed(), "sandbox container never started"
    return proc


def _owned_workspaces(pid: int) -> list[Path]:
    import tempfile  # noqa: PLC0415

    found = []
    for d in Path(tempfile.gettempdir()).glob("sandbox-agent-*"):
        try:
            if (d / ".owner").read_text().split(":")[1] == str(pid):
                found.append(d)
        except (OSError, IndexError):
            continue
    return found


def test_sr04_sigterm_to_controller_cleans_up_promptly(tmp_path: Path) -> None:
    proc = _start_hanging_cli(tmp_path, timeout_s=60)
    assert _owned_workspaces(proc.pid)
    proc.send_signal(signal.SIGTERM)
    assert proc.wait(timeout=30) == 128 + signal.SIGTERM
    assert managed("-a") == []
    assert _owned_workspaces(proc.pid) == []


def test_sr04_sigkill_to_controller_is_recovered(tmp_path: Path) -> None:
    timeout_s = 4
    proc = _start_hanging_cli(tmp_path, timeout_s=timeout_s)
    workspaces = _owned_workspaces(proc.pid)
    assert workspaces
    proc.kill()  # no cleanup code can run in the controller
    proc.wait()
    # 1. Without any controller, PID 1 stops the workload at timeout + grace.
    grace = SandboxConfig().watchdog_grace_s
    deadline = time.monotonic() + timeout_s + grace + 15
    while managed() and time.monotonic() < deadline:
        time.sleep(0.5)
    assert managed() == [], "container still running after the watchdog deadline"
    assert managed("-a"), "stopped container should still exist until a controller recovers it"
    # 2. The next controller start recovers the orphaned container and workspace at once
    #    (owner process is dead), without waiting for the reap deadline.
    env = {**os.environ, "SANDBOX_AGENT_RUNS": str(tmp_path / "runs")}
    subprocess.run(
        [sys.executable, "-m", "sandbox_agent.cli", "preflight"],
        env=env,
        check=True,
        capture_output=True,
    )
    assert managed("-a") == []
    from sandbox_agent.workspace import Workspace  # noqa: PLC0415

    Workspace.reap_stale()
    assert all(not w.exists() for w in workspaces)
