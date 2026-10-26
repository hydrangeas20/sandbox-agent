"""Runtime isolation tests against a real Docker daemon.

Each test executes probe code *inside* the sandbox and asserts the isolation
property from the container's own point of view. Nothing here runs probe code
on the host.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from sandbox_agent.config import SandboxConfig
from sandbox_agent.errors import SandboxIsolationError
from sandbox_agent.sandbox import ContainerCommand, DockerSandbox, RunOutcome

pytestmark = pytest.mark.docker


@pytest.fixture
def ws(tmp_path: Path) -> Path:
    root = tmp_path / "wsroot"
    ws = root / "ws"
    ws.mkdir(parents=True)
    (ws / "hello.txt").write_text("hi\n")
    # World-writable on purpose: only the read-only *mount* may stop container writes.
    ws.chmod(0o777)
    (ws / "hello.txt").chmod(0o666)
    return ws


def run_py(ws: Path, code: str, **cfg: object) -> RunOutcome:
    config = SandboxConfig(**{"timeout_s": 10.0, **cfg})  # type: ignore[arg-type]
    sandbox = DockerSandbox(config, ws.parent)
    return sandbox.run(ws, ContainerCommand(argv=("python3", "-c", code)))


def probe(ws: Path, code: str) -> dict[str, object]:
    out = run_py(ws, code + "\nimport json,sys; print(json.dumps(R))")
    assert out.status == "completed", out
    assert out.exit_code == 0, out.stderr
    result: dict[str, object] = json.loads(out.stdout.strip().splitlines()[-1])
    return result


def test_preflight_passes(ws: Path) -> None:
    info = DockerSandbox(SandboxConfig(), ws.parent).preflight()
    assert any("seccomp" in s for s in info["security_options"])


def test_network_disabled(ws: Path) -> None:
    r = probe(
        ws,
        """
import os, socket
R = {"ifaces": sorted(os.listdir("/sys/class/net"))}
try:
    socket.create_connection(("1.1.1.1", 53), timeout=2); R["tcp"] = "connected"
except OSError as e:
    R["tcp"] = type(e).__name__
try:
    socket.getaddrinfo("example.com", 443); R["dns"] = "resolved"
except OSError as e:
    R["dns"] = type(e).__name__
""",
    )
    assert r["ifaces"] == ["lo"]
    assert r["tcp"] != "connected"
    assert r["dns"] != "resolved"


def test_privilege_restrictions(ws: Path) -> None:
    r = probe(
        ws,
        """
import os
status = dict(l.split(":", 1) for l in open("/proc/self/status") if ":" in l)
R = {
  "uid": os.getuid(), "gid": os.getgid(), "euid": os.geteuid(),
  "capeff": status["CapEff"].strip(), "capprm": status["CapPrm"].strip(),
  "capbnd": status["CapBnd"].strip(),
  "nnp": status["NoNewPrivs"].strip(), "seccomp": status["Seccomp"].strip(),
}
try:
    os.setuid(0); R["setuid"] = "ok"
except PermissionError:
    R["setuid"] = "denied"
""",
    )
    assert r["uid"] == 10001
    assert r["euid"] == 10001
    assert r["gid"] == 10001
    assert int(str(r["capeff"]), 16) == 0
    assert int(str(r["capprm"]), 16) == 0
    assert int(str(r["capbnd"]), 16) == 0
    assert r["nnp"] == "1"
    assert r["seccomp"] == "2"  # filter mode: default seccomp profile active
    assert r["setuid"] == "denied"


def test_filesystem_restrictions(ws: Path) -> None:
    r = probe(
        ws,
        """
import os, shutil, stat
R = {}
for target in ("/usr/evil", "/etc/evil", "/workspace/evil", "/workspace/hello.txt"):
    try:
        with open(target, "a") as f: f.write("x")
        R[target] = "written"
    except OSError as e:
        R[target] = e.errno
try:
    os.symlink("/etc/passwd", "/workspace/escape"); R["symlink"] = "created"
except OSError as e:
    R["symlink"] = e.errno
shutil.copy("/usr/bin/python3", "/tmp/py"); os.chmod("/tmp/py", 0o755)
try:
    import subprocess; subprocess.run(["/tmp/py", "-c", "1"], check=True); R["tmp_exec"] = "ran"
except OSError as e:
    R["tmp_exec"] = e.errno
R["tmp_writable"] = os.access("/tmp", os.W_OK)
""",
    )
    for target in ("/usr/evil", "/etc/evil", "/workspace/evil", "/workspace/hello.txt"):
        assert r[target] == 30, f"{target} should be EROFS, got {r[target]}"
    assert r["symlink"] == 30
    assert r["tmp_exec"] == 13  # EACCES: /tmp is noexec
    assert r["tmp_writable"] is True
    assert (ws / "hello.txt").read_text() == "hi\n"
    assert not (ws / "escape").exists()


def test_env_is_minimal(ws: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-PLANTED-SECRET-0001")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "PLANTED-AWS-SECRET")
    r = probe(ws, "import os\nR = dict(os.environ)")
    blob = json.dumps(r)
    assert "PLANTED" not in blob
    assert "ANTHROPIC_API_KEY" not in r
    assert r["HOME"] == "/tmp"


def test_memory_limit_oom_killed(ws: Path) -> None:
    out = run_py(ws, "x = bytearray(600 * 1024 * 1024)\nx[::4096] = b'1' * len(x[::4096])")
    assert out.status == "oom_killed", out
    assert out.exit_code == 137


def test_pids_limit_blocks_fork_bomb(ws: Path) -> None:
    code = """
import os, time, threading
started, err = 0, None
try:
    for _ in range(500):
        threading.Thread(target=time.sleep, args=(5,), daemon=True).start(); started += 1
except RuntimeError as e:
    err = str(e)
print(started, err is not None)
os._exit(0)
"""
    out = run_py(ws, code, pids_limit=32)
    assert out.status == "completed", out
    started, hit_limit = out.stdout.split()
    assert int(started) < 32
    assert hit_limit == "True"


def test_timeout_kills_busy_loop(ws: Path) -> None:
    out = run_py(ws, "while True: pass", timeout_s=2.0)
    assert out.status == "timeout"
    assert out.exit_code is None
    assert out.duration_ms < 12_000


def test_output_is_capped(ws: Path) -> None:
    out = run_py(ws, "import sys; sys.stdout.write('A' * 2_000_000)", max_output_bytes=4096)
    assert out.status == "completed"
    assert out.stdout_truncated is True
    assert len(out.stdout) == 4096
    assert out.stdout_bytes_total == 2_000_000


def test_file_size_limit(ws: Path) -> None:
    out = run_py(
        ws,
        "import signal; signal.signal(signal.SIGXFSZ, signal.SIG_IGN)\n"
        "f = open('/tmp/big', 'wb')\n"
        "try:\n    f.write(b'0' * (8 * 1024 * 1024))\n"
        "except OSError as e:\n    print('EFBIG', e.errno)",
        fsize_bytes=4 * 1024 * 1024,
    )
    assert "EFBIG 27" in out.stdout


def test_isolation_mismatch_fails_closed_and_removes_container(
    ws: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If the daemon silently drops a control, the container must never start."""
    sandbox = DockerSandbox(SandboxConfig(timeout_s=5.0), ws.parent)
    real_inspect = sandbox._inspect

    def tampered(cid: str) -> dict[str, object]:
        data = real_inspect(cid)
        data["HostConfig"]["NetworkMode"] = "bridge"  # type: ignore[index]
        return data

    monkeypatch.setattr(sandbox, "_inspect", tampered)
    marker = ws / "started"
    with pytest.raises(SandboxIsolationError, match="network"):
        sandbox.run(ws, ContainerCommand(argv=("python3", "-c", "print('ran')")))
    assert not marker.exists()
    docker = shutil.which("docker")
    assert docker is not None
    leftover = subprocess.run(
        [docker, "ps", "-aq", "--filter", "label=sandbox-agent.managed=1"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert leftover.stdout.strip() == ""
