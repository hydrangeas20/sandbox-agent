"""Regression tests for the Phase 2 security review (docs/SECURITY_REVIEW.md).

Each test is named after its finding (``sr01`` …). These were written and run
against the pre-fix code first; the failures they produced are recorded in the
review. Tests here need no Docker daemon; Docker-backed regressions are in
``test_security_review_docker.py``.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import json
import os
import threading
import urllib.parse
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from sandbox_agent.api import create_app
from sandbox_agent.config import AgentBudget, SandboxConfig, Settings, WorkspaceLimits
from sandbox_agent.errors import WorkspaceError
from sandbox_agent.providers.base import Transcript
from sandbox_agent.providers.scripted import ScriptedProvider, Step
from sandbox_agent.sandbox import DockerSandbox
from sandbox_agent.service import TaskRequest, run_task
from sandbox_agent.tools import ToolContext, ToolExecutor
from sandbox_agent.trace import REDACTED, Tracer
from sandbox_agent.workspace import Workspace, tree_manifest
from tests.fakes import FakeRunner, outcome
from tests.test_sandbox_args import good_inspect

LIMITS = WorkspaceLimits()
PASS = outcome(0, "Ran 6 tests in 0.01s\n\nOK\n")


@pytest.fixture
def settings(fixtures_dir: Path, tmp_path: Path) -> Settings:
    return Settings(fixtures_dir=fixtures_dir, runs_dir=tmp_path / "runs", offline=True)


@pytest.fixture
def sandbox(tmp_path: Path) -> DockerSandbox:
    (tmp_path / "wsroot" / "ws").mkdir(parents=True)
    return DockerSandbox(SandboxConfig(), tmp_path / "wsroot", docker_bin="/usr/bin/false")


def _stub_docker(monkeypatch: pytest.MonkeyPatch, runner: Any) -> None:
    """Run the service without a daemon: preflight stubbed, run_tests served by ``runner``."""
    monkeypatch.setattr("sandbox_agent.sandbox.shutil.which", lambda _n: "/usr/bin/false")
    monkeypatch.setattr("sandbox_agent.service.DockerSandbox.preflight", lambda self: {})
    monkeypatch.setattr(
        "sandbox_agent.service.DockerSandbox.run", lambda self, ws, cmd: runner.run(ws, cmd)
    )


# ============================================================ SR-01 seccomp verification


def _with_secopt(sandbox: DockerSandbox, root: Path, secopt: list[str]) -> dict[str, Any]:
    data = good_inspect(sandbox.config, root / "ws")
    data["HostConfig"]["SecurityOpt"] = secopt
    return data


@pytest.mark.parametrize(
    "secopt",
    [
        ["no-new-privileges"],  # daemon default applies; inspect cannot show which profile
        ["no-new-privileges", 'seccomp={"defaultAction":"SCMP_ACT_ALLOW"}'],
        ["no-new-privileges", "seccomp=unconfined"],
        ["no-new-privileges", "label=disable"],
        ["no-new-privileges", "apparmor=unconfined"],
        ["no-new-privileges", "systempaths=unconfined"],
    ],
    ids=["no_profile", "allow_all_profile", "unconfined", "selinux_disabled", "apparmor", "paths"],
)
def test_sr01_verify_rejects_weak_security_options(
    sandbox: DockerSandbox, tmp_path: Path, secopt: list[str]
) -> None:
    from sandbox_agent.errors import SandboxIsolationError  # noqa: PLC0415

    data = _with_secopt(sandbox, tmp_path / "wsroot", secopt)
    with pytest.raises(SandboxIsolationError):
        sandbox.verify(data, tmp_path / "wsroot" / "ws")


def test_sr01_verify_rejects_tampered_pinned_profile(
    sandbox: DockerSandbox, tmp_path: Path
) -> None:
    from sandbox_agent.errors import SandboxIsolationError  # noqa: PLC0415
    from sandbox_agent.sandbox import load_seccomp_profile  # noqa: PLC0415

    profile = load_seccomp_profile()
    profile["syscalls"].append({"names": ["unshare"], "action": "SCMP_ACT_ALLOW"})
    data = _with_secopt(
        sandbox, tmp_path / "wsroot", ["no-new-privileges", "seccomp=" + json.dumps(profile)]
    )
    with pytest.raises(SandboxIsolationError, match="seccomp"):
        sandbox.verify(data, tmp_path / "wsroot" / "ws")


def test_sr01_verify_rejects_apparmor_unconfined_and_entrypoint(
    sandbox: DockerSandbox, tmp_path: Path
) -> None:
    from sandbox_agent.errors import SandboxIsolationError  # noqa: PLC0415

    ws = tmp_path / "wsroot" / "ws"
    data = good_inspect(sandbox.config, ws)
    data["AppArmorProfile"] = "unconfined"
    with pytest.raises(SandboxIsolationError, match="apparmor"):
        sandbox.verify(data, ws)
    data = good_inspect(sandbox.config, ws)
    data["Config"]["Entrypoint"] = ["/bin/sh", "-c"]
    with pytest.raises(SandboxIsolationError, match="entrypoint"):
        sandbox.verify(data, ws)


def test_sr01_create_args_pin_profile_and_wrap_command(
    sandbox: DockerSandbox, tmp_path: Path
) -> None:
    from sandbox_agent.sandbox import ContainerCommand  # noqa: PLC0415

    args = sandbox.build_create_args(
        tmp_path / "wsroot" / "ws", ContainerCommand(argv=("python3", "-c", "1")), "n"
    )
    seccomp = [a for a in args if a.startswith("seccomp=")]
    assert len(seccomp) == 1
    assert Path(seccomp[0].removeprefix("seccomp=")).is_file()
    image_at = args.index(sandbox.config.image)
    # The trusted entrypoint runs first and execs the real command after attestation.
    assert args[image_at + 1 : image_at + 5] == [
        "python3",
        "-I",
        "-S",
        "/opt/sandbox-agent/entry.py",
    ]
    assert args[-3:] == ["python3", "-c", "1"]


# ============================================================ SR-02 container environment


def test_sr02_verify_rejects_image_provided_env(sandbox: DockerSandbox, tmp_path: Path) -> None:
    from sandbox_agent.errors import SandboxIsolationError  # noqa: PLC0415

    ws = tmp_path / "wsroot" / "ws"
    for extra in ("GPG_KEY=A035C8C19219BA821ECEA86B64E628F8D684696D", "LD_PRELOAD=/tmp/x.so"):
        data = good_inspect(sandbox.config, ws)
        data["Config"]["Env"].append(extra)
        # Previously any key present in the *image* was accepted with any value.
        with pytest.raises(SandboxIsolationError, match="env"):
            sandbox.verify(data, ws)


# ============================================================ SR-03 test tampering


def _tests_only_patch() -> list[dict[str, str]]:
    return [
        {
            "path": "tests/test_core.py",
            "old": "        self.assertEqual(page.items, list(range(1, 11)))\n",
            "new": "        pass\n",
        }
    ]


def test_sr03_editing_tests_cannot_produce_success(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_docker(monkeypatch, FakeRunner([PASS]))
    provider = ScriptedProvider(
        [
            Step({"tool": "apply_patch", "args": {"edits": _tests_only_patch()}}),
            Step({"tool": "run_tests", "args": {"command": "unittest"}}),
            Step({"tool": "finish", "args": {"summary": "fixed"}}),
        ]
    )
    result = run_task(
        TaskRequest(fixture="paginator", task="fix"), settings, provider_factory=lambda _r: provider
    )
    assert result.status != "succeeded"
    assert result.diff == ""
    denials = [e["rule"] for e in result.trace if e["event"] == "policy_denial"]
    assert denials == ["patch.protected_path"]


@pytest.mark.parametrize(
    "path", ["tests/test_core.py", "./tests/test_core.py", "tests//test_core.py"]
)
def test_sr03_protected_path_variants(fixtures_dir: Path, tmp_path: Path, path: str) -> None:
    with Workspace.create(fixtures_dir / "paginator", LIMITS, base_dir=tmp_path) as ws:
        tools = ToolExecutor(ToolContext(ws, FakeRunner()))
        edit = {"path": path, "old": "import unittest", "new": "import unittest  # x"}
        res = tools.execute("apply_patch", {"edits": [edit]})
        assert res.denied_rule == "patch.protected_path"


# ============================================================ SR-06/07/08/09 workspace


def _run_with_deadline(fn: Any, seconds: float) -> tuple[bool, Any]:
    box: dict[str, Any] = {}

    def target() -> None:
        try:
            box["value"] = fn()
        except BaseException as exc:
            box["value"] = exc

    t = threading.Thread(target=target, daemon=True)
    t.start()
    t.join(seconds)
    return (not t.is_alive()), box.get("value")


def test_sr06_fifo_in_fixture_does_not_hang(tmp_path: Path) -> None:
    repo = tmp_path / "fifo_repo"
    repo.mkdir()
    (repo / "a.txt").write_text("a")
    os.mkfifo(repo / "pipe")
    finished, _ = _run_with_deadline(lambda: tree_manifest(repo), 3)
    assert finished, "tree_manifest blocked on a FIFO"


def test_sr06_fifo_fixture_task_fails_fast(
    tmp_fixtures: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_fixtures / "fifo"
    repo.mkdir()
    os.mkfifo(repo / "pipe")
    _stub_docker(monkeypatch, FakeRunner())
    settings = Settings(fixtures_dir=tmp_fixtures, runs_dir=tmp_path / "r", offline=True)
    provider = ScriptedProvider([Step({"tool": "finish", "args": {"summary": "x"}})])
    finished, result = _run_with_deadline(
        lambda: run_task(
            TaskRequest(fixture="fifo", task="x"), settings, provider_factory=lambda _r: provider
        ),
        5,
    )
    assert finished, "run_task hung on a FIFO in the fixture"
    assert result.status == "failed"
    assert "special file" in result.reason


def test_sr07_hard_link_in_fixture_rejected(tmp_path: Path) -> None:
    repo = tmp_path / "hl"
    repo.mkdir()
    secret = tmp_path / "host_secret"
    secret.write_text("HOST-SECRET\n")
    os.link(secret, repo / "innocent.txt")
    with pytest.raises(WorkspaceError, match="hard link"):
        Workspace.create(repo, LIMITS, base_dir=tmp_path)


def _real(name: str) -> Any:
    return getattr(os, name)


def test_sr08_directory_swapped_during_copy_is_not_followed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "swap"
    (repo / "pkg").mkdir(parents=True)
    (repo / "pkg" / "mod.py").write_text("x = 1\n")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "stolen.txt").write_text("HOST-SECRET\n")
    real_mkdir = _real("mkdir")
    swapped = {"done": False}

    def racing_mkdir(path: Any, *args: Any, **kwargs: Any) -> Any:
        # After the copier has classified `pkg` as a directory, swap it for a symlink.
        if not swapped["done"] and os.fspath(path).endswith("pkg"):
            swapped["done"] = True
            os.rename(repo / "pkg", tmp_path / "pkg.orig")
            os.symlink(outside, repo / "pkg")
        return real_mkdir(path, *args, **kwargs)

    monkeypatch.setattr(os, "mkdir", racing_mkdir)
    base = tmp_path / "base"
    real_mkdir(base)
    try:
        ws = Workspace.create(repo, LIMITS, base_dir=base)
    except WorkspaceError:
        return  # detected the swap: acceptable
    with ws:
        assert swapped["done"]
        copied = {p.name for p in ws.path.rglob("*")}
        assert "stolen.txt" not in copied


def test_sr08_file_growth_during_copy_respects_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "grow"
    repo.mkdir()
    (repo / "grow.txt").write_text("x" * 100)
    real_open = _real("open")

    def growing_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        if os.fspath(path).endswith("grow.txt") and not flags & os.O_WRONLY:
            with open(repo / "grow.txt", "a") as fh:
                fh.write("y" * 50_000)
        return int(real_open(path, flags, *args, **kwargs))

    monkeypatch.setattr(os, "open", growing_open)
    with pytest.raises(WorkspaceError, match="bytes"):
        Workspace.create(repo, WorkspaceLimits(max_total_bytes=10_000), base_dir=tmp_path)


def test_sr09_intermediate_directory_swap_is_not_followed(
    fixtures_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Replace a parent directory with a symlink between validation and open."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "core.py").write_text("HOST-SECRET\n")
    with Workspace.create(fixtures_dir / "paginator", LIMITS, base_dir=tmp_path) as ws:
        real_lstat = _real("lstat")
        state = {"swapped": False}

        def racing_lstat(path: Any, *args: Any, **kwargs: Any) -> Any:
            result = real_lstat(path, *args, **kwargs)
            if not state["swapped"] and os.fspath(path).endswith("paginator"):
                state["swapped"] = True
                os.rename(ws.path / "paginator", ws.path / "paginator.orig")
                os.symlink(outside, ws.path / "paginator")
            return result

        monkeypatch.setattr(os, "lstat", racing_lstat)
        try:
            text = ws.read_text("paginator/core.py")
        except Exception:
            text = ""
        assert state["swapped"]
        assert "HOST-SECRET" not in text
        state["swapped"] = False
        with contextlib.suppress(Exception):
            ws.write_text("paginator/core.py", "pwned\n")
        assert (outside / "core.py").read_text() == "HOST-SECRET\n"


def test_sr09_all_workspace_opens_are_descriptor_relative(
    fixtures_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with Workspace.create(fixtures_dir / "paginator", LIMITS, base_dir=tmp_path) as ws:
        real_open = _real("open")
        calls: list[tuple[str, int, Any]] = []

        def spy(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
            calls.append((os.fspath(path), flags, kwargs.get("dir_fd")))
            return int(real_open(path, flags, *args, **kwargs))

        monkeypatch.setattr(os, "open", spy)
        ws.read_text("paginator/core.py")
        ws.write_text("paginator/core.py", ws.read_text("paginator/core.py") + "\n")
        assert calls
        for path, flags, dir_fd in calls:
            assert flags & os.O_NOFOLLOW, path
            assert "/" not in path or (dir_fd is None and path == os.fspath(ws.path)), path


# ============================================================ SR-10 unexpected exceptions


def test_sr10_unreadable_fixture_file_is_workspace_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "locked"
    repo.mkdir()
    (repo / "locked.txt").write_text("x")
    real_open = _real("open")

    def denying_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        if os.fspath(path).endswith("locked.txt"):
            raise PermissionError(13, "Permission denied", os.fspath(path))
        return int(real_open(path, flags, *args, **kwargs))

    monkeypatch.setattr(os, "open", denying_open)
    with pytest.raises(WorkspaceError):
        Workspace.create(repo, LIMITS, base_dir=tmp_path)


def test_sr10_unexpected_provider_exception_is_contained(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_docker(monkeypatch, FakeRunner())
    leaky = "sk-ant-api03-LEAKY-provider-error-0000000000"

    class Boom:
        name = "boom"

        def next_action(self, transcript: Transcript) -> Any:
            raise ConnectionResetError(f"peer reset while sending key {leaky}")

    result = run_task(
        TaskRequest(fixture="paginator", task="x"), settings, provider_factory=lambda _r: Boom()
    )
    assert result.status == "provider_error"
    blob = json.dumps(result.trace)
    assert "ConnectionResetError" in blob
    assert "LEAKY" not in blob
    assert "peer reset" not in blob  # exception text from providers is not traced at all


def test_sr10_unexpected_tool_exception_is_execution_error(
    fixtures_dir: Path, tmp_path: Path
) -> None:
    class ExplodingRunner:
        def run(self, workspace_dir: Path, command: Any) -> Any:
            raise RuntimeError("unexpected")

    with Workspace.create(fixtures_dir / "paginator", LIMITS, base_dir=tmp_path) as ws:
        res = ToolExecutor(ToolContext(ws, ExplodingRunner())).execute(
            "run_tests", {"command": "unittest"}
        )
        assert not res.ok
        assert res.error_kind == "execution_error"


# ============================================================ SR-11 API host validation


def test_sr11_api_rejects_foreign_host_header(settings: Settings) -> None:
    client = TestClient(create_app(settings), base_url="http://127.0.0.1")
    assert client.get("/healthz").status_code == 200
    assert client.get("/healthz", headers={"host": "localhost:8000"}).status_code == 200
    assert client.get("/fixtures", headers={"host": "attacker.example"}).status_code == 400
    body = {"fixture": "paginator", "task": "x"}
    assert (
        client.post("/tasks", json=body, headers={"host": "rebind.attacker.example"}).status_code
        == 400
    )


def test_sr11_text_plain_post_is_rejected(settings: Settings) -> None:
    """False positive check: browser 'simple request' CSRF is already blocked by FastAPI."""
    client = TestClient(create_app(settings), base_url="http://127.0.0.1")
    resp = client.post(
        "/tasks",
        content='{"fixture":"paginator","task":"x"}',
        headers={"content-type": "text/plain"},
    )
    assert resp.status_code == 422


# ============================================================ SR-12 redaction


SECRET = "s3cr3t-Value-With-No-Known-Prefix-9F7A"


@pytest.mark.parametrize(
    "key",
    [
        "ANTHROPIC_API_KEY",
        "client_secret",
        "access_token",
        "refresh_token",
        "Proxy-Authorization",
        "x-goog-api-key",
        "private_key",
        "db_password",
        "AWS_SECRET_ACCESS_KEY",
        "sessionToken",
        "credentials",
    ],
)
def test_sr12_credential_named_keys_redacted_when_nested(key: str) -> None:
    t = Tracer("c")
    e = t.emit("x", payload={"outer": [{"inner": {key: SECRET, "keep": "visible"}}]})
    inner = e["payload"]["outer"][0]["inner"]
    assert inner[key] == REDACTED
    assert inner["keep"] == "visible"


def test_sr12_encoded_registered_secret_redacted() -> None:
    t = Tracer("c")
    t.register_secrets(SECRET)
    variants = {
        "base64": base64.b64encode(SECRET.encode()).decode(),
        "base64url": base64.urlsafe_b64encode(SECRET.encode()).decode().rstrip("="),
        "hex": binascii.hexlify(SECRET.encode()).decode(),
        "urlencoded": urllib.parse.quote(SECRET + "/+", safe=""),
        "json_escaped": json.dumps(SECRET)[1:-1],
    }
    e = t.emit("x", **variants)
    for name in variants:
        assert e[name] == REDACTED or REDACTED in e[name], name


def test_sr12_custom_credential_env_var_values_redacted(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MYCORP_DEPLOY_TOKEN", "opaque-deploy-credential-777")
    monkeypatch.setenv("UNRELATED_SETTING", "harmless-value-1234")
    e = Tracer("c").emit("x", text="opaque-deploy-credential-777 harmless-value-1234")
    assert "opaque-deploy-credential-777" not in e["text"]
    assert "harmless-value-1234" in e["text"]


@pytest.mark.parametrize(
    "text",
    [
        "Authorization: Basic dXNlcjpwYXNzd29yZDEyMzQ1Ng==",
        "authorization=Token abcdef0123456789abcdef",
        "postgres://admin:hunter2-db-pass@db.internal:5432/app",
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        '{"api_key": "abc123def456ghi789"}',
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
    ],
    ids=["basic_auth", "token_header", "url_userinfo", "aws_assignment", "json_key", "jwt"],
)
def test_sr12_unusual_credential_formats(text: str) -> None:
    e = Tracer("c").emit("x", text=text)
    assert REDACTED in e["text"], e["text"]


def test_sr12_test_output_never_enters_trace(
    fixtures_dir: Path, tmp_path: Path, settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    stderr = (
        "Ran 6 tests in 0.01s\n\nOK\nUNTRUSTED-OUTPUT-MARKER sk-ant-api03-FROM-TEST-OUTPUT-000000\n"
    )
    _stub_docker(monkeypatch, FakeRunner([outcome(0, stderr)]))
    provider = ScriptedProvider(
        [
            Step({"tool": "run_tests", "args": {"command": "unittest"}}),
            Step({"tool": "finish", "args": {"summary": "x"}}),
        ]
    )
    result = run_task(
        TaskRequest(fixture="paginator", task="x", budget=AgentBudget()),
        settings,
        provider_factory=lambda _r: provider,
    )
    blob = json.dumps(result.trace)
    assert "UNTRUSTED-OUTPUT-MARKER" not in blob
    assert "FROM-TEST-OUTPUT" not in blob


# ============================================================ SR-14 output retention


def test_sr14_reader_keeps_head_and_tail() -> None:
    import io  # noqa: PLC0415

    from sandbox_agent.sandbox import _BoundedReader  # noqa: PLC0415

    data = b"HEAD-" + b"x" * 200_000 + b"\nRan 6 tests in 0.1s\n\nFAILED (failures=2)\n"
    reader = _BoundedReader(io.BytesIO(data), 1024)
    reader.run()
    assert reader.text.startswith("HEAD-")
    assert reader.tail.endswith("FAILED (failures=2)\n")
    assert reader.truncated


# ============================================================ SR-03b protected config + diff gate


@pytest.mark.parametrize(
    "path",
    [
        "conftest.py",
        "pkg/conftest.py",
        "pyproject.toml",
        "setup.cfg",
        "tox.ini",
        "pytest.ini",
        "sitecustomize.py",
        "usercustomize.py",
        "pkg/evil.pth",
        ".sandbox-agent/policy.toml",
        "evals/tasks.json",
    ],
)
def test_sr03_test_config_policy_and_eval_files_protected(tmp_path: Path, path: str) -> None:
    repo = tmp_path / "repo"
    (repo / Path(path).parent).mkdir(parents=True, exist_ok=True)
    (repo / path).write_text("value = 1\n")
    with Workspace.create(repo, LIMITS, base_dir=tmp_path) as ws:
        res = ToolExecutor(ToolContext(ws, FakeRunner())).execute(
            "apply_patch", {"edits": [{"path": path, "old": "value = 1", "new": "value = 2"}]}
        )
        assert res.denied_rule == "patch.protected_path", res


def test_sr03_final_diff_gate_catches_out_of_band_changes(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Defence in depth: even if a tool bug wrote to tests/, the controller rejects the diff."""

    class TamperingRunner(FakeRunner):
        def run(self, workspace_dir: Path, command: Any) -> Any:
            target = workspace_dir / "tests" / "test_core.py"
            target.write_text(target.read_text().replace("assertEqual", "assertNotEqual", 1))
            return super().run(workspace_dir, command)

    _stub_docker(monkeypatch, TamperingRunner([PASS]))
    edit = {
        "path": "paginator/core.py",
        "old": "    start = page * per_page\n",
        "new": "    start = (page - 1) * per_page\n",
    }
    provider = ScriptedProvider(
        [
            Step({"tool": "apply_patch", "args": {"edits": [edit]}}),
            Step({"tool": "run_tests", "args": {"command": "unittest"}}),
            Step({"tool": "finish", "args": {"summary": "fixed"}}),
        ]
    )
    result = run_task(
        TaskRequest(fixture="paginator", task="fix"), settings, provider_factory=lambda _r: provider
    )
    assert result.status == "policy_aborted"
    assert "tests/test_core.py" in result.reason
    assert any(e["event"] == "diff_policy_violation" for e in result.trace)


# ============================================================ SR-04 reaper decisions (no daemon)


def test_sr04_reaper_spares_live_runs_and_removes_orphans(
    sandbox: DockerSandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    import subprocess  # noqa: PLC0415
    import time  # noqa: PLC0415

    from sandbox_agent.ownership import current_owner  # noqa: PLC0415

    future, past = int(time.time()) + 600, int(time.time()) - 1
    host = current_owner().split(":")[0]
    listing = "\n".join(
        [
            f"live|{future}|{current_owner()}",  # this process, within deadline: keep
            f"dead|{future}|{host}:999999:12345",  # owner gone: remove now
            f"late|{past}|{current_owner()}",  # past deadline: remove
            f"remote|{future}|other-host:1:1",  # foreign host, within deadline: keep
            "untagged||",  # no labels: remove
        ]
    )
    removed: list[str] = []

    def fake_cli(*args: str, timeout: float = 30) -> subprocess.CompletedProcess[str]:
        if args[0] == "rm":
            removed.extend(args[2:])
        return subprocess.CompletedProcess(args, 0, listing if args[0] == "ps" else "", "")

    monkeypatch.setattr(sandbox, "_cli", fake_cli)
    assert sandbox.reap_stale() == 3
    assert sorted(removed) == ["dead", "late", "untagged"]


def test_sr04_workspace_reaper(tmp_path: Path, fixtures_dir: Path) -> None:
    live = Workspace.create(fixtures_dir / "paginator", LIMITS, base_dir=tmp_path)
    dead = Workspace.create(fixtures_dir / "paginator", LIMITS, base_dir=tmp_path)
    host = (live.root / ".owner").read_text().split(":")[0]
    (dead.root / ".owner").write_text(f"{host}:999999:12345")
    foreign = tmp_path / "sandbox-agent-notours"
    foreign.mkdir(mode=0o755)  # wrong mode and no owner tag: never touched
    assert Workspace.reap_stale(tmp_path) == 1
    assert live.root.exists()
    assert not dead.root.exists()
    assert foreign.exists()
    live.cleanup()


# ============================================================ SR-12b redaction must be linear-time


@pytest.mark.parametrize(
    "payload",
    [
        "x" * 70_000,
        "a" * 35_000 + "token" + "b" * 35_000,
        "http" * 17_500,
        "Bearer " + "z" * 70_000,
        "-----BEGIN RSA PRIVATE KEY-----\n" * 2_000,
    ],
    ids=["word_run", "embedded_name", "scheme_like", "bearer_run", "pem_without_end"],
)
def test_sr12_redaction_is_not_quadratic(payload: str) -> None:
    """Model-controlled strings (patch text up to 64 KiB) must not stall the tracer."""
    import time  # noqa: PLC0415

    started = time.monotonic()
    Tracer("c").emit("x", args={"new": payload})
    assert time.monotonic() - started < 1.0
