"""API/CLI behaviour without Docker, plus a static check that only sandbox.py spawns processes."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from sandbox_agent.api import create_app
from sandbox_agent.cli import main
from sandbox_agent.config import Settings
from sandbox_agent.service import TaskRequest, run_task

SRC = Path(__file__).resolve().parents[1] / "src" / "sandbox_agent"


@pytest.fixture
def settings(fixtures_dir: Path, tmp_path: Path) -> Settings:
    return Settings(fixtures_dir=fixtures_dir, runs_dir=tmp_path / "runs", offline=True)


def test_healthz_and_fixtures(settings: Settings) -> None:
    client = TestClient(create_app(settings), base_url="http://127.0.0.1")
    assert client.get("/healthz").json()["status"] == "ok"
    assert "paginator" in client.get("/fixtures").json()["fixtures"]


@pytest.mark.parametrize("fixture", ["../etc", "/etc", "nope", "Paginator"])
def test_api_rejects_unknown_or_path_fixtures(settings: Settings, fixture: str) -> None:
    client = TestClient(create_app(settings), base_url="http://127.0.0.1")
    resp = client.post("/tasks", json={"fixture": fixture, "task": "x"})
    assert resp.status_code == 404


@pytest.mark.parametrize(
    "body",
    [
        {"fixture": "paginator"},
        {"fixture": "paginator", "task": ""},
        {"fixture": "paginator", "task": "x", "provider": "shell"},
        {"fixture": "paginator", "task": "x", "budget": {"max_iterations": 10_000}},
        {"fixture": "paginator", "task": "x", "workspace": "/home"},
    ],
)
def test_api_validates_requests(settings: Settings, body: dict[str, object]) -> None:
    client = TestClient(create_app(settings), base_url="http://127.0.0.1")
    assert client.post("/tasks", json=body).status_code == 422


def test_offline_mode_refuses_real_provider(settings: Settings) -> None:
    req = TaskRequest(fixture="paginator", task="x", provider="anthropic")
    result = run_task(req, settings)
    assert result.status == "provider_error"
    assert "offline" in result.reason


def test_missing_docker_fails_closed(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PATH", "/nonexistent")
    result = run_task(TaskRequest(fixture="paginator", task="x"), settings)
    assert result.status == "sandbox_error"
    assert result.agent is None
    assert result.fixture_unchanged is True


def test_cli_fixtures(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["fixtures"]) == 0
    assert "paginator" in capsys.readouterr().out


FORBIDDEN_CALLS = {
    ("os", "system"),
    ("os", "popen"),
    ("os", "execv"),
    ("os", "execve"),
    ("os", "execvp"),
    ("os", "spawnv"),
    ("os", "fork"),
}


def test_no_host_exec_outside_sandbox_module() -> None:
    """AC-1: only sandbox.py may spawn processes, and nothing may eval/exec code."""
    for path in SRC.rglob("*.py"):
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import | ast.ImportFrom):
                names = [a.name for a in node.names]
                module = getattr(node, "module", None) or ""
                imported = {module, *names}
                if path.name != "sandbox.py":
                    assert not imported & {"subprocess", "pty", "multiprocessing"}, path
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Name):
                    assert func.id not in {"eval", "exec", "compile", "__import__"}, path
                if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                    assert (func.value.id, func.attr) not in FORBIDDEN_CALLS, path
            if isinstance(node, ast.keyword) and node.arg == "shell":
                assert not (isinstance(node.value, ast.Constant) and node.value.value), path
