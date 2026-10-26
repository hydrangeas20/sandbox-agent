"""End-to-end: real sandbox, scripted provider, paginator fixture (AC-11)."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from sandbox_agent.api import create_app
from sandbox_agent.cli import main
from sandbox_agent.config import Settings
from sandbox_agent.service import TaskRequest, run_task
from sandbox_agent.workspace import tree_manifest

pytestmark = pytest.mark.docker


@pytest.fixture
def settings(fixtures_dir: Path, tmp_path: Path) -> Settings:
    return Settings(fixtures_dir=fixtures_dir, runs_dir=tmp_path / "runs", offline=True)


def _workspaces() -> set[str]:
    return {p.name for p in Path(tempfile.gettempdir()).glob("sandbox-agent-*")}


def _containers() -> str:
    docker = shutil.which("docker")
    assert docker
    return subprocess.run(
        [docker, "ps", "-aq", "--filter", "label=sandbox-agent.managed=1"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def test_agent_fixes_real_bug_and_fixture_is_untouched(
    settings: Settings, fixtures_dir: Path
) -> None:
    independent_before = tree_manifest(fixtures_dir / "paginator")
    workspaces_before = _workspaces()

    result = run_task(TaskRequest(fixture="paginator", task="fix pagination"), settings)

    assert result.status == "succeeded", result.reason
    assert result.agent is not None
    assert result.agent.patches_applied == 1
    assert result.final_tests.passed is True
    assert result.final_tests.tests_run == 6
    assert result.files_changed == ["paginator/core.py"]
    assert "-    start = page * per_page\n" in result.diff
    assert "+    start = (page - 1) * per_page\n" in result.diff

    # The original fixture is byte-for-byte unchanged (and still buggy).
    assert result.fixture_unchanged is True
    assert result.fixture_sha256_before == independent_before
    assert tree_manifest(fixtures_dir / "paginator") == independent_before
    core = (fixtures_dir / "paginator" / "paginator" / "core.py").read_text()
    assert "    start = page * per_page\n" in core

    # Trace shows the diagnose -> patch -> verify sequence.
    tools = [e["tool"] for e in result.trace if e["event"] == "tool_end"]
    assert tools == ["run_tests", "search", "read_file", "apply_patch", "run_tests"]
    runs = [
        e["result"] for e in result.trace if e["event"] == "tool_end" and e["tool"] == "run_tests"
    ]
    assert [r["passed"] for r in runs] == [False, True]

    # Nothing left behind.
    assert _workspaces() == workspaces_before
    assert _containers() == ""


def test_api_runs_task(settings: Settings) -> None:
    client = TestClient(create_app(settings))
    resp = client.post("/tasks", json={"fixture": "paginator", "task": "fix pagination"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "succeeded"
    assert body["fixture_unchanged"] is True
    assert body["diff"]


def test_cli_demo_exit_code(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SANDBOX_AGENT_RUNS", str(settings.runs_dir))
    assert main(["demo"]) == 0
    traces = list(settings.runs_dir.glob("*.trace.jsonl"))
    assert len(traces) == 1
