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
    client = TestClient(create_app(settings), base_url="http://127.0.0.1")
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


def test_trace_is_complete_and_secret_free(
    settings: Settings, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    planted = "sk-ant-api03-PLANTED-e2e-secret-000000000000"
    monkeypatch.setenv("ANTHROPIC_API_KEY", planted)
    result = run_task(
        TaskRequest(fixture="paginator", task=f"fix pagination (ignore this key: {planted})"),
        settings,
    )
    assert result.status == "succeeded"
    assert "PLANTED" not in result.model_dump_json()

    events = result.trace
    assert {e["cid"] for e in events} == {result.task_id}
    assert [e["seq"] for e in events] == list(range(1, len(events) + 1))
    kinds = [e["event"] for e in events]
    assert kinds[0] == "task_start"
    assert kinds[-1] == "task_end"
    assert "sandbox_preflight" in kinds
    starts = [e["call_id"] for e in events if e["event"] == "tool_start"]
    ends = [e["call_id"] for e in events if e["event"] == "tool_end"]
    assert starts == ends
    for e in events:
        if e["event"] == "tool_end":
            assert isinstance(e["duration_ms"], int)
    runs = [e for e in events if e["event"] == "tool_end" and e["tool"] == "run_tests"]
    assert all(r["resources"]["container"].startswith("sandbox-agent-") for r in runs)
    assert all(r["resources"]["timed_out"] is False for r in runs)
    assert events[-1]["resources"]["sandbox_runs"] == 2

    from sandbox_agent.trace import Tracer  # noqa: PLC0415

    tr = Tracer("x")
    tr.events = events
    path = tr.write_jsonl(tmp_path / "trace.jsonl")
    assert "PLANTED" not in path.read_text()


def test_trace_is_sufficient_to_replay(settings: Settings) -> None:
    """Reconstruct the action sequence from the trace alone and replay it."""
    from sandbox_agent.providers.scripted import ScriptedProvider, Step  # noqa: PLC0415

    first = run_task(TaskRequest(fixture="paginator", task="fix pagination"), settings)
    actions = [
        {"tool": e["tool"], "args": e["args"]}
        for e in first.trace
        if e["event"] == "provider_action"
    ]
    replay = ScriptedProvider([Step(a) for a in actions])
    second = run_task(
        TaskRequest(fixture="paginator", task="replay"),
        settings,
        provider_factory=lambda _req: replay,
    )
    assert second.status == first.status == "succeeded"
    assert second.diff == first.diff
    tools = lambda r: [e["tool"] for e in r.trace if e["event"] == "tool_end"]  # noqa: E731
    assert tools(second) == tools(first)
