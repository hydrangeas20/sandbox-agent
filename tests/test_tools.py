"""Tool contracts: schema validation, policy denials, allowlisted commands only."""

from __future__ import annotations

from pathlib import Path

import pytest

from sandbox_agent.config import WorkspaceLimits
from sandbox_agent.policy import ALLOWED_COMMANDS, build_command
from sandbox_agent.tools import TOOL_SPECS, ToolContext, ToolExecutor
from sandbox_agent.workspace import Workspace
from tests.fakes import FakeRunner, outcome


@pytest.fixture
def ws(fixtures_dir: Path, tmp_path: Path) -> Workspace:
    return Workspace.create(fixtures_dir / "paginator", WorkspaceLimits(), base_dir=tmp_path)


@pytest.fixture
def runner() -> FakeRunner:
    return FakeRunner()


@pytest.fixture
def tools(ws: Workspace, runner: FakeRunner) -> ToolExecutor:
    return ToolExecutor(ToolContext(workspace=ws, runner=runner))


def test_no_shell_tool_exists() -> None:
    assert set(TOOL_SPECS) == {
        "list_files",
        "read_file",
        "search",
        "apply_patch",
        "run_tests",
        "finish",
    }
    for spec in TOOL_SPECS.values():
        assert spec.json_schema()["type"] == "object"


@pytest.mark.parametrize(
    "name", ["bash", "shell", "exec", "python", "_tool_finish", "__init__", ""]
)
def test_unknown_tool_denied(tools: ToolExecutor, name: str) -> None:
    res = tools.execute(name, {})
    assert not res.ok
    assert res.error_kind == "policy_denial"
    assert res.denied_rule == "tool.unknown"


def test_list_read_search(tools: ToolExecutor) -> None:
    listed = tools.execute("list_files", {})
    assert listed.ok
    paths = {e["path"] for e in listed.output["entries"]}
    assert "paginator/core.py" in paths

    read = tools.execute(
        "read_file", {"path": "paginator/core.py", "start_line": 1, "max_lines": 5}
    )
    assert read.ok
    assert read.output["content"].splitlines()[0].startswith("    1| ")
    assert read.output["truncated"] is True

    found = tools.execute("search", {"query": "start = page"})
    assert found.ok
    assert found.output["matches"] == [
        {"path": "paginator/core.py", "line": 32, "text": "    start = page * per_page"}
    ]


@pytest.mark.parametrize(
    ("name", "args"),
    [
        ("read_file", {"path": "../../etc/passwd"}),
        ("read_file", {"path": "/etc/passwd"}),
        ("list_files", {"path": ".."}),
        ("search", {"query": "root", "path": "/etc"}),
        ("apply_patch", {"edits": [{"path": "../x", "old": "a", "new": "b"}]}),
        ("run_tests", {"command": "bash"}),
        ("run_tests", {"command": "unittest", "selector": "--help"}),
        ("run_tests", {"command": "unittest", "selector": "os.system"}),
        ("run_tests", {"command": "unittest", "selector": "tests; rm -rf /"}),
        ("run_tests", {"command": "python3 -c 'import os'"}),
    ],
)
def test_policy_denials(
    tools: ToolExecutor, runner: FakeRunner, name: str, args: dict[str, object]
) -> None:
    res = tools.execute(name, args)
    assert not res.ok
    assert res.error_kind == "policy_denial", res
    assert res.denied_rule
    assert runner.calls == []


@pytest.mark.parametrize(
    ("name", "args"),
    [
        ("read_file", {}),
        ("read_file", {"path": "a", "max_lines": 10_000}),
        ("read_file", {"path": "a", "extra": 1}),
        ("search", {"query": ""}),
        ("search", {"query": "x" * 500}),
        ("apply_patch", {"edits": []}),
        ("apply_patch", {"edits": "not-a-list"}),
        ("run_tests", {"command": "unittest", "argv": ["sh"]}),
        ("finish", {"summary": "x" * 5000}),
    ],
)
def test_invalid_arguments(tools: ToolExecutor, name: str, args: dict[str, object]) -> None:
    res = tools.execute(name, args)
    assert not res.ok
    assert res.error_kind == "invalid_arguments"


def test_run_tests_uses_fixed_argv(tools: ToolExecutor, runner: FakeRunner, ws: Workspace) -> None:
    res = tools.execute("run_tests", {"command": "unittest"})
    assert res.ok
    assert res.output["passed"] is True
    path, cmd = runner.calls[0]
    assert path == ws.path
    assert cmd.argv == ALLOWED_COMMANDS["unittest"].argv

    tools.execute("run_tests", {"command": "unittest", "selector": "tests.test_core.PaginateTest"})
    assert runner.calls[1][1].argv[-1] == "tests.test_core.PaginateTest"


def test_run_tests_reports_failures(ws: Workspace) -> None:
    stderr = "FAIL: test_x\n----\nRan 6 tests in 0.002s\n\nFAILED (failures=2)\n"
    tools = ToolExecutor(ToolContext(workspace=ws, runner=FakeRunner([outcome(1, stderr)])))
    res = tools.execute("run_tests", {"command": "unittest"})
    assert res.ok
    assert res.output["passed"] is False
    assert res.output["tests_run"] == 6
    assert res.output["failures"] == "failures=2"


def test_build_command_rejects_unknown() -> None:
    assert build_command("unittest").argv[:3] == ("python3", "-m", "unittest")
