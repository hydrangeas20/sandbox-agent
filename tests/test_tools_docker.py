"""run_tests against the real sandbox on the buggy fixture."""

from __future__ import annotations

from pathlib import Path

import pytest

from sandbox_agent.config import SandboxConfig, WorkspaceLimits
from sandbox_agent.sandbox import DockerSandbox
from sandbox_agent.tools import ToolContext, ToolExecutor
from sandbox_agent.workspace import Workspace

pytestmark = pytest.mark.docker


def test_run_tests_in_sandbox_reports_real_failures(fixtures_dir: Path, tmp_path: Path) -> None:
    with Workspace.create(fixtures_dir / "paginator", WorkspaceLimits(), base_dir=tmp_path) as ws:
        tools = ToolExecutor(ToolContext(ws, DockerSandbox(SandboxConfig(), ws.root)))
        res = tools.execute("run_tests", {"command": "unittest"})
        assert res.ok, res
        assert res.output["passed"] is False
        assert res.output["tests_run"] == 6
        assert res.output["failures"] == "failures=2"
        assert res.output["resources"]["timed_out"] is False

        one = tools.execute(
            "run_tests",
            {"command": "unittest", "selector": "tests.test_core.TotalPagesTest"},
        )
        assert one.output["passed"] is True
        assert one.output["tests_run"] == 3
