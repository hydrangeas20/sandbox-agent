"""Workspace + sandbox integration: the real workspace layout is usable and read-only."""

from __future__ import annotations

from pathlib import Path

import pytest

from sandbox_agent.config import SandboxConfig, WorkspaceLimits
from sandbox_agent.sandbox import ContainerCommand, DockerSandbox
from sandbox_agent.workspace import Workspace, tree_manifest

pytestmark = pytest.mark.docker


def test_workspace_readonly_in_container(fixtures_dir: Path, tmp_path: Path) -> None:
    with Workspace.create(fixtures_dir / "paginator", WorkspaceLimits(), base_dir=tmp_path) as ws:
        before = tree_manifest(ws.path)
        sandbox = DockerSandbox(SandboxConfig(timeout_s=20), ws.root)
        code = (
            "import os\n"
            "for p in ('/workspace/paginator/core.py', '/workspace/new.py'):\n"
            "    try:\n        open(p, 'a').write('x'); print('WROTE', p)\n"
            "    except OSError as e:\n        print('DENIED', e.errno)\n"
            "try:\n    os.symlink('/etc/passwd', '/workspace/l'); print('LINKED')\n"
            "except OSError as e:\n    print('DENIED', e.errno)\n"
            "print(sorted(os.listdir('/workspace')))\n"
        )
        out = sandbox.run(ws.path, ContainerCommand(argv=("python3", "-c", code)))
        assert out.exit_code == 0, out.stderr
        assert "WROTE" not in out.stdout
        assert "LINKED" not in out.stdout
        lines = out.stdout.splitlines()
        # Existing files are root-owned 0644 (EACCES); new entries hit the read-only mount (EROFS).
        # The world-writable case proving EROFS alone is in test_sandbox_docker.py.
        assert lines[0] in ("DENIED 13", "DENIED 30")
        assert lines[1:3] == ["DENIED 30", "DENIED 30"]
        assert "paginator" in out.stdout
        assert tree_manifest(ws.path) == before
