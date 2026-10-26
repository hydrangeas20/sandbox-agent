"""Shared fixtures.

Docker-marked tests are skipped when no daemon/image is available, *unless*
``SANDBOX_AGENT_REQUIRE_DOCKER=1`` (set in CI), in which case they fail. A
skipped security test is reported by pytest's ``-ra`` summary; it is never
counted as a pass.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from sandbox_agent.config import DEFAULT_IMAGE

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = REPO_ROOT / "fixtures" / "repos"


def _docker_ready() -> tuple[bool, str]:
    docker = shutil.which("docker")
    if docker is None:
        return False, "docker CLI not found"
    try:
        subprocess.run(
            [docker, "image", "inspect", DEFAULT_IMAGE],
            check=True,
            capture_output=True,
            timeout=20,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        return False, f"docker daemon or image {DEFAULT_IMAGE} unavailable: {exc}"
    return True, ""


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    ready, reason = _docker_ready()
    if ready:
        return
    if os.environ.get("SANDBOX_AGENT_REQUIRE_DOCKER") == "1":
        raise pytest.UsageError(f"SANDBOX_AGENT_REQUIRE_DOCKER=1 but {reason}")
    skip = pytest.mark.skip(reason=reason)
    for item in items:
        if "docker" in item.keywords:
            item.add_marker(skip)


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES


@pytest.fixture
def tmp_fixtures(tmp_path: Path) -> Path:
    """A scratch fixture registry for tests that build hostile repositories."""
    root = tmp_path / "registry"
    root.mkdir()
    return root
