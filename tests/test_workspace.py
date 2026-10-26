"""Workspace creation, path policy, symlink defences, limits and cleanup."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from sandbox_agent.config import WorkspaceLimits
from sandbox_agent.errors import FixtureError, PolicyViolation, WorkspaceError
from sandbox_agent.workspace import FixtureRegistry, Workspace, tree_manifest

LIMITS = WorkspaceLimits()


@pytest.fixture
def fixture_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "fixture"
    (repo / "pkg").mkdir(parents=True)
    (repo / "pkg" / "mod.py").write_text("x = 1\n")
    (repo / "README.md").write_text("hello\n")
    outside = tmp_path / "host_secret.txt"
    outside.write_text("TOP SECRET HOST FILE\n")
    (repo / "secret_link").symlink_to(outside)
    (repo / "etc_link").symlink_to("/etc")
    (repo / "inner_link").symlink_to("pkg/mod.py")
    return repo


@pytest.fixture
def ws(fixture_repo: Path, tmp_path: Path) -> Workspace:
    base = tmp_path / "ws_base"
    base.mkdir()
    return Workspace.create(fixture_repo, LIMITS, base_dir=base)


TRAVERSALS = [
    "../README.md",
    "../../etc/passwd",
    "pkg/../../x",
    "pkg/..",
    "/etc/passwd",
    "~/.ssh/id_rsa",
    "C:\\Windows\\system32",
    "C:/Windows",
    "pkg\\mod.py",
    "pkg/mod.py\x00.txt",
    "pkg/\nmod.py",
    "",
    "   ",
    "a/" * 40 + "x",
    "x" * 300,
]


@pytest.mark.parametrize("raw", TRAVERSALS)
def test_traversal_rejected(ws: Workspace, raw: str) -> None:
    with pytest.raises(PolicyViolation):
        ws.resolve(raw)
    with pytest.raises(PolicyViolation):
        ws.read_text(raw)
    with pytest.raises(PolicyViolation):
        ws.write_text(raw, "pwned")


@pytest.mark.parametrize(
    "raw", ["secret_link", "etc_link/passwd", "etc_link", "inner_link", "./secret_link"]
)
def test_symlink_components_rejected(ws: Workspace, raw: str) -> None:
    with pytest.raises(PolicyViolation, match="symlink"):
        ws.read_text(raw)
    with pytest.raises(PolicyViolation, match="symlink"):
        ws.write_text(raw, "pwned")


def test_symlink_write_does_not_touch_target(ws: Workspace, tmp_path: Path) -> None:
    with pytest.raises(PolicyViolation):
        ws.write_text("secret_link", "overwritten")
    assert (tmp_path / "host_secret.txt").read_text() == "TOP SECRET HOST FILE\n"


def test_symlinks_copied_as_links_not_followed(ws: Workspace) -> None:
    link = ws.path / "secret_link"
    assert link.is_symlink()
    entries = {e.path: e.kind for e in ws.list_entries()}
    assert entries["secret_link"] == "symlink"
    assert entries["etc_link"] == "symlink"
    assert not any(p.startswith("etc_link/") for p in entries)


def test_symlink_swapped_in_after_copy_is_refused(ws: Workspace, tmp_path: Path) -> None:
    """A file replaced by a link between operations must not be followed."""
    target = ws.path / "README.md"
    target.unlink()
    target.symlink_to(tmp_path / "host_secret.txt")
    with pytest.raises(PolicyViolation, match="symlink"):
        ws.write_text("README.md", "pwned")
    assert (tmp_path / "host_secret.txt").read_text() == "TOP SECRET HOST FILE\n"


def test_directory_symlink_in_middle_rejected(ws: Workspace, tmp_path: Path) -> None:
    (ws.path / "pkg2").symlink_to(tmp_path)
    with pytest.raises(PolicyViolation, match="symlink"):
        ws.read_text("pkg2/host_secret.txt")


def test_special_files_rejected(ws: Workspace) -> None:
    os.mkfifo(ws.path / "pipe")
    with pytest.raises(PolicyViolation, match="regular"):
        ws.read_text("pipe")


def test_special_file_in_fixture_rejected(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    os.mkfifo(repo / "fifo")
    with pytest.raises(WorkspaceError, match="special"):
        Workspace.create(repo, LIMITS, base_dir=tmp_path)
    assert not any(p.name.startswith("sandbox-agent-") for p in tmp_path.iterdir())


def test_read_and_write_inside_workspace(ws: Workspace, fixture_repo: Path) -> None:
    assert ws.read_text("pkg/mod.py") == "x = 1\n"
    assert ws.read_text("./pkg//mod.py") == "x = 1\n"
    ws.write_text("pkg/mod.py", "x = 2\n")
    assert ws.read_text("pkg/mod.py") == "x = 2\n"
    assert (fixture_repo / "pkg" / "mod.py").read_text() == "x = 1\n"
    assert not any(p.name.startswith(".sa-tmp-") for p in (ws.path / "pkg").iterdir())


def test_write_requires_existing_file(ws: Workspace) -> None:
    with pytest.raises(PolicyViolation, match=r"not_found|does not exist"):
        ws.write_text("pkg/new.py", "x")
    with pytest.raises(PolicyViolation):
        ws.write_text("pkg", "x")


def test_file_size_limits(fixture_repo: Path, tmp_path: Path) -> None:
    (fixture_repo / "big.txt").write_text("a" * 5000)
    small = WorkspaceLimits(max_file_bytes=1024)
    with Workspace.create(fixture_repo, small, base_dir=tmp_path) as ws:
        with pytest.raises(PolicyViolation, match="too_large"):
            ws.read_text("big.txt")
        with pytest.raises(PolicyViolation, match="too_large"):
            ws.write_text("README.md", "b" * 2000)


def test_binary_file_rejected(ws: Workspace) -> None:
    (ws.path / "blob.bin").write_bytes(b"\xff\xfe\x00\x01")
    with pytest.raises(PolicyViolation, match="binary"):
        ws.read_text("blob.bin")


def test_copy_limits(tmp_path: Path) -> None:
    repo = tmp_path / "many"
    repo.mkdir()
    for i in range(30):
        (repo / f"f{i}.txt").write_text("x" * 100)
    with pytest.raises(WorkspaceError, match="entries"):
        Workspace.create(repo, WorkspaceLimits(max_entries=10), base_dir=tmp_path)
    with pytest.raises(WorkspaceError, match="bytes"):
        Workspace.create(repo, WorkspaceLimits(max_total_bytes=1024), base_dir=tmp_path)
    assert not any(p.name.startswith("sandbox-agent-") for p in tmp_path.iterdir())


def test_copy_strips_dangerous_modes(tmp_path: Path) -> None:
    repo = tmp_path / "modes"
    repo.mkdir()
    exe = repo / "run.sh"
    exe.write_text("#!/bin/sh\n")
    exe.chmod(0o4777)
    with Workspace.create(repo, LIMITS, base_dir=tmp_path) as ws:
        assert (ws.path / "run.sh").stat().st_mode & 0o7777 == 0o644


def test_workspace_root_is_private_and_cleanup_is_safe(ws: Workspace) -> None:
    assert ws.root.stat().st_mode & 0o777 == 0o700
    root = ws.root
    ws.cleanup()
    ws.cleanup()  # idempotent
    assert not root.exists()


def test_cleanup_does_not_follow_symlinks(ws: Workspace, tmp_path: Path) -> None:
    precious = tmp_path / "precious"
    precious.mkdir()
    (precious / "keep.txt").write_text("keep")
    (ws.path / "dirlink").symlink_to(precious)
    ws.cleanup()
    assert (precious / "keep.txt").read_text() == "keep"


def test_cleanup_refuses_unexpected_root(tmp_path: Path) -> None:
    other = tmp_path / "not-ours"
    other.mkdir()
    rogue = Workspace(other, other / "repo", LIMITS)
    with pytest.raises(WorkspaceError):
        rogue.cleanup()
    assert other.exists()


@pytest.mark.parametrize(
    "name", ["../paginator", "/etc", "paginator/..", "Paginator", ".hidden", "a b", "", "x" * 80]
)
def test_fixture_name_validation(fixtures_dir: Path, name: str) -> None:
    with pytest.raises(FixtureError):
        FixtureRegistry(fixtures_dir).resolve(name)


def test_fixture_registry_rejects_symlinked_fixture(tmp_fixtures: Path, tmp_path: Path) -> None:
    (tmp_fixtures / "real").mkdir()
    (tmp_fixtures / "linked").symlink_to(tmp_path)
    reg = FixtureRegistry(tmp_fixtures)
    assert reg.names() == ["real"]
    with pytest.raises(FixtureError):
        reg.resolve("linked")


def test_known_fixture_resolves(fixtures_dir: Path) -> None:
    reg = FixtureRegistry(fixtures_dir)
    assert "paginator" in reg.names()
    assert reg.resolve("paginator").is_dir()


def test_manifest_detects_changes(fixture_repo: Path) -> None:
    before = tree_manifest(fixture_repo)
    assert tree_manifest(fixture_repo) == before
    (fixture_repo / "pkg" / "mod.py").write_text("x = 3\n")
    assert tree_manifest(fixture_repo) != before
