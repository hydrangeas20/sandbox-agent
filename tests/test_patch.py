"""Patch validation: exact single match, atomicity, size limits, malformed input."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from sandbox_agent.config import PatchLimits, WorkspaceLimits
from sandbox_agent.errors import PolicyViolation
from sandbox_agent.patch import Edit, apply_patch
from sandbox_agent.workspace import Workspace

LIMITS = PatchLimits()


@pytest.fixture
def ws(tmp_path: Path) -> Workspace:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.py").write_text("x = 1\ny = 2\nx = 1\n")
    (repo / "b.py").write_text("value = 'old'\n")
    return Workspace.create(repo, WorkspaceLimits(max_file_bytes=4096), base_dir=tmp_path)


def test_single_edit_applies(ws: Workspace) -> None:
    res = apply_patch(ws, [Edit(path="b.py", old="'old'", new="'new'")], LIMITS)
    assert res.files_changed == ["b.py"]
    assert ws.read_text("b.py") == "value = 'new'\n"


def test_sequential_edits_same_file(ws: Workspace) -> None:
    edits = [
        Edit(path="a.py", old="y = 2", new="y = 3"),
        Edit(path="a.py", old="y = 3", new="y = 4"),
    ]
    apply_patch(ws, edits, LIMITS)
    assert "y = 4" in ws.read_text("a.py")


@pytest.mark.parametrize(
    ("edit", "rule"),
    [
        (Edit(path="a.py", old="x = 1", new="x = 9"), "patch.ambiguous"),
        (Edit(path="a.py", old="zzz", new="q"), "patch.no_match"),
        (Edit(path="a.py", old="y = 2", new="y = 2"), "patch.noop"),
        (Edit(path="../a.py", old="x", new="y"), "path.traversal"),
        (Edit(path="missing.py", old="x", new="y"), "path.not_found"),
        (Edit(path="b.py", old="'old'", new="z" * 5000), "patch.result_too_large"),
    ],
)
def test_bad_edits_rejected(ws: Workspace, edit: Edit, rule: str) -> None:
    with pytest.raises(PolicyViolation) as info:
        apply_patch(ws, [edit], LIMITS)
    assert info.value.rule == rule


def test_patch_is_atomic(ws: Workspace) -> None:
    before_a, before_b = ws.read_text("a.py"), ws.read_text("b.py")
    edits = [
        Edit(path="b.py", old="'old'", new="'new'"),
        Edit(path="a.py", old="does-not-exist", new="boom"),
    ]
    with pytest.raises(PolicyViolation):
        apply_patch(ws, edits, LIMITS)
    assert ws.read_text("a.py") == before_a
    assert ws.read_text("b.py") == before_b


def test_limits_on_edit_count_and_size(ws: Workspace) -> None:
    with pytest.raises(PolicyViolation, match="no edits"):
        apply_patch(ws, [], LIMITS)
    many = [Edit(path="b.py", old="'old'", new=f"'{i}'") for i in range(3)]
    with pytest.raises(PolicyViolation) as info:
        apply_patch(ws, many, PatchLimits(max_edits=2))
    assert info.value.rule == "patch.too_many_edits"
    with pytest.raises(PolicyViolation) as info:
        apply_patch(
            ws, [Edit(path="b.py", old="'old'", new="x" * 100)], PatchLimits(max_text_bytes=16)
        )
    assert info.value.rule == "patch.too_large"


@pytest.mark.parametrize(
    "payload",
    [
        {"path": "a.py", "old": "", "new": "x"},
        {"path": "a.py", "old": "x\x00", "new": "y"},
        {"path": "a.py", "old": "x"},
        {"path": "a.py", "old": "x", "new": "y", "mode": "0777"},
        {"path": "", "old": "x", "new": "y"},
        {"path": "a.py", "old": 5, "new": "y"},
    ],
)
def test_malformed_edits_fail_validation(payload: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        Edit.model_validate(payload)
