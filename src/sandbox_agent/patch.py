"""Validated, atomic search/replace patches.

A patch is a list of exact-match edits. Each ``old`` string must occur
**exactly once** in the file's current (in-memory) content. All edits are
validated against in-memory copies first; files are written only if every
edit succeeds, so a malformed patch leaves the workspace untouched.

Exact-match edits were chosen over unified diffs because they are trivially
validated, cannot target lines the model has not seen, and fail loudly instead
of fuzzy-applying.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator

from sandbox_agent.config import PatchLimits
from sandbox_agent.errors import PolicyViolation
from sandbox_agent.workspace import Workspace

_MAX_TEXT = 64 * 1024


class Edit(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str = Field(min_length=1, max_length=255)
    old: str = Field(min_length=1, max_length=_MAX_TEXT)
    new: str = Field(max_length=_MAX_TEXT)

    @field_validator("old", "new")
    @classmethod
    def _no_nul(cls, value: str) -> str:
        if "\x00" in value:
            raise ValueError("edit text must not contain NUL bytes")
        return value


class PatchResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    files_changed: list[str]
    edits_applied: int


def apply_patch(workspace: Workspace, edits: list[Edit], limits: PatchLimits) -> PatchResult:
    if not edits:
        raise PolicyViolation("patch.empty", "patch contains no edits")
    if len(edits) > limits.max_edits:
        raise PolicyViolation("patch.too_many_edits", f"at most {limits.max_edits} edits allowed")

    pending: dict[str, str] = {}
    canonical: dict[str, str] = {}
    for index, edit in enumerate(edits):
        for label, text in (("old", edit.old), ("new", edit.new)):
            if len(text.encode()) > limits.max_text_bytes:
                raise PolicyViolation("patch.too_large", f"edit {index} {label} text too large")
        if edit.old == edit.new:
            raise PolicyViolation("patch.noop", f"edit {index} does not change anything")
        resolved = workspace.resolve(edit.path, kind="file")
        key = resolved.relative_to(workspace.path).as_posix()
        canonical[key] = edit.path
        content = pending[key] if key in pending else workspace.read_text(edit.path)
        count = content.count(edit.old)
        if count == 0:
            raise PolicyViolation("patch.no_match", f"edit {index}: `old` text not found in {key}")
        if count > 1:
            raise PolicyViolation(
                "patch.ambiguous", f"edit {index}: `old` text occurs {count} times in {key}"
            )
        pending[key] = content.replace(edit.old, edit.new, 1)

    for key, content in pending.items():
        if len(content.encode()) > workspace.limits.max_file_bytes:
            raise PolicyViolation("patch.result_too_large", f"patched {key} would exceed the limit")
    for key, content in pending.items():
        workspace.write_text(canonical[key], content)
    return PatchResult(files_changed=sorted(pending), edits_applied=len(edits))
