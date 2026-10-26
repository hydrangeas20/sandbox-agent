"""Host-side unified diff between the original fixture and the workspace.

Pure text comparison with :mod:`difflib`; no repository code is executed and
symlinks are never followed (they are reported, not diffed).
"""

from __future__ import annotations

import difflib
import os
import stat
from pathlib import Path

MAX_DIFF_CHARS = 256 * 1024


def _snapshot(root: Path) -> dict[str, tuple[str, bytes | str]]:
    files: dict[str, tuple[str, bytes | str]] = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        for name in sorted(filenames + [d for d in dirnames if (Path(dirpath) / d).is_symlink()]):
            full = Path(dirpath) / name
            rel = full.relative_to(root).as_posix()
            mode = os.lstat(full).st_mode
            if stat.S_ISLNK(mode):
                files[rel] = ("link", os.readlink(full))
            elif stat.S_ISREG(mode):
                files[rel] = ("file", full.read_bytes())
    return files


def unified_diff(original: Path, modified: Path) -> tuple[str, list[str]]:
    """Return (diff text, changed paths)."""
    before, after = _snapshot(original), _snapshot(modified)
    chunks: list[str] = []
    changed: list[str] = []
    for rel in sorted(set(before) | set(after)):
        old, new = before.get(rel), after.get(rel)
        if old == new:
            continue
        changed.append(rel)
        if (old and old[0] == "link") or (new and new[0] == "link"):
            chunks.append(f"# symlink changed: {rel}\n")
            continue
        old_text = _text(old)
        new_text = _text(new)
        if old_text is None or new_text is None:
            chunks.append(f"# binary file changed: {rel}\n")
            continue
        chunks.extend(
            difflib.unified_diff(
                old_text.splitlines(keepends=True),
                new_text.splitlines(keepends=True),
                fromfile=f"a/{rel}" if old else "/dev/null",
                tofile=f"b/{rel}" if new else "/dev/null",
            )
        )
    text = "".join(chunks)
    if len(text) > MAX_DIFF_CHARS:
        text = text[:MAX_DIFF_CHARS] + "\n# diff truncated\n"
    return text, changed


def _text(entry: tuple[str, bytes | str] | None) -> str | None:
    if entry is None:
        return ""
    data = entry[1]
    if isinstance(data, str):
        return data
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def diff_policy_violations(original: Path, modified: Path, changed: list[str]) -> list[str]:
    """Final-diff allowlist, checked at the controller boundary (SR-03).

    Independently of how the workspace was changed, the only acceptable result is a
    modification of an existing, non-protected regular file. Additions, deletions,
    symlink or type changes, and any change under a protected path are violations.
    """
    from sandbox_agent.policy import protected_reason  # noqa: PLC0415 - avoid import cycle

    violations: list[str] = []
    for rel in changed:
        reason = protected_reason(rel)
        if reason is not None:
            violations.append(f"{rel}: {reason}")
            continue
        kinds = []
        for root in (original, modified):
            try:
                mode = os.lstat(root / rel).st_mode
                kinds.append("file" if stat.S_ISREG(mode) else "other")
            except FileNotFoundError:
                kinds.append("missing")
        if kinds != ["file", "file"]:
            violations.append(f"{rel}: only modifications of existing files are allowed ({kinds})")
    return violations
