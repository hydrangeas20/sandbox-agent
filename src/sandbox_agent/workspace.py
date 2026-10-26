"""Disposable workspaces and path policy.

The workspace is a private copy of a fixture repository. Host code touches it
only through :meth:`Workspace.resolve`, which enforces:

* lexical rules: relative POSIX paths only; no ``..``, NUL, backslash, drive
  prefixes, ``~`` or control characters; bounded length and depth;
* filesystem rules: every component is ``lstat``-ed; **any** symlink component
  is refused (even one pointing inside the workspace), and only regular files
  and directories are accepted.

Writes go through a temp file created with ``O_EXCL | O_NOFOLLOW`` and an
atomic ``os.replace``. The container mounts the workspace read-only, so no
untrusted process can race these checks by creating links.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import re
import shutil
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Literal

from sandbox_agent.config import WorkspaceLimits
from sandbox_agent.errors import FixtureError, PolicyViolation, WorkspaceError

_PREFIX = "sandbox-agent-"
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_DRIVE = re.compile(r"^[A-Za-z]:")
_FIXTURE_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")

Kind = Literal["file", "dir", "any"]


def validate_relpath(raw: str, limits: WorkspaceLimits) -> tuple[str, ...]:
    """Lexically validate a workspace-relative path and return its components."""
    if not isinstance(raw, str) or not raw.strip():
        raise PolicyViolation("path.empty", "path must be a non-empty string")
    if len(raw) > limits.max_path_chars:
        raise PolicyViolation("path.too_long", f"path exceeds {limits.max_path_chars} chars")
    if _CONTROL.search(raw):
        raise PolicyViolation("path.control_chars", "path contains NUL or control characters")
    if "\\" in raw:
        raise PolicyViolation("path.backslash", "backslashes are not allowed")
    if raw.startswith(("/", "~")) or _DRIVE.match(raw):
        raise PolicyViolation("path.absolute", f"absolute paths are not allowed: {raw!r}")
    parts = tuple(p for p in PurePosixPath(raw).parts if p not in ("", "."))
    if any(p == ".." for p in raw.split("/")):
        raise PolicyViolation(
            "path.traversal", f"parent-directory components are not allowed: {raw!r}"
        )
    if len(parts) > limits.max_path_depth:
        raise PolicyViolation("path.too_deep", f"path deeper than {limits.max_path_depth}")
    return parts


@dataclass(frozen=True)
class FileEntry:
    path: str
    kind: Literal["file", "dir", "symlink"]
    size: int


class Workspace:
    """A disposable, private copy of a fixture repository."""

    def __init__(self, root: Path, repo: Path, limits: WorkspaceLimits) -> None:
        self._root = root
        self.path = repo
        self.limits = limits
        self._cleaned = False

    # ------------------------------------------------------------------ lifecycle

    @classmethod
    def create(
        cls, fixture_dir: Path, limits: WorkspaceLimits, base_dir: Path | None = None
    ) -> Workspace:
        if fixture_dir.is_symlink() or not fixture_dir.is_dir():
            raise WorkspaceError(f"fixture {fixture_dir} must be a real directory")
        root = Path(tempfile.mkdtemp(prefix=_PREFIX, dir=base_dir)).resolve()
        os.chmod(root, 0o700)
        repo = root / "repo"
        ws = cls(root, repo, limits)
        try:
            _copy_tree(fixture_dir, repo, limits)
        except BaseException:
            ws.cleanup()
            raise
        return ws

    @property
    def root(self) -> Path:
        """Private parent directory (mode 0700). Also the sandbox's allowed mount root."""
        return self._root

    def cleanup(self) -> None:
        """Remove the workspace. Idempotent; refuses to delete anything it did not create."""
        if self._cleaned:
            return
        root = self._root
        if root.is_symlink() or not root.name.startswith(_PREFIX):
            raise WorkspaceError(f"refusing to delete unexpected path {root}")
        if root.exists():
            # rmtree unlinks symlinks rather than following them (fd-based on Linux).
            shutil.rmtree(root)
        self._cleaned = True

    def __enter__(self) -> Workspace:
        return self

    def __exit__(self, *exc: object) -> None:
        self.cleanup()

    # ------------------------------------------------------------------ path policy

    def resolve(self, raw: str, *, kind: Kind = "any", must_exist: bool = True) -> Path:
        parts = validate_relpath(raw, self.limits)
        current = self.path
        for index, part in enumerate(parts):
            current = current / part
            last = index == len(parts) - 1
            try:
                st = os.lstat(current)
            except FileNotFoundError:
                if must_exist or not last:
                    raise PolicyViolation("path.not_found", f"{raw!r} does not exist") from None
                return current
            if stat.S_ISLNK(st.st_mode):
                raise PolicyViolation("path.symlink", f"symlinks are not followed: {raw!r}")
            if not last and not stat.S_ISDIR(st.st_mode):
                raise PolicyViolation("path.not_dir", f"{raw!r}: intermediate is not a directory")
            if last:
                is_file, is_dir = stat.S_ISREG(st.st_mode), stat.S_ISDIR(st.st_mode)
                if not (is_file or is_dir):
                    raise PolicyViolation("path.special_file", f"{raw!r} is not a regular file")
                if kind == "file" and not is_file:
                    raise PolicyViolation("path.not_file", f"{raw!r} is not a file")
                if kind == "dir" and not is_dir:
                    raise PolicyViolation("path.not_dir", f"{raw!r} is not a directory")
        return current

    # ------------------------------------------------------------------ file I/O

    def read_text(self, raw: str) -> str:
        path = self.resolve(raw, kind="file")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as fh:
            if os.fstat(fh.fileno()).st_size > self.limits.max_file_bytes:
                raise PolicyViolation(
                    "file.too_large", f"{raw!r} exceeds {self.limits.max_file_bytes} bytes"
                )
            data = fh.read(self.limits.max_file_bytes + 1)
        if len(data) > self.limits.max_file_bytes:
            raise PolicyViolation("file.too_large", f"{raw!r} grew beyond the read limit")
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            raise PolicyViolation("file.binary", f"{raw!r} is not UTF-8 text") from None

    def write_text(self, raw: str, content: str) -> None:
        """Replace an *existing* regular file atomically, never following links."""
        data = content.encode("utf-8")
        if len(data) > self.limits.max_file_bytes:
            raise PolicyViolation(
                "file.too_large", f"result exceeds {self.limits.max_file_bytes} bytes"
            )
        target = self.resolve(raw, kind="file")
        fd, tmp_name = tempfile.mkstemp(dir=target.parent, prefix=".sa-tmp-")
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            os.chmod(tmp_name, 0o644)
            # Re-check immediately before the swap; os.replace never follows a link at target.
            swap_ok = stat.S_ISREG(os.lstat(target).st_mode)
            if swap_ok:
                os.replace(tmp_name, target)
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp_name)
        if not swap_ok:
            raise PolicyViolation("path.symlink", f"{raw!r} changed type during write")

    def list_entries(self, raw: str = ".") -> list[FileEntry]:
        base = self.path if raw in ("", ".") else self.resolve(raw, kind="dir")
        entries: list[FileEntry] = []
        stack = [base]
        while stack:
            current = stack.pop()
            with os.scandir(current) as it:
                for entry in sorted(it, key=lambda e: e.name):
                    rel = Path(entry.path).relative_to(self.path).as_posix()
                    if entry.is_symlink():
                        entries.append(FileEntry(rel, "symlink", 0))
                    elif entry.is_dir(follow_symlinks=False):
                        entries.append(FileEntry(rel, "dir", 0))
                        stack.append(Path(entry.path))
                    elif entry.is_file(follow_symlinks=False):
                        entries.append(
                            FileEntry(rel, "file", entry.stat(follow_symlinks=False).st_size)
                        )
        return sorted(entries, key=lambda e: e.path)


def _copy_tree(src: Path, dst: Path, limits: WorkspaceLimits) -> None:
    """Copy a fixture without following symlinks; reject special files; enforce limits."""
    entries = 0
    total = 0
    os.mkdir(dst, 0o755)
    stack: list[tuple[Path, Path]] = [(src, dst)]
    while stack:
        s_dir, d_dir = stack.pop()
        with os.scandir(s_dir) as it:
            for entry in it:
                entries += 1
                if entries > limits.max_entries:
                    raise WorkspaceError(f"fixture has more than {limits.max_entries} entries")
                s_path, d_path = Path(entry.path), d_dir / entry.name
                st = entry.stat(follow_symlinks=False)
                if stat.S_ISLNK(st.st_mode):
                    # Preserved as an inert link; tools refuse to traverse it.
                    os.symlink(os.readlink(s_path), d_path)
                elif stat.S_ISDIR(st.st_mode):
                    os.mkdir(d_path, 0o755)
                    stack.append((s_path, d_path))
                elif stat.S_ISREG(st.st_mode):
                    total += st.st_size
                    if total > limits.max_total_bytes:
                        raise WorkspaceError(f"fixture exceeds {limits.max_total_bytes} bytes")
                    fd = os.open(s_path, os.O_RDONLY | os.O_NOFOLLOW)
                    with os.fdopen(fd, "rb") as rf, open(d_path, "xb") as wf:
                        shutil.copyfileobj(rf, wf)
                    # Normalise modes: strips setuid/setgid/exec bits from untrusted content.
                    os.chmod(d_path, 0o644)
                else:
                    raise WorkspaceError(f"special file in fixture: {entry.name!r}")


# ---------------------------------------------------------------------- fixtures


class FixtureRegistry:
    """Resolves fixture *names* to directories. Never accepts arbitrary paths."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()

    def names(self) -> list[str]:
        if not self.root.is_dir():
            return []
        return sorted(
            p.name
            for p in self.root.iterdir()
            if _FIXTURE_NAME.fullmatch(p.name) and p.is_dir() and not p.is_symlink()
        )

    def resolve(self, name: str) -> Path:
        if not isinstance(name, str) or not _FIXTURE_NAME.fullmatch(name):
            raise FixtureError(f"invalid fixture name: {name!r}")
        path = self.root / name
        if path.is_symlink() or not path.is_dir():
            raise FixtureError(f"unknown fixture: {name!r}")
        if path.resolve().parent != self.root:
            raise FixtureError(f"fixture {name!r} escapes the registry")
        return path


def tree_manifest(root: Path) -> str:
    """SHA-256 over every entry (path, type, content or link target). Never follows links."""
    digest = hashlib.sha256()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        for name in sorted(dirnames + filenames):
            full = Path(dirpath) / name
            rel = full.relative_to(root).as_posix()
            st = os.lstat(full)
            if stat.S_ISLNK(st.st_mode):
                digest.update(f"L {rel} -> {os.readlink(full)}\n".encode())
            elif stat.S_ISDIR(st.st_mode):
                digest.update(f"D {rel}\n".encode())
            else:
                digest.update(f"F {rel} {st.st_mode & 0o777:o}\n".encode())
                digest.update(hashlib.sha256(full.read_bytes()).digest())
    return digest.hexdigest()
