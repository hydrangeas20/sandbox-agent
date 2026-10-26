"""Disposable workspaces and path policy.

The workspace is a private copy of a fixture repository. Host code touches it
only through :meth:`Workspace.resolve`, which enforces:

* lexical rules: relative POSIX paths only; no ``..``, NUL, backslash, drive
  prefixes, ``~`` or control characters; bounded length and depth;
* filesystem rules: every component is ``lstat``-ed; **any** symlink component
  is refused (even one pointing inside the workspace), and only regular files
  and directories are accepted.

All file I/O is **descriptor-relative**: each path component is opened with
``O_NOFOLLOW`` (``O_DIRECTORY`` for parents) relative to the previous component's
descriptor, so replacing a parent directory with a symlink between validation and
use cannot redirect a read or write. Files are opened ``O_NONBLOCK`` and checked
with ``fstat`` (FIFOs and devices never block or get read). Writes use a temp file
created ``O_EXCL`` in the parent descriptor and ``os.replace`` relative to it.

The container mounts the workspace read-only, so untrusted *execution* cannot race
these checks at all; the descriptor-relative walk also covers other host processes
and the fixture copy (SECURITY_REVIEW SR-08/SR-09).
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import re
import secrets
import shutil
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Literal

from sandbox_agent.config import WorkspaceLimits
from sandbox_agent.errors import FixtureError, PolicyViolation, WorkspaceError
from sandbox_agent.ownership import current_owner, owner_alive

_PREFIX = "sandbox-agent-"
_OWNER_FILE = ".owner"
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


_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


def _open_child_dir(parent_fd: int, name: str, raw: str) -> int:
    try:
        return os.open(name, _DIR_FLAGS, dir_fd=parent_fd)
    except FileNotFoundError:
        raise PolicyViolation("path.not_found", f"{raw!r} does not exist") from None
    except OSError:
        # Classify for the error message only; the refusal itself already happened.
        try:
            is_link = stat.S_ISLNK(os.lstat(name, dir_fd=parent_fd).st_mode)
        except OSError:
            is_link = False
        if is_link:
            raise PolicyViolation("path.symlink", f"symlinks are not followed: {raw!r}") from None
        raise PolicyViolation("path.not_dir", f"{raw!r}: intermediate is not a directory") from None


def _open_regular(parent_fd: int, name: str, raw: str) -> tuple[int, os.stat_result]:
    """Open an existing regular file relative to ``parent_fd`` without following links."""
    try:
        fd = os.open(name, _FILE_FLAGS, dir_fd=parent_fd)
    except FileNotFoundError:
        raise PolicyViolation("path.not_found", f"{raw!r} does not exist") from None
    except OSError as exc:
        if exc.errno == 40:
            raise PolicyViolation("path.symlink", f"symlinks are not followed: {raw!r}") from None
        raise PolicyViolation("path.unreadable", f"{raw!r} cannot be opened") from None
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        os.close(fd)
        if stat.S_ISDIR(st.st_mode):
            raise PolicyViolation("path.not_file", f"{raw!r} is not a file")
        raise PolicyViolation("path.special_file", f"{raw!r} is not a regular file")
    return fd, st


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
        (root / _OWNER_FILE).write_text(current_owner())
        repo = root / "repo"
        ws = cls(root, repo, limits)
        try:
            _copy_tree(fixture_dir, repo, limits)
        except OSError as exc:
            ws.cleanup()
            raise WorkspaceError(f"could not copy fixture: {exc.strerror or exc}") from None
        except BaseException:
            ws.cleanup()
            raise
        return ws

    @staticmethod
    def reap_stale(base_dir: Path | None = None) -> int:
        """Remove workspaces left behind by a controller that died (SR-04).

        Only directories this package created (prefix, mode 0700, owned by this user,
        containing an owner tag) whose owning controller on this host is gone.
        """
        base = Path(base_dir or tempfile.gettempdir())
        removed = 0
        for candidate in base.glob(f"{_PREFIX}*"):
            try:
                st = os.lstat(candidate)
                if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid():
                    continue
                if st.st_mode & 0o777 != 0o700:
                    continue
                owner = (candidate / _OWNER_FILE).read_text()
            except OSError:
                continue
            if owner_alive(owner) is False:
                shutil.rmtree(candidate, ignore_errors=True)
                removed += 1
        return removed

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

    def _open_parent(self, raw: str) -> tuple[int, str]:
        """Return (fd of the parent directory, final component) for a workspace path."""
        parts = validate_relpath(raw, self.limits)
        if not parts:
            raise PolicyViolation("path.not_file", f"{raw!r} is the repository root")
        fd = os.open(self.path, _DIR_FLAGS)
        try:
            for part in parts[:-1]:
                # lstat first only to give a precise error; the O_NOFOLLOW open is authoritative.
                try:
                    if stat.S_ISLNK(os.lstat(part, dir_fd=fd).st_mode):
                        raise PolicyViolation("path.symlink", f"symlinks are not followed: {raw!r}")
                except FileNotFoundError:
                    raise PolicyViolation("path.not_found", f"{raw!r} does not exist") from None
                child = _open_child_dir(fd, part, raw)
                os.close(fd)
                fd = child
        except BaseException:
            os.close(fd)
            raise
        return fd, parts[-1]

    def read_text(self, raw: str) -> str:
        parent, name = self._open_parent(raw)
        try:
            fd, st = _open_regular(parent, name, raw)
        finally:
            os.close(parent)
        with os.fdopen(fd, "rb") as fh:
            if st.st_size > self.limits.max_file_bytes:
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
        parent, name = self._open_parent(raw)
        try:
            fd, _ = _open_regular(parent, name, raw)  # must already exist as a regular file
            os.close(fd)
            tmp_name = f".sa-tmp-{secrets.token_hex(8)}"
            tmp_fd = os.open(
                tmp_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o644,
                dir_fd=parent,
            )
            try:
                with os.fdopen(tmp_fd, "wb") as fh:
                    fh.write(data)
                # Re-check immediately before the swap; os.replace never follows a link at
                # the target, and both names are resolved relative to the same parent fd.
                if not stat.S_ISREG(os.lstat(name, dir_fd=parent).st_mode):
                    raise PolicyViolation("path.symlink", f"{raw!r} changed type during write")
                os.replace(tmp_name, name, src_dir_fd=parent, dst_dir_fd=parent)
            finally:
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(tmp_name, dir_fd=parent)
        finally:
            os.close(parent)

    def list_entries(self, raw: str = ".") -> list[FileEntry]:
        """List entries recursively (descriptor-relative; symlinks listed, never entered)."""
        if raw in ("", "."):
            fd, prefix = os.open(self.path, _DIR_FLAGS), ""
        else:
            parent, name = self._open_parent(raw)
            try:
                fd = _open_child_dir(parent, name, raw)
            finally:
                os.close(parent)
            prefix = "/".join(validate_relpath(raw, self.limits)) + "/"
        entries: list[FileEntry] = []
        try:
            self._walk(fd, prefix, entries)
        finally:
            os.close(fd)
        return sorted(entries, key=lambda e: e.path)

    def _walk(self, fd: int, prefix: str, entries: list[FileEntry]) -> None:
        with os.scandir(fd) as it:
            listed = sorted(it, key=lambda e: e.name)
        for entry in listed:
            rel = prefix + entry.name
            st = entry.stat(follow_symlinks=False)
            if stat.S_ISLNK(st.st_mode):
                entries.append(FileEntry(rel, "symlink", 0))
            elif stat.S_ISDIR(st.st_mode):
                entries.append(FileEntry(rel, "dir", 0))
                try:
                    child = os.open(entry.name, _DIR_FLAGS, dir_fd=fd)
                except OSError:
                    continue  # changed type since listing: skip rather than follow
                try:
                    self._walk(child, rel + "/", entries)
                finally:
                    os.close(child)
            elif stat.S_ISREG(st.st_mode):
                entries.append(FileEntry(rel, "file", st.st_size))


def _copy_tree(src: Path, dst: Path, limits: WorkspaceLimits) -> None:
    """Copy a fixture without following symlinks, descriptor-relative throughout.

    Rejects special files and hard links, enforces entry and byte limits on the bytes
    actually copied, and detects entries swapped between listing and opening.
    """
    budget = {"entries": 0, "bytes": 0}
    os.mkdir(dst, 0o755)
    src_fd = os.open(src, _DIR_FLAGS)
    dst_fd = os.open(dst, _DIR_FLAGS)
    try:
        _copy_dir(src_fd, dst_fd, limits, budget)
    finally:
        os.close(src_fd)
        os.close(dst_fd)


def _copy_dir(src_fd: int, dst_fd: int, limits: WorkspaceLimits, budget: dict[str, int]) -> None:
    with os.scandir(src_fd) as it:
        entries = sorted(it, key=lambda e: e.name)
    for entry in entries:
        budget["entries"] += 1
        if budget["entries"] > limits.max_entries:
            raise WorkspaceError(f"fixture has more than {limits.max_entries} entries")
        name = entry.name
        listed = entry.stat(follow_symlinks=False)
        if stat.S_ISLNK(listed.st_mode):
            # Preserved as an inert link; tools refuse to traverse it.
            os.symlink(os.readlink(name, dir_fd=src_fd), name, dir_fd=dst_fd)
        elif stat.S_ISDIR(listed.st_mode):
            try:
                child_src = os.open(name, _DIR_FLAGS, dir_fd=src_fd)
            except OSError:
                raise WorkspaceError(f"fixture entry {name!r} changed during copy") from None
            try:
                if not _same_inode(os.fstat(child_src), listed):
                    raise WorkspaceError(f"fixture entry {name!r} changed during copy")
                os.mkdir(name, 0o755, dir_fd=dst_fd)
                child_dst = os.open(name, _DIR_FLAGS, dir_fd=dst_fd)
                try:
                    _copy_dir(child_src, child_dst, limits, budget)
                finally:
                    os.close(child_dst)
            finally:
                os.close(child_src)
        elif stat.S_ISREG(listed.st_mode):
            _copy_file(src_fd, dst_fd, name, listed=listed, limits=limits, budget=budget)
        else:
            raise WorkspaceError(f"special file in fixture: {name!r}")


def _copy_file(
    src_fd: int,
    dst_fd: int,
    name: str,
    *,
    listed: os.stat_result,
    limits: WorkspaceLimits,
    budget: dict[str, int],
) -> None:
    try:
        rfd = os.open(name, _FILE_FLAGS, dir_fd=src_fd)
    except OSError as exc:
        if exc.errno == 40:
            raise WorkspaceError(f"fixture entry {name!r} changed during copy") from None
        raise
    with os.fdopen(rfd, "rb") as rf:
        st = os.fstat(rf.fileno())
        if not stat.S_ISREG(st.st_mode) or not _same_inode(st, listed):
            raise WorkspaceError(f"fixture entry {name!r} changed during copy")
        if st.st_nlink > 1:
            # A hard link can alias a file outside the fixture tree (e.g. a host secret).
            raise WorkspaceError(f"hard link in fixture is not allowed: {name!r}")
        wfd = os.open(
            name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644, dir_fd=dst_fd
        )
        with os.fdopen(wfd, "wb") as wf:
            while chunk := rf.read(65536):
                budget["bytes"] += len(chunk)
                if budget["bytes"] > limits.max_total_bytes:
                    raise WorkspaceError(f"fixture exceeds {limits.max_total_bytes} bytes")
                wf.write(chunk)
    # Modes are normalised to 0644 at creation: setuid/setgid/exec bits are dropped.


def _same_inode(a: os.stat_result, b: os.stat_result) -> bool:
    return (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino)


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
    """SHA-256 over every entry (path, type, content or link target). Never follows links.

    Special files (FIFOs, sockets, devices) are hashed by type and mode only; they are
    never opened for reading, so a FIFO cannot block the integrity check (SR-06).
    """
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
            elif stat.S_ISREG(st.st_mode):
                digest.update(f"F {rel} {st.st_mode & 0o777:o}\n".encode())
                digest.update(_hash_regular(full))
            else:
                digest.update(
                    f"S {rel} {stat.S_IFMT(st.st_mode):o} {st.st_mode & 0o777:o}\n".encode()
                )
    return digest.hexdigest()


def _hash_regular(path: Path) -> bytes:
    try:
        fd = os.open(path, _FILE_FLAGS)
    except OSError:
        return b"unreadable"
    with os.fdopen(fd, "rb") as fh:
        if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
            return b"changed-type"
        h = hashlib.sha256()
        while chunk := fh.read(1 << 20):
            h.update(chunk)
        return h.digest()
