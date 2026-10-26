"""Bootstrap a minimal Python 3.12 base image without registry access.

The canonical sandbox base is ``python:3.12-slim`` (see ``sandbox/Dockerfile``).
Some build environments block Docker Hub; this script builds an equivalent
*minimal* base by copying the host's Python 3.12 interpreter, its standard
library and the shared-library closure (via ``ldd``) into a deterministic tar,
then ``docker import``-ing it.

The resulting image deliberately contains **no shell and no coreutils** — only
the interpreter. It is an environment-specific fallback, documented in
``docs/DECISIONS.md``; it is not used by CI.

This script reads trusted host files only. It never touches fixture content.
"""

from __future__ import annotations

import argparse
import io
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

PYTHON = Path("/usr/bin/python3.12")
STDLIB = Path("/usr/lib/python3.12")
EXCLUDE_DIRS = {
    "test",
    "idlelib",
    "tkinter",
    "turtledemo",
    "ensurepip",
    "site-packages",
    "dist-packages",
    "__pycache__",
}
PASSWD = (
    "root:x:0:0:root:/root:/usr/sbin/nologin\n"
    "sandbox:x:10001:10001:sandbox:/tmp:/usr/sbin/nologin\n"
)
GROUP = "root:x:0:\nsandbox:x:10001:\n"


def _ldd_closure(binaries: list[Path]) -> set[Path]:
    libs: set[Path] = set()
    ldd = shutil.which("ldd")
    if ldd is None:
        raise SystemExit("ldd not found")
    for binary in binaries:
        out = subprocess.run([ldd, str(binary)], capture_output=True, text=True, check=False).stdout
        for line in out.splitlines():
            match = re.search(r"(/\S+)\s+\(0x", line)
            if match:
                libs.add(Path(match.group(1)))
    return libs


def _add_file(tar: tarfile.TarFile, src: Path, arcname: str) -> None:
    real = src.resolve()
    info = tarfile.TarInfo(arcname.lstrip("/"))
    data = real.read_bytes()
    info.size = len(data)
    info.mode = 0o755 if (real.stat().st_mode & 0o111) else 0o644
    info.mtime = 0
    tar.addfile(info, io.BytesIO(data))


def _add_dir(tar: tarfile.TarFile, arcname: str, mode: int = 0o755) -> None:
    info = tarfile.TarInfo(arcname.lstrip("/"))
    info.type = tarfile.DIRTYPE
    info.mode = mode
    info.mtime = 0
    tar.addfile(info)


def _add_symlink(tar: tarfile.TarFile, arcname: str, target: str) -> None:
    info = tarfile.TarInfo(arcname.lstrip("/"))
    info.type = tarfile.SYMTYPE
    info.linkname = target
    info.mtime = 0
    tar.addfile(info)


def _add_text(tar: tarfile.TarFile, arcname: str, text: str) -> None:
    data = text.encode()
    info = tarfile.TarInfo(arcname.lstrip("/"))
    info.size = len(data)
    info.mode = 0o644
    info.mtime = 0
    tar.addfile(info, io.BytesIO(data))


def build_rootfs(out: Path) -> None:
    if not PYTHON.exists() or not STDLIB.is_dir():
        raise SystemExit(f"host needs {PYTHON} and {STDLIB}")
    stdlib_files = sorted(
        p
        for p in STDLIB.rglob("*")
        if p.is_file() and not (set(p.relative_to(STDLIB).parts) & EXCLUDE_DIRS)
    )
    extensions = [p for p in stdlib_files if p.suffix == ".so"]
    libs = _ldd_closure([PYTHON, *extensions])

    files: dict[str, Path] = {"/usr/bin/python3.12": PYTHON}
    for lib in libs:
        arc = str(lib)
        for prefix in ("/lib64/", "/lib/"):
            if arc.startswith(prefix):
                arc = "/usr" + arc
        files[arc] = lib
    for f in stdlib_files:
        files[str(f)] = f

    dirs: set[str] = {"/tmp", "/workspace", "/etc", "/usr/bin", "/usr/lib", "/usr/sbin"}
    for arc in files:
        parent = Path(arc).parent
        while str(parent) != "/":
            dirs.add(str(parent))
            parent = parent.parent

    with tarfile.open(out, "w", format=tarfile.PAX_FORMAT) as tar:
        for d in sorted(dirs):
            _add_dir(tar, d, 0o1777 if d == "/tmp" else 0o755)
        _add_symlink(tar, "/lib", "usr/lib")
        _add_symlink(tar, "/lib64", "usr/lib64")
        _add_symlink(tar, "/bin", "usr/bin")
        _add_symlink(tar, "/usr/bin/python3", "python3.12")
        _add_symlink(tar, "/usr/bin/python", "python3.12")
        for arc in sorted(files):
            _add_file(tar, files[arc], arc)
        _add_text(tar, "/etc/passwd", PASSWD)
        _add_text(tar, "/etc/group", GROUP)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", default="sandbox-agent-base:local")
    args = parser.parse_args()
    docker = shutil.which("docker")
    if docker is None:
        print("docker not found", file=sys.stderr)
        return 1
    with tempfile.TemporaryDirectory() as tmp:
        tar_path = Path(tmp) / "rootfs.tar"
        build_rootfs(tar_path)
        subprocess.run(
            [
                docker,
                "import",
                "--change",
                "ENV PATH=/usr/local/bin:/usr/bin:/bin",
                "--change",
                "ENV LANG=C.UTF-8",
                "--change",
                'CMD ["python3"]',
                str(tar_path),
                args.tag,
            ],
            check=True,
        )
    print(f"built {args.tag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
