"""Refuse to publish artifacts that contain the provider credential.

Usage (credential supplied only through the environment, never as an argument):

    ANTHROPIC_API_KEY=... python scripts/check_artifacts_for_secret.py runs/

Scans every file for the key and its base64/base64url/hex/URL/JSON-escaped forms and
for any Anthropic-key-shaped string. Prints only file names and match *kinds*, never
the matching text. Exit 0 = clean, 1 = credential found, 2 = misuse (e.g. no key set).
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

from sandbox_agent.trace import _encodings

KEY_SHAPE = re.compile(rb"sk-ant-[A-Za-z0-9_\-]{20,}")


def scan(root: Path, secret: str) -> list[tuple[str, str]]:
    needles = {v.encode() for v in _encodings(secret) if len(v) >= 8}
    findings: list[tuple[str, str]] = []
    for path in sorted(p for p in root.rglob("*") if p.is_file() and not p.is_symlink()):
        data = path.read_bytes()
        if any(n in data for n in needles):
            findings.append((str(path), "credential (or an encoding of it)"))
        elif KEY_SHAPE.search(data):
            findings.append((str(path), "Anthropic-key-shaped string"))
    return findings


def main(argv: list[str]) -> int:
    secret = os.environ.get("ANTHROPIC_API_KEY", "")
    if len(argv) != 1 or len(secret) < 8:
        print("usage: ANTHROPIC_API_KEY=... check_artifacts_for_secret.py DIR", file=sys.stderr)
        return 2
    root = Path(argv[0])
    if not root.is_dir():
        print(f"no artifact directory: {root}", file=sys.stderr)
        return 2
    findings = scan(root, secret)
    for path, kind in findings:
        print(f"::error file={path}::{kind} found; artifacts will not be uploaded")
    if not findings:
        print(f"artifact scan clean: {sum(1 for p in root.rglob('*') if p.is_file())} files")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
