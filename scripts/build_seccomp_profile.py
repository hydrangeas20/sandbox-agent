"""Derive the pinned sandbox seccomp profile from Docker's default profile.

Usage:
    python scripts/build_seccomp_profile.py <moby/profiles>/seccomp/default.json

Input: moby/profiles ``seccomp/default.json`` (Apache-2.0). Output:
``src/sandbox_agent/seccomp/profile.json``. The only change is a *canary*:
``get_mempolicy`` (unused by CPython) is removed from the allow lists and given an
explicit rule returning errno 1729. The in-container entrypoint calls it before
running untrusted code; any other value proves the pinned profile is not the one
being enforced (permissive daemon default, ``seccomp=unconfined``, etc.).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

CANARY_SYSCALL = "get_mempolicy"
CANARY_ERRNO = 1729
OUT = Path(__file__).resolve().parents[1] / "src" / "sandbox_agent" / "seccomp" / "profile.json"


def main(src: str) -> int:
    profile = json.loads(Path(src).read_text())
    for rule in profile["syscalls"]:
        rule["names"] = [n for n in rule["names"] if n != CANARY_SYSCALL]
    profile["syscalls"] = [r for r in profile["syscalls"] if r["names"]]
    profile["syscalls"].append(
        {"names": [CANARY_SYSCALL], "action": "SCMP_ACT_ERRNO", "errnoRet": CANARY_ERRNO}
    )
    OUT.write_text(json.dumps(profile, indent=1, sort_keys=True) + "\n")
    print(f"wrote {OUT} ({len(profile['syscalls'])} rules)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1]))
