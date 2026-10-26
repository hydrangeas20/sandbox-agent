"""Controller identity, used to recover from unexpected controller termination (SR-04).

Containers and workspaces are tagged with ``<host>:<pid>:<start-ticks>`` of the
controller process that created them. The process start time (``/proc/<pid>/stat``
field 22) makes the tag robust to PID reuse. If a later controller on the same host
finds a tag whose process is gone, the resource is an orphan and can be removed at
once; resources owned by a live controller, or by another host (remote
``DOCKER_HOST``), are left alone and fall back to deadline-based reaping.
"""

from __future__ import annotations

import os
import socket
from functools import cache


def _start_ticks(pid: int) -> str | None:
    try:
        with open(f"/proc/{pid}/stat") as fh:
            stat = fh.read()
    except OSError:
        return None
    # The command name (field 2) may contain spaces/parens; fields resume after the last ')'.
    fields = stat.rsplit(")", 1)[1].split()
    return fields[19]  # field 22 overall: starttime


@cache
def current_owner() -> str:
    pid = os.getpid()
    return f"{socket.gethostname()}:{pid}:{_start_ticks(pid) or 'unknown'}"


def owner_alive(owner: str) -> bool | None:
    """True/False for an owner on this host; None if it cannot be judged (foreign/malformed)."""
    try:
        host, pid_text, ticks = owner.rsplit(":", 2)
        pid = int(pid_text)
    except ValueError:
        return None
    if host != socket.gethostname() or ticks == "unknown":
        return None
    return _start_ticks(pid) == ticks
