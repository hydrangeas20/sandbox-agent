"""Trusted in-container entrypoint (PID 1) for Sandbox Coding Agent.

Invoked by the host as::

    python3 -I -S /opt/sandbox-agent/entry.py --deadline S --uid U --env-keys K,K -- ARGV...

Before any untrusted code runs it:

1. makes itself non-dumpable (blocks same-UID ptrace, /proc/1/mem, /proc/1/environ);
2. **attests** the isolation controls from inside the container (PID 1, non-root UID,
   seccomp filter mode, the pinned profile's canary errno, NoNewPrivs, empty
   capability sets, loopback-only networking, read-only / and /workspace,
   noexec+nosuid /tmp). Any failure: report and exit 121 without running ARGV;
3. writes ``sandbox-agent:attest {json}`` as the first line on stderr.

It then forks ARGV with a scrubbed environment (only ``--env-keys``; Docker's injected
``HOSTNAME`` and the per-run nonce are removed), enforces a wall-clock deadline that
does not depend on the host process, reaps all processes, and writes
``sandbox-agent:exit {json}`` (exit status, signal, cgroup OOM-kill delta, memory
limit) as the last line on stderr after every other process in the container is dead.

Both marker lines carry a per-run nonce that untrusted code cannot read, so they
cannot be forged. Standard library only; runs on a shell-less base image.
"""

from __future__ import annotations

import contextlib
import ctypes
import json
import os
import platform
import signal
import sys
import time

EXIT_ATTEST_FAILED = 121
EXIT_DEADLINE = 124
CANARY_ERRNO = 1729
CANARY_SYSCALL = {"x86_64": 239, "aarch64": 236}  # get_mempolicy
PR_SET_DUMPABLE = 4
NONCE_VAR = "SANDBOX_AGENT_NONCE"


def emit(kind: str, nonce: str, payload: dict[str, object]) -> None:
    line = f"sandbox-agent:{kind} {nonce} {json.dumps(payload, sort_keys=True)}\n"
    os.write(2, line.encode())


def status_fields() -> dict[str, str]:
    with open("/proc/self/status") as fh:
        return {k: v.strip() for k, v in (ln.split(":", 1) for ln in fh if ":" in ln)}


def read_first(paths: list[tuple[str, str | None]]) -> int | None:
    """Return the first readable integer among (path, key) pairs (key for 'k v' files)."""
    for path, key in paths:
        try:
            with open(path) as fh:
                text = fh.read()
        except OSError:
            continue
        if key is None:
            value = text.strip()
            return None if value == "max" else int(value)
        for line in text.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[0] == key:
                return int(parts[1])
    return None


def oom_kills() -> int | None:
    return read_first(
        [
            ("/sys/fs/cgroup/memory.events", "oom_kill"),  # cgroup v2
            ("/sys/fs/cgroup/memory/memory.oom_control", "oom_kill"),  # cgroup v1
        ]
    )


def memory_limit() -> int | None:
    return read_first(
        [
            ("/sys/fs/cgroup/memory.max", None),
            ("/sys/fs/cgroup/memory/memory.limit_in_bytes", None),
        ]
    )


def attest(uid: int, libc: ctypes.CDLL) -> tuple[list[str], dict[str, object]]:
    problems: list[str] = []
    facts: dict[str, object] = {}

    def expect(cond: bool, message: str) -> None:
        if not cond:
            problems.append(message)

    expect(os.getpid() == 1, f"entrypoint is pid {os.getpid()}, expected 1")
    facts["uid"], facts["gid"] = os.getuid(), os.getgid()
    expect(os.getuid() == uid and os.geteuid() == uid, f"uid {os.getuid()} != {uid}")
    expect(os.getgid() != 0 and os.getegid() != 0, "gid is root")

    st = status_fields()
    facts["seccomp_mode"] = st.get("Seccomp")
    expect(st.get("Seccomp") == "2", f"seccomp mode {st.get('Seccomp')!r}, expected filter (2)")
    expect(st.get("NoNewPrivs") == "1", "no_new_privs not set")
    for cap in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
        value = st.get(cap, "missing")
        expect(value != "missing" and int(value, 16) == 0, f"{cap}={value}")

    nr = CANARY_SYSCALL.get(platform.machine())
    if nr is None:
        problems.append(f"no canary syscall number for {platform.machine()}")
    else:
        ctypes.set_errno(0)
        result = libc.syscall(nr, 0, 0, 0, 0, 0)
        errno = ctypes.get_errno()
        facts["seccomp_canary_errno"] = errno
        expect(result == -1 and errno == CANARY_ERRNO, f"seccomp canary returned {result}/{errno}")

    try:
        ifaces = sorted(os.listdir("/sys/class/net"))
    except OSError as exc:
        ifaces = [f"error:{exc.errno}"]
    facts["net_ifaces"] = ifaces
    expect(ifaces == ["lo"], f"network interfaces {ifaces}")

    for path, need in (
        ("/", os.ST_RDONLY),
        ("/workspace", os.ST_RDONLY),
        ("/tmp", os.ST_NOEXEC | os.ST_NOSUID),  # noqa: S108 - container path
    ):
        try:
            flags = os.statvfs(path).f_flag
        except OSError as exc:
            problems.append(f"statvfs {path}: {exc.errno}")
            continue
        expect(flags & need == need, f"{path} mount flags {flags:#x} lack {need:#x}")
    facts["memory_limit"] = memory_limit()
    return problems, facts


def parse_args(argv: list[str]) -> tuple[float, int, list[str], list[str]]:
    if "--" not in argv:
        raise SystemExit("usage: entry.py --deadline S --uid U --env-keys K,K -- ARGV")
    split = argv.index("--")
    opts, command = argv[:split], argv[split + 1 :]
    values = dict(zip(opts[0::2], opts[1::2], strict=False))
    keys = [k for k in values.get("--env-keys", "").split(",") if k]
    if not command:
        raise SystemExit("no command")
    return float(values["--deadline"]), int(values["--uid"]), keys, command


def kill_all() -> None:
    """SIGKILL every process in the container except PID 1 (ESRCH: nothing left)."""
    with contextlib.suppress(ProcessLookupError):
        os.kill(-1, signal.SIGKILL)


def main() -> int:
    started = time.monotonic()
    deadline, uid, env_keys, command = parse_args(sys.argv[1:])
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
    nonce = os.environ.get(NONCE_VAR, "")
    if len(nonce) < 16:
        os.write(2, b"sandbox-agent:attest-failed missing nonce\n")
        return EXIT_ATTEST_FAILED

    problems, facts = attest(uid, libc)
    if problems:
        emit("attest-failed", nonce, {"problems": problems, **facts})
        return EXIT_ATTEST_FAILED
    emit("attest", nonce, facts)

    child_env = {k: os.environ[k] for k in env_keys if k in os.environ and k != NONCE_VAR}
    oom_before = oom_kills()
    pid = os.fork()
    if pid == 0:  # child: becomes the untrusted command
        try:
            with open("/proc/self/oom_score_adj", "w") as fh:
                fh.write("1000")  # the OOM killer picks the workload, never the watchdog
        except OSError:
            pass
        try:
            os.execvpe(command[0], command, child_env)  # noqa: S606 - argv list, no shell
        except OSError as exc:
            os.write(2, f"exec failed: {exc.strerror}\n".encode())
        os._exit(127)

    state = {"deadline": False}

    def on_deadline(_sig: int, _frame: object) -> None:
        state["deadline"] = True
        kill_all()

    signal.signal(signal.SIGALRM, on_deadline)
    signal.setitimer(signal.ITIMER_REAL, deadline)
    wait_status: int | None = None
    while wait_status is None:
        reaped, status = os.wait()
        if reaped == pid:
            wait_status = status
    signal.setitimer(signal.ITIMER_REAL, 0)
    kill_all()  # stragglers (daemonised grandchildren)
    while True:
        try:
            os.wait()
        except ChildProcessError:
            break

    exit_code = os.waitstatus_to_exitcode(wait_status)
    term_signal = -exit_code if exit_code < 0 else None
    oom_after = oom_kills()
    report = {
        "exit_code": exit_code if exit_code >= 0 else None,
        "signal": term_signal,
        "deadline": state["deadline"],
        "oom_kills": (oom_after - oom_before)
        if oom_after is not None and oom_before is not None
        else None,
        "memory_limit": facts.get("memory_limit"),
        "duration_ms": int((time.monotonic() - started) * 1000),
    }
    emit("exit", nonce, report)
    if state["deadline"]:
        return EXIT_DEADLINE
    return 128 + term_signal if term_signal is not None else exit_code


if __name__ == "__main__":
    raise SystemExit(main())
