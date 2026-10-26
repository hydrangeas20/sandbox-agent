"""Trusted in-container entrypoint (PID 1) for Sandbox Coding Agent.

Invoked by the host as::

    python3 -I -S /opt/sandbox-agent/entry.py --deadline S --uid U --env-keys K,K \
        --max-output-bytes N -- ARGV...

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
limit, output budget) as the last line on stderr after every other process in the
container is dead.

**Output budget.** ARGV's stdout and stderr are pipes to PID 1, which relays them to
the container's own stdout and stderr (whose ``/proc/1/fd`` entries the workload
cannot open, because PID 1 is non-dumpable). PID 1 forwards at most
``--max-output-bytes`` across both streams. The first chunk that would exceed it is
cut at the budget, every workload process is killed at once, and anything still
buffered is discarded. The bytes that leave the container are therefore exactly
bounded and do not depend on how quickly the host can react.

Both marker lines carry a per-run nonce that untrusted code cannot read, so they
cannot be forged. Standard library only; runs on a shell-less base image.
"""

from __future__ import annotations

import contextlib
import ctypes
import json
import os
import platform
import select
import signal
import sys
import time

EXIT_ATTEST_FAILED = 121
EXIT_DEADLINE = 124
RELAY_CHUNK = 65536
POLL_S = 0.05
CANARY_ERRNO = 1729
CANARY_SYSCALL = {"x86_64": 239, "aarch64": 236}  # get_mempolicy
PR_SET_DUMPABLE = 4
NONCE_VAR = "SANDBOX_AGENT_NONCE"


def emit(kind: str, nonce: str, payload: dict[str, object], *, fresh_line: bool = False) -> None:
    line = f"sandbox-agent:{kind} {nonce} {json.dumps(payload, sort_keys=True)}\n"
    # The exit marker follows untrusted output, which may end mid-line; a leading newline
    # guarantees the marker is a line of its own (the host strips the empty line).
    os.write(2, (("\n" if fresh_line else "") + line).encode())


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


USAGE = "usage: entry.py --deadline S --uid U --env-keys K,K --max-output-bytes N -- ARGV"


def parse_args(argv: list[str]) -> tuple[float, int, list[str], int, list[str]]:
    if "--" not in argv:
        raise SystemExit(USAGE)
    split = argv.index("--")
    opts, command = argv[:split], argv[split + 1 :]
    values = dict(zip(opts[0::2], opts[1::2], strict=False))
    keys = [k for k in values.get("--env-keys", "").split(",") if k]
    if not command or "--max-output-bytes" not in values:
        raise SystemExit(USAGE)
    max_output = int(values["--max-output-bytes"])
    if max_output < 1:
        raise SystemExit(USAGE)
    return float(values["--deadline"]), int(values["--uid"]), keys, max_output, command


def kill_all() -> None:
    """SIGKILL every process in the container except PID 1 (ESRCH: nothing left)."""
    with contextlib.suppress(ProcessLookupError):
        os.kill(-1, signal.SIGKILL)


class Relay:
    """Forward the workload's pipes to PID 1's stdout/stderr within one shared budget."""

    def __init__(self, sources: dict[int, int], budget: int) -> None:
        self.sources = sources  # read end -> destination fd (1 or 2)
        self.budget = budget
        self.forwarded = 0
        self.limited = False
        self.sink_closed: set[int] = set()

    def _write(self, dest: int, data: bytes) -> None:
        view = memoryview(data)
        while view and dest not in self.sink_closed:
            try:
                view = view[os.write(dest, view) :]
            except BrokenPipeError:
                self.sink_closed.add(dest)  # host went away: keep draining, stop writing

    def pump(self, fd: int) -> None:
        data = os.read(fd, RELAY_CHUNK)
        if not data:
            os.close(fd)
            del self.sources[fd]
            return
        if self.limited:
            return  # over budget: drain and discard until the writers are dead
        room = self.budget - self.forwarded
        if len(data) > room:
            data = data[:room]
            self.limited = True
            kill_all()  # before forwarding anything else: the budget is exact
        self.forwarded += len(data)
        self._write(self.sources[fd], data)

    def poll(self) -> None:
        if not self.sources:
            time.sleep(POLL_S)
            return
        ready, _, _ = select.select(list(self.sources), [], [], POLL_S)
        for fd in ready:
            self.pump(fd)


def spawn(command: list[str], child_env: dict[str, str], max_output: int) -> tuple[int, Relay]:
    """Fork the untrusted command with its stdout/stderr connected to a new relay."""
    out_r, out_w = os.pipe()
    err_r, err_w = os.pipe()
    pid = os.fork()
    if pid == 0:  # child: becomes the untrusted command
        # stdout/stderr become the relay pipes; no other descriptor is inherited
        # (os.pipe() descriptors are close-on-exec), so the workload holds no handle
        # to the container's own output.
        os.dup2(out_w, 1)
        os.dup2(err_w, 2)
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

    os.close(out_w)
    os.close(err_w)
    return pid, Relay({out_r: 1, err_r: 2}, max_output)


def supervise(pid: int, relay: Relay) -> int:
    """Relay output until the command has exited and every write end is closed.

    Once the command exits, stragglers (daemonised grandchildren) are killed, which
    closes the pipes they inherited. Returns the command's wait status.
    """
    wait_status: int | None = None
    while wait_status is None or relay.sources:
        relay.poll()
        while True:
            try:
                reaped, status = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                break
            if reaped == 0:
                break
            if reaped == pid:
                wait_status = status
                kill_all()
    return wait_status


def main() -> int:
    started = time.monotonic()
    deadline, uid, env_keys, max_output, command = parse_args(sys.argv[1:])
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
    pid, relay = spawn(command, child_env, max_output)
    state = {"deadline": False}

    def on_deadline(_sig: int, _frame: object) -> None:
        state["deadline"] = True
        kill_all()

    signal.signal(signal.SIGALRM, on_deadline)
    signal.setitimer(signal.ITIMER_REAL, deadline)
    wait_status = supervise(pid, relay)
    signal.setitimer(signal.ITIMER_REAL, 0)
    kill_all()
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
        "output_bytes": relay.forwarded,
        "output_limit": relay.limited,
        "duration_ms": int((time.monotonic() - started) * 1000),
    }
    emit("exit", nonce, report, fresh_line=True)
    if state["deadline"]:
        return EXIT_DEADLINE
    return 128 + term_signal if term_signal is not None else exit_code


if __name__ == "__main__":
    raise SystemExit(main())
