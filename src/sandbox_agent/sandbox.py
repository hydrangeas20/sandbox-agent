"""Docker sandbox runner.

This is the **only** module that spawns processes. It never runs repository or
agent-supplied code on the host: every untrusted command executes inside a
container created from a frozen :class:`SandboxConfig`.

Flow for one run (fail closed at every step):

1. Validate the workspace mount source (must live under the private workspace
   root; sensitive host paths are rejected).
2. ``docker create`` with an argv list (never a shell string), a **pinned seccomp
   profile**, a per-run nonce and a deadline label.
3. ``docker inspect`` the *created* container and compare every isolation
   setting against the config, including the exact seccomp profile, the exact
   environment and the exact command. Any mismatch -> :class:`SandboxIsolationError`
   and the container is removed **before it starts**.
4. ``docker start --attach``. The trusted entrypoint (``sandbox/entry.py``, PID 1)
   attests the controls from inside the container and only then runs the command;
   a missing or failed attestation aborts the run. The host keeps a bounded head
   and tail per stream. PID 1 relays the command's output and stops it at exactly
   the total budget, killing the workload; the host kills the container if more
   than the budget plus PID 1's marker lines arrives (backstop). A wall-clock
   timeout triggers ``docker kill``. PID 1 also enforces its own
   deadline, so a container cannot outlive a crashed host process for long.
5. Classify the outcome (OOM attribution uses the entrypoint's cgroup evidence)
   and always ``docker rm -f``. Stale containers from crashed runs are reaped at
   the next preflight.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import IO, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from sandbox_agent.config import CONTAINER_TMP, SANDBOX_UID, WORKSPACE_MOUNT, SandboxConfig
from sandbox_agent.errors import SandboxIsolationError, SandboxUnavailableError
from sandbox_agent.ownership import current_owner, owner_alive

_CLI_TIMEOUT_S = 30.0
_LABEL = "sandbox-agent.managed=1"
_DEADLINE_LABEL = "sandbox-agent.deadline"
_OWNER_LABEL = "sandbox-agent.owner"
_TAIL_BYTES = 8192
# Besides the workload's output, PID 1 writes only its attest and exit marker lines.
# The host-side budget allows for them, so it fires only if the in-container budget
# was not enforced (defence in depth).
_MARKER_ALLOWANCE_BYTES = 64 * 1024

SECCOMP_PROFILE_PATH = Path(__file__).with_name("seccomp") / "profile.json"
ENTRYPOINT = ("python3", "-I", "-S", "/opt/sandbox-agent/entry.py")
NONCE_VAR = "SANDBOX_AGENT_NONCE"
_NONCE_RE = re.compile(r"^[0-9a-f]{32}$")
#: Security options a created container may carry, besides the pinned seccomp profile.
_ALLOWED_SECURITY_OPTS = frozenset({"no-new-privileges", "no-new-privileges:true"})

Status = Literal["completed", "timeout", "oom_killed", "killed", "output_limit"]


def load_seccomp_profile() -> dict[str, Any]:
    profile: dict[str, Any] = json.loads(SECCOMP_PROFILE_PATH.read_text())
    return profile


def _sensitive_host_paths() -> list[Path]:
    home = Path.home()
    return [
        Path("/var/run/docker.sock"),
        Path("/run/docker.sock"),
        Path("/run/containerd"),
        home / ".ssh",
        home / ".aws",
        home / ".config" / "gcloud",
        home / ".docker",
        home / ".kube",
        home / ".netrc",
        home / ".gnupg",
    ]


_FORBIDDEN_ROOTS = frozenset(
    {"/", "/home", "/root", "/etc", "/usr", "/var", "/proc", "/sys", "/dev"}
)


class ContainerCommand(BaseModel):
    """A fully resolved argv to execute inside the container (never via a shell)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    argv: tuple[str, ...] = Field(min_length=1, max_length=64)

    @field_validator("argv")
    @classmethod
    def _no_nul(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        # argv is passed as a list (no shell), so newlines are inert; NUL would truncate.
        for arg in value:
            if "\x00" in arg or len(arg) > 8192:
                raise ValueError("argv elements must be NUL-free and at most 8192 chars")
        return value


class RunOutcome(BaseModel):
    """Result of one sandboxed command. Resource outcomes are explicit fields.

    ``status``:
      * ``timeout`` - host timeout or in-container watchdog deadline;
      * ``oom_killed`` - Docker reported OOMKilled, or the entrypoint observed the
        workload die by SIGKILL while the cgroup's ``oom_kill`` counter increased;
      * ``killed`` - SIGKILL (exit 137) with no OOM evidence and not sent by the runner;
      * ``output_limit`` - the total output budget was reached: PID 1 cut the output at
        the budget and killed the workload (or, as a backstop, the runner killed it).
    """

    model_config = ConfigDict(frozen=True)

    status: Status
    exit_code: int | None
    stdout: str
    stderr: str
    stdout_tail: str = ""
    stderr_tail: str = ""
    stdout_truncated: bool
    stderr_truncated: bool
    stdout_bytes_total: int
    stderr_bytes_total: int
    duration_ms: int
    container: str
    attestation: dict[str, Any] = Field(default_factory=dict)
    exit_report: dict[str, Any] | None = None


class _OutputBudget:
    """Total bytes shared by both streams; fires ``on_exceeded`` once when exceeded."""

    def __init__(self, limit: int, on_exceeded: Any) -> None:
        self.limit = limit
        self.total = 0
        self.tripped = False
        self._on_exceeded = on_exceeded
        self._lock = threading.Lock()

    def consume(self, n: int) -> None:
        fire = False
        with self._lock:
            self.total += n
            if self.total > self.limit and not self.tripped:
                self.tripped = fire = True
        if fire:
            self._on_exceeded()


class _BoundedReader(threading.Thread):
    """Drain a pipe completely, keeping the first ``limit`` bytes and a tail window."""

    def __init__(self, stream: IO[bytes], limit: int, budget: _OutputBudget | None = None) -> None:
        super().__init__(daemon=True)
        self._stream = stream
        self._limit = limit
        self._budget = budget
        self._chunks: list[bytes] = []
        self._kept = 0
        self._tail = b""
        self.total = 0

    def run(self) -> None:
        while True:
            chunk = self._stream.read(65536)
            if not chunk:
                break
            self.total += len(chunk)
            room = self._limit - self._kept
            if room > 0:
                piece = chunk[:room]
                self._chunks.append(piece)
                self._kept += len(piece)
            self._tail = (self._tail + chunk)[-_TAIL_BYTES:]
            if self._budget is not None:
                self._budget.consume(len(chunk))

    @property
    def text(self) -> str:
        return b"".join(self._chunks).decode("utf-8", errors="replace")

    @property
    def tail(self) -> str:
        return self._tail.decode("utf-8", errors="replace")

    @property
    def truncated(self) -> bool:
        return self.total > self._limit


class DockerSandbox:
    """Runs :class:`ContainerCommand` s inside containers built from one frozen config."""

    def __init__(
        self,
        config: SandboxConfig,
        workspace_root: Path,
        docker_bin: str | None = None,
    ) -> None:
        self.config = config
        self.workspace_root = workspace_root.resolve(strict=True)
        if str(self.workspace_root) in _FORBIDDEN_ROOTS or self.workspace_root == Path.home():
            raise SandboxIsolationError(f"workspace root {self.workspace_root} is too broad")
        resolved = docker_bin or shutil.which("docker")
        if resolved is None:
            raise SandboxUnavailableError(
                "docker CLI not found; refusing to run (no host fallback)"
            )
        self._docker = resolved
        if not SECCOMP_PROFILE_PATH.is_file():
            raise SandboxIsolationError(f"pinned seccomp profile missing: {SECCOMP_PROFILE_PATH}")

    # ------------------------------------------------------------------ docker CLI

    def _cli(self, *args: str, timeout: float = _CLI_TIMEOUT_S) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(
                [self._docker, *args],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                env=_docker_cli_env(),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SandboxUnavailableError(f"docker {args[0]} failed: {exc}") from exc

    def preflight(self) -> dict[str, Any]:
        """Check the daemon and image; raise if a required control is unavailable."""
        info = self._cli("info", "--format", "{{json .}}")
        if info.returncode != 0:
            raise SandboxUnavailableError(f"docker daemon unavailable: {info.stderr.strip()}")
        data: dict[str, Any] = json.loads(info.stdout)
        sec = [str(s) for s in data.get("SecurityOptions") or []]
        if not any("seccomp" in s for s in sec):
            raise SandboxIsolationError("docker daemon does not report seccomp support")
        image = self._cli("image", "inspect", "--format", "{{json .Config}}", self.config.image)
        if image.returncode != 0:
            raise SandboxUnavailableError(
                f"sandbox image {self.config.image} not found; run `make image`"
            )
        image_cfg: dict[str, Any] = json.loads(image.stdout) or {}
        image_env = set(image_cfg.get("Env") or [])
        wanted = {f"{k}={v}" for k, v in self.config.env}
        if image_env != wanted:
            raise SandboxIsolationError(
                f"image env differs from the configured env: extra={sorted(image_env - wanted)} "
                f"missing={sorted(wanted - image_env)}; rebuild with `make image`"
            )
        if image_cfg.get("Entrypoint"):
            raise SandboxIsolationError(f"image sets an entrypoint: {image_cfg['Entrypoint']}")
        reaped = self.reap_stale()
        return {
            "server_version": data.get("ServerVersion"),
            "security_options": sec,
            "cgroup_version": data.get("CgroupVersion"),
            "image": self.config.image,
            "seccomp_profile": SECCOMP_PROFILE_PATH.name,
            "reaped_containers": reaped,
        }

    def reap_stale(self, now: float | None = None) -> int:
        """Remove orphaned managed containers (SR-04).

        A container is removed when its owning controller (same host) is no longer
        running, or when its reap deadline (``create + timeout + watchdog grace + 60 s``)
        has passed. Containers of live controllers within their deadline are untouched.
        """
        fmt = '{{.ID}}|{{.Label "' + _DEADLINE_LABEL + '"}}|{{.Label "' + _OWNER_LABEL + '"}}'
        listing = self._cli("ps", "-a", "--filter", f"label={_LABEL}", "--format", fmt)
        if listing.returncode != 0:
            raise SandboxUnavailableError(f"docker ps failed: {listing.stderr.strip()}")
        now = time.time() if now is None else now
        stale = []
        for line in listing.stdout.splitlines():
            cid, deadline, owner = [*line.split("|"), "", ""][:3]
            expired = not deadline.strip().isdigit() or int(deadline) < now
            if expired or owner_alive(owner) is False:
                stale.append(cid)
        if stale:
            self._cli("rm", "-f", *stale)
        return len(stale)

    # ------------------------------------------------------------------ arguments

    def validate_mount_source(self, workspace_dir: Path) -> Path:
        if workspace_dir.is_symlink():
            raise SandboxIsolationError("workspace mount source is a symlink")
        resolved = workspace_dir.resolve(strict=True)
        if not resolved.is_dir():
            raise SandboxIsolationError("workspace mount source is not a directory")
        if resolved == self.workspace_root or not resolved.is_relative_to(self.workspace_root):
            raise SandboxIsolationError(
                f"mount source {resolved} is not inside workspace root {self.workspace_root}"
            )
        for sensitive in _sensitive_host_paths():
            if sensitive == resolved or sensitive.is_relative_to(resolved):
                raise SandboxIsolationError(f"mount source would expose {sensitive}")
        if "," in str(resolved) or "=" in str(resolved):
            raise SandboxIsolationError("mount source path contains reserved characters")
        return resolved

    def wrapped_argv(self, command: ContainerCommand) -> list[str]:
        cfg = self.config
        return [
            *ENTRYPOINT,
            "--deadline", f"{cfg.timeout_s + cfg.watchdog_grace_s}",
            "--uid", str(SANDBOX_UID),
            "--env-keys", ",".join(k for k, _ in cfg.env),
            "--max-output-bytes", str(cfg.max_total_output_bytes),
            "--",
            *command.argv,
        ]  # fmt: skip

    def build_create_args(
        self,
        workspace_dir: Path,
        command: ContainerCommand,
        name: str,
        *,
        nonce: str = "0" * 32,
    ) -> list[str]:
        cfg = self.config
        source = self.validate_mount_source(workspace_dir)
        deadline = int(time.time() + cfg.timeout_s + cfg.watchdog_grace_s + 60)
        args = [
            "create",
            "--name", name,
            "--label", _LABEL,
            "--label", f"{_DEADLINE_LABEL}={deadline}",
            "--label", f"{_OWNER_LABEL}={current_owner()}",
            "--hostname", "sandbox",
            "--network", cfg.network,
            "--user", cfg.user,
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--security-opt", f"seccomp={SECCOMP_PROFILE_PATH}",
            "--read-only",
            "--tmpfs", f"{CONTAINER_TMP}:rw,noexec,nosuid,nodev,size={cfg.tmpfs_bytes},mode=1777",
            "--memory", str(cfg.memory_bytes),
            "--memory-swap", str(cfg.memory_bytes),
            "--cpus", f"{cfg.cpus}",
            "--pids-limit", str(cfg.pids_limit),
            "--ulimit", f"nofile={cfg.nofile}:{cfg.nofile}",
            "--ulimit", f"fsize={cfg.fsize_bytes}:{cfg.fsize_bytes}",
            "--ipc", "none",
            "--cgroupns", "private",
            "--log-driver", "none",
            "--stop-timeout", "1",
            "--mount", f"type=bind,source={source},target={WORKSPACE_MOUNT},readonly",
            "--workdir", WORKSPACE_MOUNT,
        ]  # fmt: skip
        for key, value in cfg.env:
            args += ["--env", f"{key}={value}"]
        args += ["--env", f"{NONCE_VAR}={nonce}"]
        args += ["--", cfg.image, *self.wrapped_argv(command)]
        return args

    # ------------------------------------------------------------------ verification

    def verify(  # noqa: PLR0915 - one flat checklist is easier to review than helpers
        self,
        inspect: dict[str, Any],
        workspace_dir: Path,
        nonce: str | None = None,
        expected_argv: list[str] | None = None,
    ) -> None:
        """Compare a created container against the config. Raises on any deviation."""
        cfg = self.config
        host = inspect.get("HostConfig") or {}
        conf = inspect.get("Config") or {}
        problems: list[str] = []

        def expect(cond: bool, msg: str) -> None:
            if not cond:
                problems.append(msg)

        expect(host.get("NetworkMode") == "none", f"network mode is {host.get('NetworkMode')!r}")
        expect(host.get("Privileged") is False, "container is privileged")
        expect([c.upper() for c in host.get("CapDrop") or []] == ["ALL"], "CapDrop is not [ALL]")
        expect(not host.get("CapAdd"), f"CapAdd is {host.get('CapAdd')!r}")

        # Security options: an explicit allowlist. The daemon's *default* seccomp profile
        # is invisible to inspect, so the pinned profile must be present and identical.
        sec = [str(s) for s in host.get("SecurityOpt") or []]
        expect(any(s.startswith("no-new-privileges") for s in sec), "no-new-privileges missing")
        seccomp = [s for s in sec if s.startswith("seccomp=")]
        others = [
            s for s in sec if not s.startswith("seccomp=") and s not in _ALLOWED_SECURITY_OPTS
        ]
        expect(not others, f"unexpected security options: {others}")
        if len(seccomp) != 1:
            problems.append(f"expected exactly one pinned seccomp profile, found {len(seccomp)}")
        else:
            try:
                applied = json.loads(seccomp[0].removeprefix("seccomp="))
            except json.JSONDecodeError:
                applied = None
            expect(applied == load_seccomp_profile(), "seccomp profile differs from pinned profile")
        expect(
            str(inspect.get("AppArmorProfile", "")) != "unconfined",
            "apparmor profile is unconfined",
        )

        expect(host.get("ReadonlyRootfs") is True, "root filesystem is writable")
        expect(host.get("Memory") == cfg.memory_bytes, f"memory limit {host.get('Memory')}")
        expect(host.get("MemorySwap") == cfg.memory_bytes, f"swap limit {host.get('MemorySwap')}")
        expect(host.get("NanoCpus") == round(cfg.cpus * 1e9), f"cpu limit {host.get('NanoCpus')}")
        expect(host.get("PidsLimit") == cfg.pids_limit, f"pids limit {host.get('PidsLimit')}")
        ulimits = {u.get("Name"): (u.get("Soft"), u.get("Hard")) for u in host.get("Ulimits") or []}
        expect(ulimits.get("nofile") == (cfg.nofile, cfg.nofile), f"nofile ulimit {ulimits}")
        expect(
            ulimits.get("fsize") == (cfg.fsize_bytes, cfg.fsize_bytes), f"fsize ulimit {ulimits}"
        )
        tmp_opts = set(str((host.get("Tmpfs") or {}).get(CONTAINER_TMP, "")).split(","))
        expect({"noexec", "nosuid", "nodev"} <= tmp_opts, f"tmpfs options {tmp_opts}")
        expect(host.get("IpcMode") == "none", f"ipc mode {host.get('IpcMode')!r}")
        for ns in ("PidMode", "UTSMode", "UsernsMode", "CgroupnsMode"):
            expect(host.get(ns) != "host", f"{ns} is host")
        expect(not host.get("Devices"), "devices are mapped")
        expect(not host.get("Binds"), f"legacy binds present: {host.get('Binds')}")
        expect(not host.get("VolumesFrom"), "volumes-from present")
        expect((host.get("LogConfig") or {}).get("Type") == "none", "log driver is not none")
        expect(conf.get("User") == cfg.user, f"user is {conf.get('User')!r}")
        expect(not conf.get("Entrypoint"), f"image entrypoint is set: {conf.get('Entrypoint')}")
        if expected_argv is not None:
            actual = [inspect.get("Path"), *(inspect.get("Args") or [])]
            expect(actual == expected_argv, f"container command differs: {actual}")

        mounts = inspect.get("Mounts") or []
        expected_source = str(workspace_dir.resolve())
        ok_mounts = (
            len(mounts) == 1
            and mounts[0].get("Type") == "bind"
            and mounts[0].get("Source") == expected_source
            and mounts[0].get("Destination") == WORKSPACE_MOUNT
            and mounts[0].get("RW") is False
        )
        expect(ok_mounts, f"unexpected mounts: {mounts}")

        # Environment: exactly the configured variables plus this run's nonce. Values
        # are compared too, so neither the image nor the daemon can add or alter any.
        env = [str(e) for e in conf.get("Env") or []]
        wanted = {f"{k}={v}" for k, v in cfg.env}
        nonce_entries = [e for e in env if e.startswith(f"{NONCE_VAR}=")]
        rest = set(env) - set(nonce_entries)
        expect(
            rest == wanted,
            f"env differs: extra={sorted(rest - wanted)} missing={sorted(wanted - rest)}",
        )
        expect(len(env) == len(set(env)), "duplicate env entries")
        if len(nonce_entries) != 1:
            problems.append("env nonce missing")
        else:
            value = nonce_entries[0].split("=", 1)[1]
            expect(
                bool(_NONCE_RE.fullmatch(value)) and (nonce is None or value == nonce),
                "env nonce mismatch",
            )

        if problems:
            raise SandboxIsolationError("isolation verification failed: " + "; ".join(problems))

    # ------------------------------------------------------------------ run

    def run(self, workspace_dir: Path, command: ContainerCommand) -> RunOutcome:
        name = f"sandbox-agent-{uuid.uuid4().hex[:12]}"
        nonce = secrets.token_hex(16)
        create_args = self.build_create_args(workspace_dir, command, name, nonce=nonce)
        created = self._cli(*create_args)
        if created.returncode != 0:
            raise SandboxIsolationError(f"docker create failed: {created.stderr.strip()[:500]}")
        container_id = created.stdout.strip()
        try:
            self.verify(
                self._inspect(container_id),
                workspace_dir,
                nonce=nonce,
                expected_argv=self.wrapped_argv(command),
            )
            return self._start(container_id, name, nonce)
        finally:
            self._cli("rm", "-f", container_id)

    def _inspect(self, container_id: str) -> dict[str, Any]:
        res = self._cli("inspect", container_id)
        if res.returncode != 0:
            raise SandboxIsolationError(f"docker inspect failed: {res.stderr.strip()}")
        data = json.loads(res.stdout)
        if not isinstance(data, list) or len(data) != 1:
            raise SandboxIsolationError("unexpected docker inspect output")
        result: dict[str, Any] = data[0]
        return result

    def _start(self, container_id: str, name: str, nonce: str) -> RunOutcome:  # noqa: PLR0915
        limit = self.config.max_output_bytes
        started = time.monotonic()
        killed_by_budget = threading.Event()

        def kill_for_output() -> None:
            # Backstop only: PID 1 enforces the exact budget inside the container, so
            # this fires only if that failed. Called from a reader thread; kill
            # asynchronously so both readers keep draining (a blocked reader
            # back-pressures dockerd and stalls the kill).
            killed_by_budget.set()
            threading.Thread(target=self._cli, args=("kill", container_id), daemon=True).start()

        budget = _OutputBudget(
            self.config.max_total_output_bytes + _MARKER_ALLOWANCE_BYTES, kill_for_output
        )
        proc = subprocess.Popen(
            [self._docker, "start", "--attach", container_id],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            env=_docker_cli_env(),
        )
        assert proc.stdout is not None  # noqa: S101 - guaranteed by PIPE
        assert proc.stderr is not None  # noqa: S101
        out = _BoundedReader(proc.stdout, limit, budget)
        err = _BoundedReader(proc.stderr, limit, budget)
        out.start()
        err.start()
        timed_out = False
        try:
            proc.wait(timeout=self.config.timeout_s)
        except subprocess.TimeoutExpired:
            timed_out = True
            self._cli("kill", container_id)
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        out.join(timeout=5)
        err.join(timeout=5)
        duration_ms = int((time.monotonic() - started) * 1000)
        state = self._inspect(container_id).get("State") or {}
        exit_code = state.get("ExitCode")

        stderr_head, attestation, failed = _take_marker(err.text, "attest", nonce, first=True)
        if failed is not None:
            raise SandboxIsolationError(f"runtime attestation failed: {failed}")
        if attestation is None:
            raise SandboxIsolationError(
                "runtime attestation missing: the trusted entrypoint did not confirm isolation"
            )
        stderr_tail, report, _ = _take_marker(err.tail, "exit", nonce, first=False)
        if err.total <= limit:
            stderr_head, _, _ = _take_marker(stderr_head, "exit", nonce, first=False)
        if report is not None and _report_exit_status(report) != exit_code:
            report = None  # inconsistent with Docker's view: ignore rather than trust it

        status: Status
        if timed_out or (report is not None and report.get("deadline")):
            status = "timeout"
        elif killed_by_budget.is_set() or (report is not None and report.get("output_limit")):
            status = "output_limit"
        elif bool(state.get("OOMKilled")) or (
            report is not None and report.get("signal") == 9 and (report.get("oom_kills") or 0) > 0
        ):
            status = "oom_killed"
        elif exit_code == 137:
            status = "killed"
        else:
            status = "completed"
        return RunOutcome(
            status=status,
            exit_code=None if timed_out else (int(exit_code) if exit_code is not None else None),
            stdout=out.text,
            stderr=stderr_head,
            stdout_tail=out.tail,
            stderr_tail=stderr_tail,
            stdout_truncated=out.truncated,
            stderr_truncated=err.truncated,
            stdout_bytes_total=out.total,
            stderr_bytes_total=err.total,
            duration_ms=duration_ms,
            container=name,
            attestation=attestation,
            exit_report=report,
        )


def _take_marker(
    text: str, kind: str, nonce: str, *, first: bool
) -> tuple[str, dict[str, Any] | None, Any]:
    """Extract the entrypoint's ``sandbox-agent:<kind>`` line (first or last line only).

    Returns (text without the marker, payload, failure-payload). Only the first line
    (attest) or last line (exit) is considered: untrusted code runs strictly after the
    attest line and is dead before the exit line is written, and both carry a nonce
    the workload cannot read.
    """
    lines = text.splitlines(keepends=True)
    if not lines:
        return text, None, None
    index = 0 if first else len(lines) - 1
    line = lines[index].rstrip("\n")
    for marker, is_failure in (
        (f"sandbox-agent:{kind}-failed ", True),
        (f"sandbox-agent:{kind} ", False),
    ):
        if line.startswith(marker):
            token, _, payload = line[len(marker) :].partition(" ")
            if token != nonce:
                return text, None, None
            try:
                data = json.loads(payload)
            except json.JSONDecodeError:
                data = {"raw": payload[:200]}
            before = lines[:index]
            if not first and before and before[-1].endswith("\n"):
                # Drop the newline the entrypoint inserts before its exit marker.
                before[-1] = before[-1][:-1]
            rest = "".join(before + lines[index + 1 :])
            return (rest, None, data) if is_failure else (rest, data, None)
    if first and line.startswith("sandbox-agent:attest-failed"):
        return text, None, line
    return text, None, None


def _report_exit_status(report: dict[str, Any]) -> int | None:
    if report.get("deadline"):
        return 124
    if report.get("signal") is not None:
        return 128 + int(report["signal"])
    code = report.get("exit_code")
    return int(code) if code is not None else None


def _docker_cli_env() -> dict[str, str]:
    """Environment for the docker *CLI* process (not the container).

    Only variables the CLI needs are passed; provider credentials never reach
    the CLI either. The container environment is set explicitly via --env and
    verified by inspect.
    """
    keep = ("PATH", "HOME", "DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_CONTEXT", "DOCKER_CERT_PATH")
    keep_tls = ("DOCKER_TLS_VERIFY",)
    return {k: v for k, v in os.environ.items() if k in keep or k in keep_tls}
