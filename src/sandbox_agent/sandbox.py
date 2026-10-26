"""Docker sandbox runner.

This is the **only** module that spawns processes. It never runs repository or
agent-supplied code on the host: every untrusted command executes inside a
container created from a frozen :class:`SandboxConfig`.

Flow for one run (fail closed at every step):

1. Validate the workspace mount source (must live under the private workspace
   root; sensitive host paths are rejected).
2. ``docker create`` with an argv list (never a shell string).
3. ``docker inspect`` the *created* container and compare every isolation
   setting against the config. Any mismatch -> :class:`SandboxIsolationError`
   and the container is removed **before it starts**.
4. ``docker start --attach`` with bounded output readers and a wall-clock
   timeout (``docker kill`` on expiry).
5. Inspect the final state (exit code, OOM kill) and always ``docker rm -f``.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import IO, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from sandbox_agent.config import ALLOWED_ENV_KEYS, CONTAINER_TMP, WORKSPACE_MOUNT, SandboxConfig
from sandbox_agent.errors import SandboxIsolationError, SandboxUnavailableError

_CLI_TIMEOUT_S = 30.0
_LABEL = "sandbox-agent.managed=1"


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
    """Result of one sandboxed command. Resource outcomes are explicit fields."""

    model_config = ConfigDict(frozen=True)

    status: Literal["completed", "timeout", "oom_killed"]
    exit_code: int | None
    stdout: str
    stderr: str
    stdout_truncated: bool
    stderr_truncated: bool
    stdout_bytes_total: int
    stderr_bytes_total: int
    duration_ms: int
    container: str


class _BoundedReader(threading.Thread):
    """Drain a pipe completely, keeping at most ``limit`` bytes in memory."""

    def __init__(self, stream: IO[bytes], limit: int) -> None:
        super().__init__(daemon=True)
        self._stream = stream
        self._limit = limit
        self._chunks: list[bytes] = []
        self._kept = 0
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

    @property
    def text(self) -> str:
        return b"".join(self._chunks).decode("utf-8", errors="replace")

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
        if any("seccomp" in s and "unconfined" in s for s in sec):
            raise SandboxIsolationError("daemon default seccomp profile is unconfined")
        image = self._cli("image", "inspect", self.config.image)
        if image.returncode != 0:
            raise SandboxUnavailableError(
                f"sandbox image {self.config.image} not found; run `make image`"
            )
        return {
            "server_version": data.get("ServerVersion"),
            "security_options": sec,
            "cgroup_version": data.get("CgroupVersion"),
            "image": self.config.image,
        }

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

    def build_create_args(
        self, workspace_dir: Path, command: ContainerCommand, name: str
    ) -> list[str]:
        cfg = self.config
        source = self.validate_mount_source(workspace_dir)
        args = [
            "create",
            "--name", name,
            "--label", _LABEL,
            "--hostname", "sandbox",
            "--network", cfg.network,
            "--user", cfg.user,
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
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
        args += ["--", cfg.image, *command.argv]
        return args

    # ------------------------------------------------------------------ verification

    def verify(
        self, inspect: dict[str, Any], workspace_dir: Path, image_env_keys: set[str]
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
        sec = [str(s) for s in host.get("SecurityOpt") or []]
        expect(any(s.startswith("no-new-privileges") for s in sec), "no-new-privileges missing")
        expect(not any("unconfined" in s for s in sec), f"unconfined security option: {sec}")
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

        allowed_keys = ALLOWED_ENV_KEYS | image_env_keys
        for entry in conf.get("Env") or []:
            key = str(entry).split("=", 1)[0]
            expect(key in allowed_keys, f"unexpected env var {key}")
        wanted = {f"{k}={v}" for k, v in cfg.env}
        expect(wanted <= set(conf.get("Env") or []), "configured env not applied")

        if problems:
            raise SandboxIsolationError("isolation verification failed: " + "; ".join(problems))

    def _image_env_keys(self) -> set[str]:
        res = self._cli("image", "inspect", "--format", "{{json .Config.Env}}", self.config.image)
        if res.returncode != 0:
            raise SandboxUnavailableError(f"cannot inspect image {self.config.image}")
        env = json.loads(res.stdout) or []
        return {str(e).split("=", 1)[0] for e in env}

    # ------------------------------------------------------------------ run

    def run(self, workspace_dir: Path, command: ContainerCommand) -> RunOutcome:
        name = f"sandbox-agent-{uuid.uuid4().hex[:12]}"
        create_args = self.build_create_args(workspace_dir, command, name)
        image_env = self._image_env_keys()
        created = self._cli(*create_args)
        if created.returncode != 0:
            raise SandboxIsolationError(f"docker create failed: {created.stderr.strip()[:500]}")
        container_id = created.stdout.strip()
        try:
            self.verify(self._inspect(container_id), workspace_dir, image_env)
            return self._start(container_id, name)
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

    def _start(self, container_id: str, name: str) -> RunOutcome:
        limit = self.config.max_output_bytes
        started = time.monotonic()
        proc = subprocess.Popen(
            [self._docker, "start", "--attach", container_id],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            env=_docker_cli_env(),
        )
        assert proc.stdout is not None  # noqa: S101 - guaranteed by PIPE
        assert proc.stderr is not None  # noqa: S101
        out = _BoundedReader(proc.stdout, limit)
        err = _BoundedReader(proc.stderr, limit)
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
        oom = bool(state.get("OOMKilled"))
        exit_code = state.get("ExitCode")
        status: Literal["completed", "timeout", "oom_killed"]
        if timed_out:
            status = "timeout"
        elif oom:
            status = "oom_killed"
        else:
            status = "completed"
        return RunOutcome(
            status=status,
            exit_code=None if timed_out else (int(exit_code) if exit_code is not None else None),
            stdout=out.text,
            stderr=err.text,
            stdout_truncated=out.truncated,
            stderr_truncated=err.truncated,
            stdout_bytes_total=out.total,
            stderr_bytes_total=err.total,
            duration_ms=duration_ms,
            container=name,
        )


def _docker_cli_env() -> dict[str, str]:
    """Environment for the docker *CLI* process (not the container).

    Only variables the CLI needs are passed; provider credentials never reach
    the CLI either. The container environment is set explicitly via --env and
    verified by inspect.
    """
    keep = ("PATH", "HOME", "DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_CONTEXT", "DOCKER_CERT_PATH")
    keep_tls = ("DOCKER_TLS_VERIFY",)
    return {k: v for k, v in os.environ.items() if k in keep or k in keep_tls}
