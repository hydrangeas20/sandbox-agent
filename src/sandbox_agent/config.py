"""Immutable configuration for isolation, workspace limits and agent budgets.

Every security-relevant knob lives here as a frozen Pydantic model. Fields that
must never be relaxed in the MVP (network, read-only rootfs, privilege flags)
are typed as ``Literal`` so a relaxed value is a validation error, not a
runtime decision.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

DEFAULT_IMAGE = "sandbox-agent-runner:0.1"
SANDBOX_UID = 10001
SANDBOX_GID = 10001
WORKSPACE_MOUNT = "/workspace"

_IMAGE_RE = re.compile(
    r"^[a-z0-9][a-z0-9._/-]{0,127}(:[A-Za-z0-9._-]{1,128})?(@sha256:[0-9a-f]{64})?$"
)

#: Environment variables the container may receive. Nothing is inherited from the host.
ALLOWED_ENV_KEYS = frozenset(
    {"PATH", "HOME", "LANG", "PYTHONDONTWRITEBYTECODE", "PYTHONUNBUFFERED", "PYTHONHASHSEED"}
)

DEFAULT_ENV: tuple[tuple[str, str], ...] = (
    ("PATH", "/usr/local/bin:/usr/bin:/bin"),
    ("HOME", "/tmp"),  # noqa: S108 - path inside the container (private tmpfs)
    ("LANG", "C.UTF-8"),
    ("PYTHONDONTWRITEBYTECODE", "1"),
    ("PYTHONUNBUFFERED", "1"),
    ("PYTHONHASHSEED", "0"),
)

_MiB = 1024 * 1024


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class SandboxConfig(_Frozen):
    """Isolation settings for one container run. Immutable once constructed."""

    image: str = DEFAULT_IMAGE
    user: str = f"{SANDBOX_UID}:{SANDBOX_GID}"
    network: Literal["none"] = "none"
    read_only_rootfs: Literal[True] = True
    privileged: Literal[False] = False
    cap_drop: tuple[Literal["ALL"]] = ("ALL",)
    no_new_privileges: Literal[True] = True
    memory_bytes: int = Field(default=256 * _MiB, ge=16 * _MiB, le=2048 * _MiB)
    cpus: float = Field(default=1.0, ge=0.1, le=4.0)
    pids_limit: int = Field(default=64, ge=8, le=512)
    nofile: int = Field(default=256, ge=32, le=4096)
    fsize_bytes: int = Field(default=32 * _MiB, ge=_MiB, le=512 * _MiB)
    tmpfs_bytes: int = Field(default=64 * _MiB, ge=_MiB, le=512 * _MiB)
    timeout_s: float = Field(default=30.0, gt=0, le=600)
    max_output_bytes: int = Field(default=64 * 1024, ge=1024, le=4 * _MiB)
    env: tuple[tuple[str, str], ...] = DEFAULT_ENV

    @field_validator("image")
    @classmethod
    def _check_image(cls, value: str) -> str:
        if not _IMAGE_RE.fullmatch(value):
            raise ValueError(f"invalid image reference: {value!r}")
        return value

    @field_validator("user")
    @classmethod
    def _check_user(cls, value: str) -> str:
        match = re.fullmatch(r"(\d+):(\d+)", value)
        if not match or int(match.group(1)) == 0 or int(match.group(2)) == 0:
            raise ValueError("sandbox user must be a numeric non-root uid:gid")
        return value

    @field_validator("env")
    @classmethod
    def _check_env(cls, value: tuple[tuple[str, str], ...]) -> tuple[tuple[str, str], ...]:
        keys = [k for k, _ in value]
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate environment keys")
        unknown = set(keys) - ALLOWED_ENV_KEYS
        if unknown:
            raise ValueError(f"environment keys not allowlisted: {sorted(unknown)}")
        return value


class WorkspaceLimits(_Frozen):
    """Limits on the disposable workspace and on file-level tool I/O."""

    max_entries: int = Field(default=2000, ge=1, le=100_000)
    max_total_bytes: int = Field(default=10 * _MiB, ge=1024, le=512 * _MiB)
    max_file_bytes: int = Field(default=256 * 1024, ge=1024, le=16 * _MiB)
    max_search_results: int = Field(default=200, ge=1, le=10_000)
    max_query_chars: int = Field(default=200, ge=1, le=1000)
    max_path_chars: int = Field(default=255, ge=16, le=4096)
    max_path_depth: int = Field(default=16, ge=1, le=64)


class PatchLimits(_Frozen):
    max_edits: int = Field(default=20, ge=1, le=200)
    max_text_bytes: int = Field(default=64 * 1024, ge=16, le=_MiB)


class AgentBudget(_Frozen):
    """Hard ceilings on one agent run. The model cannot extend these."""

    max_iterations: int = Field(default=12, ge=1, le=200)
    max_tool_calls: int = Field(default=20, ge=1, le=500)
    max_wall_clock_s: float = Field(default=300.0, gt=0, le=3600)
    max_policy_denials: int = Field(default=3, ge=1, le=50)
    max_invalid_outputs: int = Field(default=2, ge=1, le=20)
    max_observation_chars: int = Field(default=16_000, ge=256, le=200_000)


class Settings(_Frozen):
    """Process-level paths and switches, resolved once at startup."""

    fixtures_dir: Path
    runs_dir: Path
    offline: bool = True

    @classmethod
    def from_env(cls) -> Settings:
        root = Path(__file__).resolve().parents[2]
        fixtures = Path(os.environ.get("SANDBOX_AGENT_FIXTURES", root / "fixtures" / "repos"))
        runs = Path(os.environ.get("SANDBOX_AGENT_RUNS", root / "runs"))
        offline = os.environ.get("SANDBOX_AGENT_OFFLINE", "1") != "0"
        return cls(fixtures_dir=fixtures, runs_dir=runs, offline=offline)
