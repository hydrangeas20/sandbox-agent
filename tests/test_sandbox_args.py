"""Unit tests for sandbox argument construction and fail-closed verification (no Docker)."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import pytest

from sandbox_agent.config import SandboxConfig
from sandbox_agent.errors import SandboxIsolationError, SandboxUnavailableError
from sandbox_agent.sandbox import ContainerCommand, DockerSandbox

CMD = ContainerCommand(argv=("python3", "-c", "print(1)"))


@pytest.fixture
def root(tmp_path: Path) -> Path:
    r = tmp_path / "wsroot"
    (r / "ws").mkdir(parents=True)
    return r


@pytest.fixture
def sandbox(root: Path) -> DockerSandbox:
    return DockerSandbox(SandboxConfig(), root, docker_bin="/usr/bin/false")


def good_inspect(cfg: SandboxConfig, source: Path) -> dict[str, Any]:
    return {
        "HostConfig": {
            "NetworkMode": "none",
            "Privileged": False,
            "CapDrop": ["ALL"],
            "CapAdd": None,
            "SecurityOpt": ["no-new-privileges"],
            "ReadonlyRootfs": True,
            "Memory": cfg.memory_bytes,
            "MemorySwap": cfg.memory_bytes,
            "NanoCpus": round(cfg.cpus * 1e9),
            "PidsLimit": cfg.pids_limit,
            "Ulimits": [
                {"Name": "nofile", "Soft": cfg.nofile, "Hard": cfg.nofile},
                {"Name": "fsize", "Soft": cfg.fsize_bytes, "Hard": cfg.fsize_bytes},
            ],
            "Tmpfs": {"/tmp": "rw,noexec,nosuid,nodev,size=1"},
            "IpcMode": "none",
            "PidMode": "",
            "UTSMode": "",
            "UsernsMode": "",
            "CgroupnsMode": "private",
            "Devices": [],
            "Binds": None,
            "VolumesFrom": None,
            "LogConfig": {"Type": "none"},
        },
        "Config": {"User": cfg.user, "Env": [f"{k}={v}" for k, v in cfg.env]},
        "Mounts": [
            {
                "Type": "bind",
                "Source": str(source.resolve()),
                "Destination": "/workspace",
                "RW": False,
            }
        ],
    }


def test_create_args_contain_every_control(sandbox: DockerSandbox, root: Path) -> None:
    args = sandbox.build_create_args(root / "ws", CMD, "n")
    joined = " ".join(args)
    for flag in (
        "--network none",
        "--user 10001:10001",
        "--cap-drop ALL",
        "--security-opt no-new-privileges",
        "--read-only",
        "--pids-limit 64",
        "--ipc none",
        "--cgroupns private",
        "--log-driver none",
    ):
        assert flag in joined
    assert "--privileged" not in args
    assert "/var/run/docker.sock" not in joined
    assert "readonly" in next(a for a in args if a.startswith("type=bind"))
    # Command comes after the image and a `--` separator; it is never a shell string.
    sep = args.index("--")
    assert args[sep + 1] == sandbox.config.image
    assert tuple(args[sep + 2 :]) == CMD.argv


def test_verify_accepts_matching_container(sandbox: DockerSandbox, root: Path) -> None:
    sandbox.verify(good_inspect(sandbox.config, root / "ws"), root / "ws", set())


MUTATIONS: dict[str, tuple[str, str, Any]] = {
    "network_bridge": ("HostConfig", "NetworkMode", "bridge"),
    "network_host": ("HostConfig", "NetworkMode", "host"),
    "privileged": ("HostConfig", "Privileged", True),
    "cap_add": ("HostConfig", "CapAdd", ["SYS_ADMIN"]),
    "cap_drop_missing": ("HostConfig", "CapDrop", []),
    "no_nnp": ("HostConfig", "SecurityOpt", []),
    "seccomp_unconfined": (
        "HostConfig",
        "SecurityOpt",
        ["no-new-privileges", "seccomp=unconfined"],
    ),
    "rw_rootfs": ("HostConfig", "ReadonlyRootfs", False),
    "memory": ("HostConfig", "Memory", 0),
    "swap": ("HostConfig", "MemorySwap", -1),
    "pids": ("HostConfig", "PidsLimit", 0),
    "cpus": ("HostConfig", "NanoCpus", 0),
    "ulimits": ("HostConfig", "Ulimits", []),
    "tmp_exec": ("HostConfig", "Tmpfs", {"/tmp": "rw"}),
    "pid_host": ("HostConfig", "PidMode", "host"),
    "cgroupns_host": ("HostConfig", "CgroupnsMode", "host"),
    "devices": ("HostConfig", "Devices", [{"PathOnHost": "/dev/kvm"}]),
    "binds": ("HostConfig", "Binds", ["/:/host"]),
    "log_driver": ("HostConfig", "LogConfig", {"Type": "json-file"}),
    "root_user": ("Config", "User", "0:0"),
    "secret_env": ("Config", "Env", ["ANTHROPIC_API_KEY=sk-ant-xxx"]),
}


@pytest.mark.parametrize("name", sorted(MUTATIONS))
def test_verify_rejects_deviation(name: str, sandbox: DockerSandbox, root: Path) -> None:
    section, key, value = MUTATIONS[name]
    data = good_inspect(sandbox.config, root / "ws")
    data[section][key] = value
    with pytest.raises(SandboxIsolationError):
        sandbox.verify(data, root / "ws", set())


@pytest.mark.parametrize(
    "mounts",
    [
        [],
        [
            {
                "Type": "bind",
                "Source": "/var/run/docker.sock",
                "Destination": "/var/run/docker.sock",
                "RW": True,
            }
        ],
        [{"Type": "bind", "Source": "WS", "Destination": "/workspace", "RW": True}],
        [
            {"Type": "bind", "Source": "WS", "Destination": "/workspace", "RW": False},
            {"Type": "volume", "Source": "/x", "Destination": "/data", "RW": True},
        ],
    ],
    ids=["none", "docker_sock", "rw_workspace", "extra_volume"],
)
def test_verify_rejects_extra_mount(
    mounts: list[dict[str, Any]], sandbox: DockerSandbox, root: Path
) -> None:
    data = good_inspect(sandbox.config, root / "ws")
    patched = copy.deepcopy(mounts)
    for m in patched:
        if m["Source"] == "WS":
            m["Source"] = str((root / "ws").resolve())
    data["Mounts"] = patched
    with pytest.raises(SandboxIsolationError):
        sandbox.verify(data, root / "ws", set())


def test_mount_source_outside_root_rejected(sandbox: DockerSandbox, tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    with pytest.raises(SandboxIsolationError):
        sandbox.validate_mount_source(outside)
    with pytest.raises(SandboxIsolationError):
        sandbox.validate_mount_source(sandbox.workspace_root)


def test_mount_source_symlink_rejected(sandbox: DockerSandbox, root: Path) -> None:
    link = root / "link"
    link.symlink_to(root / "ws")
    with pytest.raises(SandboxIsolationError):
        sandbox.validate_mount_source(link)


@pytest.mark.parametrize("bad_root", ["/", "/etc", "/home"])
def test_config_rejects_dangerous_mounts(bad_root: str) -> None:
    with pytest.raises(SandboxIsolationError):
        DockerSandbox(SandboxConfig(), Path(bad_root), docker_bin="/usr/bin/false")


def test_home_as_root_rejected() -> None:
    with pytest.raises(SandboxIsolationError):
        DockerSandbox(SandboxConfig(), Path.home(), docker_bin="/usr/bin/false")


def test_no_docker_fails_closed(root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PATH", "/nonexistent")
    with pytest.raises(SandboxUnavailableError):
        DockerSandbox(SandboxConfig(), root)


def test_preflight_unavailable_daemon_fails_closed(root: Path) -> None:
    sb = DockerSandbox(SandboxConfig(), root, docker_bin="/usr/bin/false")
    with pytest.raises(SandboxUnavailableError):
        sb.preflight()


@pytest.mark.parametrize("arg", ["a\x00b", "x" * 9000])
def test_container_command_rejects_control_chars(arg: str) -> None:
    with pytest.raises(ValueError, match="argv"):
        ContainerCommand(argv=("python3", arg))
