from __future__ import annotations

import pytest
from pydantic import ValidationError

from sandbox_agent.config import AgentBudget, SandboxConfig


def test_defaults_are_locked_down() -> None:
    cfg = SandboxConfig()
    assert cfg.network == "none"
    assert cfg.read_only_rootfs is True
    assert cfg.privileged is False
    assert cfg.cap_drop == ("ALL",)
    assert cfg.no_new_privileges is True
    assert not cfg.user.startswith("0:")


def test_config_is_immutable() -> None:
    cfg = SandboxConfig()
    with pytest.raises(ValidationError):
        cfg.network = "bridge"  # type: ignore[misc,assignment]


@pytest.mark.parametrize(
    "overrides",
    [
        {"network": "bridge"},
        {"network": "host"},
        {"privileged": True},
        {"read_only_rootfs": False},
        {"no_new_privileges": False},
        {"cap_drop": ()},
        {"user": "0:0"},
        {"user": "root"},
        {"memory_bytes": 10 * 1024**3},
        {"pids_limit": 100_000},
        {"timeout_s": 0},
        {"image": "evil; rm -rf /"},
        {"env": (("ANTHROPIC_API_KEY", "x"),)},
        {"env": (("PATH", "/a"), ("PATH", "/b"))},
        {"unexpected": 1},
    ],
)
def test_unsafe_settings_rejected(overrides: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        SandboxConfig(**overrides)  # type: ignore[arg-type]


def test_budget_bounds() -> None:
    with pytest.raises(ValidationError):
        AgentBudget(max_iterations=0)
    assert AgentBudget().max_tool_calls == 20
