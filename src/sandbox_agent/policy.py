"""Command allowlist.

The agent never supplies argv. It names a command from :data:`ALLOWED_COMMANDS`
and may add a *test selector* that must match a strict dotted-identifier
pattern rooted at the ``tests`` package. Anything else is a policy denial.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from sandbox_agent.errors import PolicyViolation
from sandbox_agent.sandbox import ContainerCommand

_SELECTOR = re.compile(r"^tests(\.[A-Za-z_][A-Za-z0-9_]{0,63}){0,6}$")


@dataclass(frozen=True)
class CommandSpec:
    description: str
    argv: tuple[str, ...]
    selector_argv: tuple[str, ...] | None = None


ALLOWED_COMMANDS: dict[str, CommandSpec] = {
    "unittest": CommandSpec(
        description="Run the repository's stdlib unittest suite (tests/ package).",
        argv=("python3", "-m", "unittest", "discover", "-s", "tests", "-t", ".", "-v"),
        selector_argv=("python3", "-m", "unittest", "-v"),
    ),
}


def build_command(name: str, selector: str | None = None) -> ContainerCommand:
    spec = ALLOWED_COMMANDS.get(name)
    if spec is None:
        raise PolicyViolation(
            "command.not_allowlisted",
            f"{name!r} is not an allowlisted command; allowed: {sorted(ALLOWED_COMMANDS)}",
        )
    if selector is None:
        return ContainerCommand(argv=spec.argv)
    if spec.selector_argv is None:
        raise PolicyViolation("command.selector_unsupported", f"{name!r} does not take a selector")
    if not _SELECTOR.fullmatch(selector):
        raise PolicyViolation(
            "command.bad_selector",
            "selector must be a dotted test id under 'tests', e.g. tests.test_core.MyTest",
        )
    return ContainerCommand(argv=(*spec.selector_argv, selector))
