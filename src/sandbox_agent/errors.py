"""Exception hierarchy.

Security-relevant failures have dedicated types so callers can fail closed on
them explicitly instead of catching a generic ``Exception``.
"""

from __future__ import annotations

import json
from typing import Any

_DIAGNOSTICS_CHARS = 2000


class SandboxAgentError(Exception):
    """Base class for all errors raised by this package."""


class PolicyViolation(SandboxAgentError):  # noqa: N818 - domain term, not an "Error" suffix
    """A request was denied by policy (path, command, tool name, size limit)."""

    def __init__(self, rule: str, detail: str) -> None:
        super().__init__(f"{rule}: {detail}")
        self.rule = rule
        self.detail = detail


class SandboxUnavailableError(SandboxAgentError):
    """Docker (or the sandbox image) is not available. Never falls back to host execution."""


class SandboxIsolationError(SandboxAgentError):
    """A requested isolation control could not be applied or verified.

    ``diagnostics`` (optional) holds bounded, structured evidence for failures of a
    started run: execution phase, container, exit status, Docker state, attestation
    status and cleanup result. It is appended to the message and capped at
    ``_DIAGNOSTICS_CHARS``. It carries a stderr excerpt only for attestation failures,
    where PID 1 exits before forking the workload, so the excerpt is entrypoint output.
    """

    def __init__(self, message: str, *, diagnostics: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.diagnostics = diagnostics

    def __str__(self) -> str:
        if not self.diagnostics:
            return self.message
        # `phase` first, so truncation never hides which step failed.
        ordered = {"phase": self.diagnostics.get("phase"), **self.diagnostics}
        text = json.dumps(ordered, default=str)
        if len(text) > _DIAGNOSTICS_CHARS:
            text = text[:_DIAGNOSTICS_CHARS] + "...(truncated)"
        return f"{self.message} [diagnostics: {text}]"


class WorkspaceError(SandboxAgentError):
    """The disposable workspace could not be created, populated or cleaned up."""


class ProviderError(SandboxAgentError):
    """The LLM provider failed or returned output that could not be validated."""


class ProviderHTTPError(ProviderError):
    """The provider answered with an HTTP error status (kept for billing decisions)."""

    def __init__(self, message: str, *, status: int) -> None:
        super().__init__(message)
        self.status = status


class ProviderBudgetExceeded(ProviderError):  # noqa: N818 - domain term
    """A model-call, token or cost budget would be exceeded; the task must stop."""


class FixtureError(SandboxAgentError):
    """The requested fixture repository is unknown, invalid or was modified."""
