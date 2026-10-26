"""Exception hierarchy.

Security-relevant failures have dedicated types so callers can fail closed on
them explicitly instead of catching a generic ``Exception``.
"""

from __future__ import annotations


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
    """A requested isolation control could not be applied or verified."""


class WorkspaceError(SandboxAgentError):
    """The disposable workspace could not be created, populated or cleaned up."""


class ProviderError(SandboxAgentError):
    """The LLM provider failed or returned output that could not be validated."""


class FixtureError(SandboxAgentError):
    """The requested fixture repository is unknown, invalid or was modified."""
