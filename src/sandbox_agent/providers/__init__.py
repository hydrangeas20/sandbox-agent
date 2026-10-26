"""LLM provider adapters. All provider output is untrusted and validated by the controller."""

from sandbox_agent.providers.base import AgentAction, Provider, Transcript, Turn

__all__ = ["AgentAction", "Provider", "Transcript", "Turn"]
