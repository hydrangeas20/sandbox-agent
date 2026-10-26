"""Execution trace (in-memory event log; JSONL persistence and pattern redaction in M8)."""

from __future__ import annotations

import copy
import time
from typing import Any


class Tracer:
    def __init__(self, correlation_id: str) -> None:
        self.correlation_id = correlation_id
        self.events: list[dict[str, Any]] = []
        self._seq = 0
        self._secrets: set[str] = set()

    def register_secrets(self, *values: str) -> None:
        self._secrets.update(v for v in values if v)

    def emit(self, event: str, **fields: Any) -> dict[str, Any]:
        self._seq += 1
        record = {"seq": self._seq, "ts": time.time(), "cid": self.correlation_id, "event": event}
        record.update(fields)
        self.events.append(record)
        return record

    def redacted_events(self) -> list[dict[str, Any]]:
        return [self._scrub(copy.deepcopy(e)) for e in self.events]

    def _scrub(self, value: Any) -> Any:
        if isinstance(value, str):
            for secret in self._secrets:
                value = value.replace(secret, "[REDACTED]")
            return value
        if isinstance(value, dict):
            return {k: self._scrub(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self._scrub(v) for v in value]
        return value
