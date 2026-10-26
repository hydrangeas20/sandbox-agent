"""Execution trace (minimal in-memory event log; extended in M8)."""

from __future__ import annotations

import time
from typing import Any


class Tracer:
    def __init__(self, correlation_id: str) -> None:
        self.correlation_id = correlation_id
        self.events: list[dict[str, Any]] = []
        self._seq = 0

    def emit(self, event: str, **fields: Any) -> dict[str, Any]:
        self._seq += 1
        record = {"seq": self._seq, "ts": time.time(), "cid": self.correlation_id, "event": event}
        record.update(fields)
        self.events.append(record)
        return record
