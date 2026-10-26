"""Experiment-level spend ledger: one budget across separate CLI invocations.

Each real-model run appends its *estimated* cost (from the adapter's usage
accounting) to a local JSON file. Before a run, the per-task or per-eval cap is
reduced to whatever remains of the experiment budget, and a run is refused once
nothing remains.

This is an estimate kept by this tool. The Anthropic Console's usage and billing
pages are the source of truth, and a spend limit set there is the only hard cap.
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sandbox_agent.errors import ProviderError

#: Below this remaining amount a run is refused (a single call could exceed it).
MIN_RUN_BUDGET_USD = 0.01


class SpendLedger:
    def __init__(self, path: Path, experiment_budget_usd: float) -> None:
        if experiment_budget_usd <= 0:
            raise ValueError("experiment budget must be positive")
        self.path = path
        self.budget = experiment_budget_usd

    def entries(self) -> list[dict[str, Any]]:
        try:
            data = json.loads(self.path.read_text())
        except FileNotFoundError:
            return []
        entries = data.get("entries", [])
        return entries if isinstance(entries, list) else []

    def spent(self) -> float:
        return sum(float(e.get("cost_usd", 0.0)) for e in self.entries())

    def remaining(self) -> float:
        return max(0.0, self.budget - self.spent())

    def cap(self, requested_usd: float) -> float:
        """The cap a new run may use; raises if the experiment budget is exhausted."""
        remaining = self.remaining()
        if remaining < MIN_RUN_BUDGET_USD:
            raise ProviderError(
                f"experiment budget exhausted: ${self.spent():.4f} of ${self.budget:.2f} "
                f"recorded in {self.path}"
            )
        return min(requested_usd, remaining)

    def record(self, label: str, *, model: str, cost_usd: float, calls: int, tokens: int) -> None:
        entries = self.entries()
        entries.append(
            {
                "utc": datetime.now(UTC).isoformat(timespec="seconds"),
                "label": label,
                "model": model,
                "cost_usd": round(cost_usd, 6),
                "calls": calls,
                "tokens": tokens,
            }
        )
        doc = {
            "experiment_budget_usd": self.budget,
            "note": "Estimated by sandbox-agent; the Anthropic Console is authoritative.",
            "entries": entries,
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".ledger-")
        with os.fdopen(fd, "w") as fh:
            json.dump(doc, fh, indent=2)
        os.replace(tmp, self.path)
