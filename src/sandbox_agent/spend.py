"""Experiment-level spend ledger with per-request reservations.

One JSON file tracks every real-model request made under an experiment budget, across
separate CLI invocations, retries and crashes:

1. **Reserve** before each request: the adapter's worst-case estimate for that request
   is appended as a ``reserved`` entry, and refused if ``spent + reservation`` would
   exceed the experiment budget. The file is written (and fsynced) *before* the
   request is sent.
2. **Settle** after the request returns or fails: the entry becomes ``settled`` with
   the actual cost from the API's ``usage``, or a conservative estimate when the
   request failed in a way that may have been billed.
3. **Interruption**: if the process is interrupted, killed or crashes between the two,
   the reservation stays ``reserved`` and keeps counting at its reserved amount. Spend
   therefore never silently disappears; at worst it is over-counted.

``spent()`` = settled actual costs + unsettled reservations. Every read-modify-write
holds an exclusive ``flock`` on a sidecar lock file, and writes go to a temp file that
is fsynced and atomically renamed over the ledger, so a crash mid-write leaves the
previous version intact. An unreadable ledger fails closed: no request is allowed.

These are estimates kept by this tool; the Anthropic Console is authoritative, and a
spend limit set there is the only hard cap.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import socket
import tempfile
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sandbox_agent.errors import ProviderBudgetExceeded

LEDGER_VERSION = 2
#: Below this remaining amount a run is refused (a single call could exceed it).
MIN_RUN_BUDGET_USD = 0.001


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _entry_cost(entry: dict[str, Any]) -> float:
    state = entry.get("state", "settled")  # v1 entries were always settled
    if state == "reserved":
        return float(entry.get("reserved_usd", 0.0))
    return float(entry.get("actual_usd", entry.get("cost_usd", 0.0)))


class SpendLedger:
    def __init__(self, path: Path, experiment_budget_usd: float) -> None:
        if experiment_budget_usd <= 0:
            raise ValueError("experiment budget must be positive")
        self.path = path
        self.budget = experiment_budget_usd
        self._lock_path = path.with_name(path.name + ".lock")

    # ------------------------------------------------------------------ storage

    @contextlib.contextmanager
    def _locked(self) -> Iterator[None]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self._lock_path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _load(self) -> dict[str, Any]:
        try:
            text = self.path.read_text()
        except FileNotFoundError:
            return {"version": LEDGER_VERSION, "entries": []}
        try:
            doc = json.loads(text)
        except json.JSONDecodeError:
            doc = None
        if not isinstance(doc, dict) or not isinstance(doc.get("entries"), list):
            # Never treat a damaged ledger as empty: that would reset the budget.
            raise ProviderBudgetExceeded(
                f"experiment ledger {self.path} is unreadable; refusing real-model requests"
            )
        return doc

    def _save(self, doc: dict[str, Any]) -> None:
        doc["version"] = LEDGER_VERSION
        doc["experiment_budget_usd"] = self.budget
        doc["note"] = "Estimated by sandbox-agent; the Anthropic Console is authoritative."
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".ledger-")
        try:
            with os.fdopen(fd, "w") as fh:
                json.dump(doc, fh, indent=2)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.path)
        except BaseException:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp)
            raise
        dir_fd = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)  # make the rename itself durable
        finally:
            os.close(dir_fd)

    # ------------------------------------------------------------------ queries

    def entries(self) -> list[dict[str, Any]]:
        with self._locked():
            return list(self._load()["entries"])

    def spent(self) -> float:
        return sum(_entry_cost(e) for e in self.entries())

    def remaining(self) -> float:
        return max(0.0, self.budget - self.spent())

    def cap(self, requested_usd: float) -> float:
        """The cap a new run may use; raises if the experiment budget is exhausted."""
        remaining = self.remaining()
        if remaining < MIN_RUN_BUDGET_USD:
            raise ProviderBudgetExceeded(
                f"experiment budget exhausted: ${self.spent():.4f} of ${self.budget:.2f} "
                f"recorded in {self.path}"
            )
        return min(requested_usd, remaining)

    def summary(self) -> dict[str, Any]:
        entries = self.entries()
        unsettled = [e for e in entries if e.get("state") == "reserved"]
        return {
            "path": str(self.path),
            "experiment_budget_usd": self.budget,
            "spent_usd": round(sum(_entry_cost(e) for e in entries), 6),
            "requests": len(entries),
            "unsettled_reservations": len(unsettled),
            "unsettled_usd": round(sum(_entry_cost(e) for e in unsettled), 6),
        }

    # ------------------------------------------------------------------ updates

    def reserve(self, amount_usd: float, *, label: str, model: str) -> str:
        """Persist a reservation for one request; raise if it would exceed the budget."""
        if amount_usd < 0:
            raise ValueError("reservation must be non-negative")
        with self._locked():
            doc = self._load()
            spent = sum(_entry_cost(e) for e in doc["entries"])
            if spent + amount_usd > self.budget:
                raise ProviderBudgetExceeded(
                    f"experiment budget would be exceeded: ${spent:.4f} spent or reserved, "
                    f"next request up to ${amount_usd:.4f}, budget ${self.budget:.2f}"
                )
            rid = uuid.uuid4().hex
            doc["entries"].append(
                {
                    "id": rid,
                    "state": "reserved",
                    "reserved_usd": round(amount_usd, 6),
                    "label": label,
                    "model": model,
                    "reserved_utc": _now(),
                    "host": socket.gethostname(),
                    "pid": os.getpid(),
                }
            )
            self._save(doc)
            return rid

    def settle(
        self,
        reservation_id: str,
        actual_usd: float,
        *,
        outcome: str,
        tokens: int = 0,
        basis: str = "reported usage",
    ) -> None:
        with self._locked():
            doc = self._load()
            for entry in doc["entries"]:
                if entry.get("id") == reservation_id:
                    if entry.get("state") != "reserved":
                        raise ValueError(f"reservation {reservation_id} already settled")
                    entry.update(
                        state="settled",
                        actual_usd=round(actual_usd, 6),
                        outcome=outcome,
                        tokens=tokens,
                        cost_basis=basis,
                        settled_utc=_now(),
                        exceeded_reservation=actual_usd > float(entry["reserved_usd"]),
                    )
                    self._save(doc)
                    return
        raise ValueError(f"unknown reservation {reservation_id}")
