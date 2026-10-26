"""Experiment ledger: reserve before each model request, settle after, survive interruption.

All tests use stub transports; no network and no credentials.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from sandbox_agent.config import ModelBudget, Settings
from sandbox_agent.errors import ProviderBudgetExceeded, ProviderError, ProviderHTTPError
from sandbox_agent.providers.anthropic import AnthropicProvider
from sandbox_agent.providers.base import Transcript
from sandbox_agent.service import TaskRequest, run_task
from sandbox_agent.spend import SpendLedger
from tests.fakes import FakeRunner
from tests.test_security_review import _stub_docker

KEY = "sk-ant-api03-STUB-KEY-never-real-000000000000000000"
OK = {
    "content": [{"type": "tool_use", "id": "t0", "name": "list_files", "input": {}}],
    "usage": {"input_tokens": 2000, "output_tokens": 100},
}
HAIKU_OK_COST = (2000 * 0.10 + 100 * 0.50) / 1e6


def provider(ledger: SpendLedger | None, transport: Any) -> AnthropicProvider:
    return AnthropicProvider(
        model="claude-haiku-5-5",
        api_key=KEY,
        transport=transport,
        budget=ModelBudget(),
        ledger=ledger,
    )


def states(path: Path) -> list[str]:
    return [e["state"] for e in json.loads(path.read_text())["entries"]]


@pytest.fixture
def ledger(tmp_path: Path) -> SpendLedger:
    return SpendLedger(tmp_path / "ledger.json", experiment_budget_usd=5.0)


# ---------------------------------------------------------------- reserve / settle


def test_reservation_is_persisted_before_the_request_is_sent(ledger: SpendLedger) -> None:
    seen: list[list[str]] = []

    def transport(body: dict[str, Any], headers: dict[str, str], timeout: float) -> Any:
        seen.append(states(ledger.path))  # read from disk, as another process would
        return OK

    p = provider(ledger, transport)
    p.next_action(Transcript(task="x"))
    assert seen == [["reserved"]]
    entry = json.loads(ledger.path.read_text())["entries"][0]
    assert entry["state"] == "settled"
    assert entry["reserved_usd"] >= entry["actual_usd"]
    assert entry["actual_usd"] == pytest.approx(HAIKU_OK_COST)
    assert ledger.spent() == pytest.approx(HAIKU_OK_COST)


@pytest.mark.parametrize(
    ("exc", "charged"),
    [
        (ProviderHTTPError("anthropic API HTTP 429", status=429), False),
        (ProviderError("anthropic API request failed: TimeoutError"), True),
        (ProviderHTTPError("anthropic API HTTP 529", status=529), True),
    ],
)
def test_failed_requests_are_settled(ledger: SpendLedger, exc: Exception, charged: bool) -> None:
    def transport(*_a: Any) -> Any:
        raise exc

    with pytest.raises(ProviderError):
        provider(ledger, transport).next_action(Transcript(task="x"))
    entry = json.loads(ledger.path.read_text())["entries"][0]
    assert entry["state"] == "settled"
    assert entry["outcome"] == "failed"
    assert (entry["actual_usd"] > 0) is charged
    if charged:
        assert entry["actual_usd"] == pytest.approx(entry["reserved_usd"])


# ---------------------------------------------------------------- interruption / crash


def test_keyboard_interrupt_leaves_reservation_counted(ledger: SpendLedger) -> None:
    def transport(*_a: Any) -> Any:
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        provider(ledger, transport).next_action(Transcript(task="x"))
    reopened = SpendLedger(ledger.path, experiment_budget_usd=5.0)
    assert states(ledger.path) == ["reserved"]
    reserved = json.loads(ledger.path.read_text())["entries"][0]["reserved_usd"]
    assert reopened.spent() == pytest.approx(reserved)
    assert reopened.summary()["unsettled_reservations"] == 1


CRASH_SCRIPT = """
import sys, time
from pathlib import Path
from sandbox_agent.config import ModelBudget
from sandbox_agent.providers.anthropic import AnthropicProvider
from sandbox_agent.providers.base import Transcript
from sandbox_agent.spend import SpendLedger

def hang(*_a):
    print("IN-FLIGHT", flush=True)
    time.sleep(60)

ledger = SpendLedger(Path(sys.argv[1]), experiment_budget_usd=float(sys.argv[2]))
p = AnthropicProvider(model="claude-haiku-5-5", api_key="sk-ant-api03-STUB-000000000000000000",
                      transport=hang, budget=ModelBudget(), ledger=ledger)
p.next_action(Transcript(task="x"))
"""


def test_sigkill_mid_request_preserves_reservation_and_blocks_overspend(tmp_path: Path) -> None:
    path = tmp_path / "ledger.json"
    script = tmp_path / "crash.py"
    script.write_text(CRASH_SCRIPT)
    proc = subprocess.Popen(
        [sys.executable, str(script), str(path), "0.01"], stdout=subprocess.PIPE, text=True
    )
    assert proc.stdout is not None
    assert proc.stdout.readline().strip() == "IN-FLIGHT"
    os.kill(proc.pid, signal.SIGKILL)  # no cleanup code can run
    proc.wait()
    assert states(path) == ["reserved"]
    reserved = json.loads(path.read_text())["entries"][0]["reserved_usd"]
    # Budget chosen so the same request fits *only if* the orphan were forgotten.
    after = SpendLedger(path, experiment_budget_usd=reserved * 1.5)
    assert after.spent() == pytest.approx(reserved)
    assert after.summary()["unsettled_reservations"] == 1
    sent: list[int] = []

    def transport(*_a: Any) -> Any:
        sent.append(1)
        return OK

    with pytest.raises(ProviderBudgetExceeded, match="experiment budget"):
        provider(after, transport).next_action(Transcript(task="x"))
    assert sent == []  # refused before any request


# ---------------------------------------------------------------- retries and caps


def test_retries_count_toward_the_same_budget(
    tmp_path: Path, fixtures_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_docker(monkeypatch, FakeRunner())
    led = SpendLedger(tmp_path / "ledger.json", experiment_budget_usd=5.0)
    responses: list[Any] = [
        ProviderError("anthropic API request failed: TimeoutError"),
        ProviderHTTPError("anthropic API HTTP 529", status=529),
        {"content": [{"type": "tool_use", "id": "f", "name": "finish", "input": {"summary": "s"}}],
         "usage": {"input_tokens": 2000, "output_tokens": 50}},
    ]  # fmt: skip

    def transport(*_a: Any) -> Any:
        item = responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    settings = Settings(fixtures_dir=fixtures_dir, runs_dir=tmp_path / "runs", offline=False)
    result = run_task(
        TaskRequest(fixture="paginator", task="x", provider="anthropic"),
        settings,
        provider_factory=lambda _r: provider(led, transport),
    )
    entries = json.loads(led.path.read_text())["entries"]
    assert [e["outcome"] for e in entries] == ["failed", "failed", "ok"]
    assert result.model_usage is not None
    assert result.model_usage["calls"] == 3
    assert led.spent() == pytest.approx(result.model_usage["cost_usd"])


def test_experiment_budget_is_enforced_per_request(tmp_path: Path) -> None:
    led = SpendLedger(tmp_path / "ledger.json", experiment_budget_usd=0.003)
    p = provider(led, lambda *_a: OK)
    p.next_action(Transcript(task="x"))  # reserve ~0.0007, settle ~0.00025
    refused = None
    for _ in range(20):
        try:
            p.next_action(Transcript(task="x"))
        except ProviderBudgetExceeded as exc:
            refused = exc
            break
    assert refused is not None
    assert "experiment budget" in str(refused)
    assert all(s == "settled" for s in states(led.path))
    assert led.spent() <= 0.003


# ---------------------------------------------------------------- durability


def test_failed_write_keeps_previous_ledger(
    ledger: SpendLedger, monkeypatch: pytest.MonkeyPatch
) -> None:
    rid = ledger.reserve(0.10, label="a", model="m")
    ledger.settle(rid, 0.05, outcome="ok")
    before = ledger.path.read_text()

    def broken_replace(*_a: Any, **_k: Any) -> None:
        raise OSError("disk full")

    monkeypatch.setattr("sandbox_agent.spend.os.replace", broken_replace)
    with pytest.raises(OSError, match="disk full"):
        ledger.reserve(0.10, label="b", model="m")
    assert ledger.path.read_text() == before
    assert not list(ledger.path.parent.glob(".ledger-*"))  # no stray temp files


def test_corrupt_ledger_fails_closed(ledger: SpendLedger) -> None:
    ledger.path.write_text('{"entries": [ {"state": "settled", "actual_usd": 4.0}, ')  # truncated
    with pytest.raises(ProviderBudgetExceeded, match="unreadable"):
        ledger.spent()
    with pytest.raises(ProviderBudgetExceeded, match="unreadable"):
        ledger.reserve(0.01, label="x", model="m")


def test_concurrent_reservations_do_not_lose_updates(tmp_path: Path) -> None:
    path = tmp_path / "ledger.json"
    errors: list[Exception] = []

    def worker() -> None:
        try:
            led = SpendLedger(path, experiment_budget_usd=100.0)
            for _ in range(10):
                led.settle(led.reserve(0.01, label="w", model="m"), 0.01, outcome="ok")
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert len(json.loads(path.read_text())["entries"]) == 50
    assert SpendLedger(path, 100.0).spent() == pytest.approx(0.50)


def test_real_provider_requires_a_ledger(
    fixtures_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", KEY)
    settings = Settings(fixtures_dir=fixtures_dir, runs_dir=tmp_path, offline=False)
    r = run_task(TaskRequest(fixture="paginator", task="x", provider="anthropic"), settings)
    assert r.status == "provider_error"
    assert "experiment budget" in r.reason
    time.sleep(0)  # no request was attempted (no transport configured)


# ---------------------------------------------------------------- the live smoke configuration


def _smoke_provider(ledger: SpendLedger, transport: Any) -> AnthropicProvider:
    """Exactly what `sandbox-agent run` builds for the live-smoke workflow."""
    return AnthropicProvider(
        model="claude-haiku-5-5",
        api_key=KEY,
        transport=transport,
        budget=ModelBudget(max_cost_usd=0.50, max_model_calls=12),
        ledger=ledger,
        ledger_label="paginator",
    )


def _tool(n: int, usage: dict[str, int]) -> dict[str, Any]:
    return {
        "content": [{"type": "tool_use", "id": f"t{n}", "name": "list_files", "input": {}}],
        "usage": usage,
    }


@pytest.mark.parametrize("behaviour", ["never_finishes", "maximal_usage", "always_times_out"])
def test_live_smoke_configuration_is_bounded(
    tmp_path: Path, fixtures_dir: Path, monkeypatch: pytest.MonkeyPatch, behaviour: str
) -> None:
    _stub_docker(monkeypatch, FakeRunner())
    led = SpendLedger(tmp_path / "ledger.json", experiment_budget_usd=0.50)
    requests: list[int] = []

    def transport(body: dict[str, Any], headers: dict[str, str], timeout: float) -> Any:
        # A reservation for this request is already on disk when it is sent.
        assert (
            sum(e["state"] == "reserved" for e in json.loads(led.path.read_text())["entries"]) == 1
        )
        assert body["max_tokens"] == 1024
        assert body["model"] == "claude-haiku-5-5"
        n = len(requests)
        requests.append(n)
        if behaviour == "always_times_out":
            raise ProviderError("anthropic API request failed: TimeoutError")
        usage = {
            "input_tokens": 90_000 if behaviour == "maximal_usage" else 3_000,
            "output_tokens": 1024,
        }
        return _tool(n, usage)

    settings = Settings(fixtures_dir=fixtures_dir, runs_dir=tmp_path / "runs", offline=False)
    result = run_task(
        TaskRequest(
            fixture="paginator", task="x", provider="anthropic",
            model_budget=ModelBudget(max_cost_usd=0.50, max_model_calls=12),
        ),
        settings,
        provider_factory=lambda _r: _smoke_provider(led, transport),
    )  # fmt: skip
    entries = json.loads(led.path.read_text())["entries"]
    assert len(requests) <= 12
    assert len(entries) == len(requests)  # one reservation per request, no more, no fewer
    assert all(e["state"] == "settled" for e in entries)
    assert result.status in {"budget_exhausted", "provider_error"}
    assert result.model_usage is not None
    assert result.model_usage["calls"] == len(requests)
    assert led.spent() <= 0.50
    assert result.model_usage["cost_usd"] <= 0.50
    if behaviour == "always_times_out":
        assert len(requests) == 3  # max_invalid_outputs=2: the third failure ends the run
