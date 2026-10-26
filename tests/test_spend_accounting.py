"""Cost accounting for failed requests and the cross-invocation experiment budget (stubbed)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from sandbox_agent.config import ModelBudget
from sandbox_agent.errors import ProviderError
from sandbox_agent.providers.anthropic import AnthropicProvider
from sandbox_agent.providers.base import Transcript

KEY = "sk-ant-api03-STUB-KEY-never-real-000000000000000000"


def failing(exc: Exception) -> Any:
    def transport(body: dict[str, Any], headers: dict[str, str], timeout: float) -> Any:
        raise exc

    return transport


def haiku(transport: Any) -> AnthropicProvider:
    return AnthropicProvider(
        model="claude-haiku-5-5", api_key=KEY, transport=transport, budget=ModelBudget()
    )


def test_ambiguous_failure_is_charged_worst_case_and_traced() -> None:
    """A timeout may still be billed: charge the pre-call worst-case estimate."""
    from sandbox_agent.errors import ProviderHTTPError  # noqa: PLC0415

    p = haiku(failing(ProviderError("anthropic API request failed: TimeoutError")))
    with pytest.raises(ProviderError):
        p.next_action(Transcript(task="x"))
    assert p.usage.calls == 1
    assert p.usage.cost_usd > 0
    assert p.last_call is not None
    assert p.last_call["failed"] is True
    assert p.last_call["cost_usd"] == pytest.approx(p.usage.cost_usd)
    assert ProviderHTTPError  # imported for the next test


@pytest.mark.parametrize(
    ("status", "charged"), [(401, False), (429, False), (400, False), (529, True), (500, True)]
)
def test_http_failures_charged_unless_rejected_before_processing(
    status: int, charged: bool
) -> None:
    from sandbox_agent.errors import ProviderHTTPError  # noqa: PLC0415

    p = haiku(failing(ProviderHTTPError(f"anthropic API HTTP {status}", status=status)))
    with pytest.raises(ProviderError):
        p.next_action(Transcript(task="x"))
    assert (p.usage.cost_usd > 0) is charged


def test_ledger_caps_spend_across_invocations(tmp_path: Path) -> None:
    from sandbox_agent.spend import SpendLedger  # noqa: PLC0415

    ledger = SpendLedger(tmp_path / "ledger.json", experiment_budget_usd=1.00)
    assert ledger.remaining() == pytest.approx(1.00)
    assert ledger.cap(0.50) == pytest.approx(0.50)
    ledger.record("smoke", model="claude-haiku-5-5", cost_usd=0.70, calls=3, tokens=1000)
    reopened = SpendLedger(tmp_path / "ledger.json", experiment_budget_usd=1.00)
    assert reopened.spent() == pytest.approx(0.70)
    assert reopened.cap(0.50) == pytest.approx(0.30)  # the next run gets only what is left
    reopened.record("retry", model="claude-haiku-5-5", cost_usd=0.30, calls=1, tokens=10)
    with pytest.raises(ProviderError, match="experiment budget"):
        SpendLedger(tmp_path / "ledger.json", experiment_budget_usd=1.00).cap(0.50)


def test_cli_refuses_real_model_without_experiment_budget(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from sandbox_agent.cli import main  # noqa: PLC0415

    monkeypatch.setenv("SANDBOX_AGENT_OFFLINE", "0")
    monkeypatch.setenv("ANTHROPIC_API_KEY", KEY)
    code = main(["run", "--provider", "anthropic", "--fixture", "paginator", "--task", "x"])
    assert code == 2
    assert "--experiment-budget-usd" in capsys.readouterr().err


def test_cli_refuses_when_ledger_is_exhausted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from sandbox_agent.cli import main  # noqa: PLC0415
    from sandbox_agent.spend import SpendLedger  # noqa: PLC0415

    ledger = tmp_path / "ledger.json"
    SpendLedger(ledger, 0.50).record(
        "earlier", model="claude-haiku-5-5", cost_usd=0.50, calls=9, tokens=1
    )
    monkeypatch.setenv("SANDBOX_AGENT_OFFLINE", "0")
    monkeypatch.setenv("ANTHROPIC_API_KEY", KEY)
    code = main(
        ["run", "--provider", "anthropic", "--fixture", "paginator", "--task", "x",
         "--experiment-budget-usd", "0.50", "--ledger", str(ledger)]
    )  # fmt: skip
    assert code == 2
    assert "experiment budget exhausted" in capsys.readouterr().err
