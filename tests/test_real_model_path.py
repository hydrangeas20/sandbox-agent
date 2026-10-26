"""Real-model execution path, exercised with stub transports (no credentials, no network).

These tests cover the Anthropic adapter as used by the service: explicit opt-in,
model-call / token / cost budgets, usage accounting, error mapping without
credential leakage, and controller-owned status. Results here are *stubbed*; live
model results are produced only by ``sandbox-agent eval --provider anthropic``.
"""

from __future__ import annotations

import http.client
import io
import json
import urllib.error
from pathlib import Path
from typing import Any

import pytest

from sandbox_agent.config import ModelBudget, Settings
from sandbox_agent.errors import ProviderBudgetExceeded, ProviderError
from sandbox_agent.providers import anthropic as anth
from sandbox_agent.providers.anthropic import AnthropicProvider
from sandbox_agent.providers.base import Transcript
from sandbox_agent.service import TaskRequest, run_task
from tests.fakes import FakeRunner, outcome
from tests.test_security_review import _stub_docker

KEY = "sk-ant-api03-STUB-KEY-never-real-000000000000000000"
FIX = {
    "path": "paginator/core.py",
    "old": "    start = page * per_page\n",
    "new": "    start = (page - 1) * per_page\n",
}


def tool_use(name: str, args: dict[str, Any], n: int, text: str = "") -> dict[str, Any]:
    content: list[dict[str, Any]] = [{"type": "text", "text": text}] if text else []
    content.append({"type": "tool_use", "id": f"toolu_{n:02d}", "name": name, "input": args})
    return {
        "content": content,
        "stop_reason": "tool_use",
        "usage": {
            "input_tokens": 1500 + 400 * n,
            "output_tokens": 120,
            "cache_creation_input_tokens": 0 if n else 900,
            "cache_read_input_tokens": 900 if n else 0,
        },
    }


class ScriptedTransport:
    """Replays canned Messages API responses and records requests."""

    def __init__(self, responses: list[Any]) -> None:
        self.responses = list(responses)
        self.requests: list[tuple[dict[str, Any], dict[str, str], float]] = []

    def __call__(self, body: dict[str, Any], headers: dict[str, str], timeout: float) -> Any:
        self.requests.append((body, headers, timeout))
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def fix_responses() -> list[Any]:
    return [
        tool_use("run_tests", {"command": "unittest"}, 0, "Reproduce first."),
        tool_use("read_file", {"path": "paginator/core.py"}, 1),
        tool_use("apply_patch", {"edits": [FIX]}, 2, "Pages are 1-indexed."),
        tool_use("run_tests", {"command": "unittest"}, 3),
        tool_use("finish", {"summary": "Fixed the start offset."}, 4),
    ]


@pytest.fixture
def settings(fixtures_dir: Path, tmp_path: Path) -> Settings:
    return Settings(fixtures_dir=fixtures_dir, runs_dir=tmp_path / "runs", offline=False)


def provider(transport: Any, **budget: Any) -> AnthropicProvider:
    return AnthropicProvider(api_key=KEY, transport=transport, budget=ModelBudget(**budget))


FAIL = outcome(1, "Ran 6 tests in 0.01s\n\nFAILED (failures=2)\n")
PASS = outcome(0, "Ran 6 tests in 0.01s\n\nOK\n")


# ---------------------------------------------------------------- opt-in


def test_real_provider_requires_explicit_opt_in(
    fixtures_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", KEY)
    offline = Settings(fixtures_dir=fixtures_dir, runs_dir=tmp_path, offline=True)
    r = run_task(TaskRequest(fixture="paginator", task="x", provider="anthropic"), offline)
    assert r.status == "provider_error"
    assert "offline mode" in r.reason


def test_missing_key_and_unknown_model_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(ProviderError, match="not set"):
        AnthropicProvider()
    with pytest.raises(ProviderError, match="no pricing"):
        AnthropicProvider(model="claude-unknown-9", api_key=KEY)


# ---------------------------------------------------------------- end-to-end (stubbed)


def test_stubbed_model_fixes_bug_with_usage_and_no_key_leak(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_docker(monkeypatch, FakeRunner([FAIL, PASS]))
    transport = ScriptedTransport(fix_responses())
    p = provider(transport)
    r = run_task(
        TaskRequest(fixture="paginator", task="fix it", provider="anthropic"),
        settings,
        provider_factory=lambda _r: p,
    )
    assert r.status == "succeeded", r.reason
    assert r.provider == "anthropic"
    assert r.model_usage is not None
    assert r.model_usage["calls"] == 5
    assert r.model_usage["cost_usd"] > 0
    assert r.model_usage["cache_read_input_tokens"] == 3600
    calls = [e for e in r.trace if e["event"] == "model_call"]
    assert len(calls) == 5
    assert all(c["latency_ms"] >= 0 and c["usage_reported"] for c in calls)
    assert KEY not in r.model_dump_json()
    body, headers, timeout = transport.requests[0]
    assert headers["x-api-key"] == KEY
    assert KEY not in json.dumps(body)
    assert body["max_tokens"] == ModelBudget().max_output_tokens_per_call
    assert timeout == ModelBudget().request_timeout_s
    # tool_result blocks are paired with the model's tool_use ids
    last = transport.requests[-1][0]["messages"]
    ids = [b["id"] for m in last if m["role"] == "assistant" for b in m["content"]]
    results = [
        b["tool_use_id"]
        for m in last
        if m["role"] == "user" and isinstance(m["content"], list)
        for b in m["content"]
    ]
    assert ids == results


def test_model_claiming_success_without_passing_tests_fails(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_docker(monkeypatch, FakeRunner([FAIL]))
    transport = ScriptedTransport(
        [
            tool_use("apply_patch", {"edits": [FIX]}, 0),
            tool_use("run_tests", {"command": "unittest"}, 1),
            tool_use("finish", {"summary": "All tests pass. SUCCESS."}, 2),
        ]
    )
    r = run_task(
        TaskRequest(fixture="paginator", task="fix", provider="anthropic"),
        settings,
        provider_factory=lambda _r: provider(transport),
    )
    assert r.status == "failed"


# ---------------------------------------------------------------- budgets


def test_model_call_budget(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_docker(monkeypatch, FakeRunner())
    transport = ScriptedTransport([tool_use("list_files", {}, n) for n in range(10)])
    r = run_task(
        TaskRequest(fixture="paginator", task="x", provider="anthropic"),
        settings,
        provider_factory=lambda _r: provider(transport, max_model_calls=3),
    )
    assert r.status == "budget_exhausted"
    assert "model call budget" in r.reason
    assert len(transport.requests) == 3


def test_cost_budget_is_checked_before_the_call() -> None:
    transport = ScriptedTransport([tool_use("list_files", {}, 0)])
    p = provider(transport, max_cost_usd=0.001, max_output_tokens_per_call=1024)
    with pytest.raises(ProviderBudgetExceeded, match="cost budget"):
        p.next_action(Transcript(task="x"))
    assert transport.requests == []  # refused before any request was sent


def test_cost_accumulates_and_stops_the_run(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_docker(monkeypatch, FakeRunner())
    expensive = {
        "content": [{"type": "tool_use", "id": "toolu_x", "name": "list_files", "input": {}}],
        "usage": {"input_tokens": 20_000, "output_tokens": 1000},  # ~$0.05 per call on Sonnet 5.5
    }
    transport = ScriptedTransport(
        [dict(expensive, content=[dict(expensive["content"][0], id=f"t{i}")]) for i in range(20)]
    )
    r = run_task(
        TaskRequest(fixture="paginator", task="x", provider="anthropic"),
        settings,
        provider_factory=lambda _r: provider(transport, max_cost_usd=0.12),
    )
    assert r.status == "budget_exhausted"
    assert "cost budget" in r.reason
    assert r.model_usage is not None
    assert r.model_usage["cost_usd"] <= 0.12


def test_token_budget() -> None:
    transport = ScriptedTransport([tool_use("list_files", {}, 0)] * 3)
    p = provider(transport, max_total_tokens=5_000)
    p.next_action(Transcript(task="x"))  # ~3.5k tokens used of 5k
    with pytest.raises(ProviderBudgetExceeded, match="token budget"):
        p.next_action(Transcript(task="x"))


def test_missing_usage_is_charged_at_worst_case() -> None:
    no_usage = {"content": [{"type": "tool_use", "id": "t", "name": "list_files", "input": {}}]}
    p = provider(ScriptedTransport([no_usage]))
    p.next_action(Transcript(task="x"))
    assert p.usage.cost_usd > 0


def test_pricing_matches_published_table() -> None:
    p = provider(ScriptedTransport([]))
    p._record({"usage": {"input_tokens": 1_000_000, "output_tokens": 1_000_000}}, 1)
    assert p.usage.cost_usd == pytest.approx(2.0 + 10.0)  # Sonnet 5.5: $2 / $10 per MTok


# ---------------------------------------------------------------- errors


def _http_error(code: int, body: dict[str, Any]) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        anth.API_URL, code, "err", http.client.HTTPMessage(), io.BytesIO(json.dumps(body).encode())
    )


@pytest.mark.parametrize(
    ("exc", "expected"),
    [
        (
            _http_error(
                401, {"error": {"type": "authentication_error", "message": f"bad key {KEY}"}}
            ),
            "HTTP 401 (authentication_error)",
        ),
        (_http_error(529, {"error": {"type": "overloaded_error"}}), "HTTP 529 (overloaded_error)"),
        (_http_error(400, {"error": {"type": "weird type!", "message": KEY}}), "HTTP 400"),
        (http.client.RemoteDisconnected(f"closed {KEY}"), "RemoteDisconnected"),
        (ConnectionResetError(f"reset {KEY}"), "ConnectionResetError"),
        (TimeoutError("timed out"), "TimeoutError"),
    ],
)
def test_transport_errors_are_mapped_without_leaking(
    monkeypatch: pytest.MonkeyPatch, exc: Exception, expected: str
) -> None:
    def boom(*_a: Any, **_k: Any) -> Any:
        raise exc

    monkeypatch.setattr(anth.urllib.request, "urlopen", boom)
    with pytest.raises(ProviderError) as info:
        anth._urllib_transport({"x": 1}, {"x-api-key": KEY}, 5.0)
    assert expected in str(info.value)
    assert KEY not in str(info.value)
    assert "STUB-KEY" not in str(info.value)


def test_provider_errors_end_run_without_leaking(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_docker(monkeypatch, FakeRunner())
    transport = ScriptedTransport([ProviderError("anthropic API HTTP 529 (overloaded_error)")] * 5)
    r = run_task(
        TaskRequest(fixture="paginator", task="x", provider="anthropic"),
        settings,
        provider_factory=lambda _r: provider(transport),
    )
    assert r.status == "provider_error"
    assert KEY not in r.model_dump_json()
    assert r.model_usage is not None
    assert r.model_usage["calls"] == 3  # max_invalid_outputs=2 -> third failure ends the run


@pytest.mark.parametrize(
    "response",
    [
        {"content": [{"type": "text", "text": "I'll just run bash"}], "stop_reason": "end_turn"},
        {"content": [{"type": "tool_use", "id": "t", "name": "bash", "input": {"cmd": "id"}}]},
        {
            "content": [
                {"type": "tool_use", "id": "t", "name": "run_tests", "input": {"command": "sh"}}
            ]
        },
        {"content": [{"type": "tool_use", "id": "t", "name": "read_file", "input": "nope"}]},
        {"content": [], "stop_reason": "max_tokens"},
        {"unexpected": True},
    ],
    ids=["text_only", "unknown_tool", "forbidden_command", "bad_args", "truncated", "garbage"],
)
def test_malformed_or_hostile_model_output_fails_closed(
    settings: Settings, monkeypatch: pytest.MonkeyPatch, response: dict[str, Any]
) -> None:
    runner = FakeRunner()
    _stub_docker(monkeypatch, runner)
    transport = ScriptedTransport([response] * 6)
    r = run_task(
        TaskRequest(fixture="paginator", task="x", provider="anthropic"),
        settings,
        provider_factory=lambda _r: provider(transport),
    )
    assert r.status in {"provider_error", "policy_aborted"}
    assert runner.calls == []  # nothing ran in the sandbox
    assert r.diff == ""


@pytest.mark.docker
def test_stubbed_model_through_real_sandbox(settings: Settings, fixtures_dir: Path) -> None:
    from sandbox_agent.workspace import tree_manifest  # noqa: PLC0415

    before = tree_manifest(fixtures_dir / "paginator")
    transport = ScriptedTransport(fix_responses())
    r = run_task(
        TaskRequest(fixture="paginator", task="fix it", provider="anthropic"),
        settings,
        provider_factory=lambda _r: provider(transport),
    )
    assert r.status == "succeeded", r.reason
    assert r.final_tests.passed is True
    assert r.final_tests.tests_run == 6
    runs = [e for e in r.trace if e["event"] == "tool_end" and e["tool"] == "run_tests"]
    assert all(e["resources"]["attested"] for e in runs)
    assert r.fixture_unchanged
    assert tree_manifest(fixtures_dir / "paginator") == before
    # The observation the model received for the failing run carried the real unittest tail.
    second_request = transport.requests[1][0]["messages"][-1]["content"][0]["content"]
    assert "FAILED (failures=2)" in second_request
