"""Static security checks for the paid live-smoke workflow, and its helper scripts.

These never contact any API. The fake credential below is not a real key.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "live-smoke.yml"
FAKE = "sk-ant-api03-FAKE-for-tests-only-0123456789abcdefghij"


@pytest.fixture(scope="module")
def wf() -> dict[str, Any]:
    data: dict[str, Any] = yaml.safe_load(WORKFLOW.read_text())
    return data


@pytest.fixture(scope="module")
def job(wf: dict[str, Any]) -> dict[str, Any]:
    jobs = wf["jobs"]
    assert list(jobs) == ["smoke"]
    smoke: dict[str, Any] = jobs["smoke"]
    return smoke


def steps_by_name(job: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {s.get("name", s.get("uses", "")): s for s in job["steps"]}


def test_manual_dispatch_only(wf: dict[str, Any]) -> None:
    triggers = wf.get("on", wf.get(True))  # PyYAML parses the bare key `on` as True
    assert set(triggers) == {"workflow_dispatch"}
    text = WORKFLOW.read_text()
    for forbidden in ("pull_request", "pull_request_target", "schedule:", "push:", "workflow_run"):
        assert forbidden not in text.split("jobs:")[0], forbidden


def test_least_privilege_and_serialised(wf: dict[str, Any], job: dict[str, Any]) -> None:
    assert wf["permissions"] == {"contents": "read"}
    assert "permissions" not in job
    assert wf["concurrency"] == {"group": "sandbox-agent-eval", "cancel-in-progress": False}
    assert job["timeout-minutes"] <= 30


def test_environment_and_main_pinning(job: dict[str, Any]) -> None:
    assert job["environment"] == "sandbox-agent-eval"
    condition = job["if"]
    for clause in (
        "github.event_name == 'workflow_dispatch'",
        "github.repository == 'hydrangeas20/sandbox-agent'",
        "github.ref == 'refs/heads/main'",
        "inputs.expected_sha == github.sha",
        "inputs.confirm == 'RUN-PAID-HAIKU-SMOKE'",
    ):
        assert clause in condition
    checkout = next(
        s for s in job["steps"] if str(s.get("uses", "")).startswith("actions/checkout@")
    )
    assert checkout["with"] == {"ref": "${{ github.sha }}", "persist-credentials": False}


def test_actions_pinned_to_full_commit_shas(job: dict[str, Any]) -> None:
    uses = [s["uses"] for s in job["steps"] if "uses" in s]
    assert uses
    for ref in uses:
        assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", ref), ref


def test_secret_reaches_only_three_steps(wf: dict[str, Any], job: dict[str, Any]) -> None:
    assert "secrets." not in json.dumps(wf.get("env", {}))
    assert "secrets." not in json.dumps(job.get("env", {}))
    with_secret = [s["name"] for s in job["steps"] if "secrets.ANTHROPIC_API_KEY" in json.dumps(s)]
    assert with_secret == [
        "Require the API key secret",
        "Paid smoke test (secret available to the controller only)",
        "Scan artifacts for the credential",
    ]
    steps = steps_by_name(job)
    for name in with_secret:
        assert steps[name]["env"]["ANTHROPIC_API_KEY"] == "${{ secrets.ANTHROPIC_API_KEY }}"
    # Steps that build or run untrusted code before the paid step never see it.
    for name in ("Build sandbox image (no secrets)", "Sandbox isolation checks (no secrets)",
                 "Offline checks (no secrets)", "Install (no secrets)"):  # fmt: skip
        assert "secrets." not in json.dumps(steps[name])


def test_secret_is_never_echoed(job: dict[str, Any]) -> None:
    for step in job["steps"]:
        script = step.get("run", "")
        assert "echo $ANTHROPIC_API_KEY" not in script
        assert '"$ANTHROPIC_API_KEY"' not in script
        assert "set -x" not in script
        assert "printenv" not in script
        assert "env |" not in script


def test_refuses_without_secret(job: dict[str, Any]) -> None:
    step = steps_by_name(job)["Require the API key secret"]
    assert 'if [ -z "${ANTHROPIC_API_KEY:-}" ]' in step["run"]
    assert "exit 1" in step["run"]
    names = [s.get("name", s.get("uses")) for s in job["steps"]]
    assert names.index("Require the API key secret") < names.index(
        "Paid smoke test (secret available to the controller only)"
    )


def test_exactly_one_haiku_paginator_run_with_caps(job: dict[str, Any]) -> None:
    run = steps_by_name(job)["Paid smoke test (secret available to the controller only)"]["run"]
    assert run.count("sandbox-agent run") == 1
    assert "sandbox-agent eval" not in run
    for flag in (
        "--provider anthropic",
        "--model claude-haiku-5-5",
        "--fixture paginator",
        "--max-cost-usd 0.50",
        "--experiment-budget-usd 0.50",
        "--ledger runs/spend-ledger.json",
    ):
        assert flag in run, flag
    text = WORKFLOW.read_text()
    assert not re.search(r"claude-(sonnet|opus|fable|mythos)", text)


def test_upload_only_after_clean_scan(job: dict[str, Any]) -> None:
    steps = steps_by_name(job)
    upload = next(
        s for s in job["steps"] if str(s.get("uses", "")).startswith("actions/upload-artifact@")
    )
    assert "steps.leakcheck.outcome == 'success'" in upload["if"]
    assert upload["with"]["path"] == "runs/"
    assert steps["Scan artifacts for the credential"]["id"] == "leakcheck"


# ---------------------------------------------------------------- helper scripts


def run_script(name: str, *args: str, key: str | None) -> subprocess.CompletedProcess[str]:
    env = {k: v for k, v in os.environ.items() if k != "ANTHROPIC_API_KEY"}
    if key is not None:
        env["ANTHROPIC_API_KEY"] = key
    return subprocess.run(
        [sys.executable, str(ROOT / "scripts" / name), *args],
        capture_output=True, text=True, env=env, check=False,
    )  # fmt: skip


def test_leak_check_clean(tmp_path: Path) -> None:
    (tmp_path / "trace.jsonl").write_text('{"event": "model_call", "x-api-key": "[REDACTED]"}\n')
    r = run_script("check_artifacts_for_secret.py", str(tmp_path), key=FAKE)
    assert r.returncode == 0, r.stdout + r.stderr
    assert FAKE not in r.stdout + r.stderr


@pytest.mark.parametrize(
    "content",
    [
        FAKE,
        __import__("base64").b64encode(FAKE.encode()).decode(),
        FAKE.encode().hex(),
        "sk-ant-api03-SOME-OTHER-KEY-SHAPED-STRING-000000",
    ],
    ids=["raw", "base64", "hex", "other_key_shape"],
)
def test_leak_check_blocks_and_does_not_print_secret(tmp_path: Path, content: str) -> None:
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested" / "result.json").write_text(json.dumps({"oops": content}))
    r = run_script("check_artifacts_for_secret.py", str(tmp_path), key=FAKE)
    assert r.returncode == 1
    assert "::error" in r.stdout
    assert FAKE not in r.stdout + r.stderr
    assert content not in r.stdout + r.stderr


def test_leak_check_requires_key(tmp_path: Path) -> None:
    assert run_script("check_artifacts_for_secret.py", str(tmp_path), key=None).returncode == 2


def test_summary_renders_result_and_ledger(tmp_path: Path) -> None:
    result = {
        "status": "succeeded", "reason": "ok", "final_tests": {"passed": True},
        "files_changed": ["paginator/core.py"], "fixture_unchanged": True, "duration_ms": 9000,
        "agent": {"tool_calls": 5, "policy_denials": 0, "invalid_outputs": 0},
        "model_usage": {"model": "claude-haiku-5-5", "calls": 6, "input_tokens": 30000,
                        "output_tokens": 900, "cache_creation_input_tokens": 0,
                        "cache_read_input_tokens": 0, "cost_usd": 0.00345},
        "trace": [{"event": "model_call", "failed": True, "error": "anthropic API HTTP 529"}],
    }  # fmt: skip
    ledger = {
        "experiment_budget_usd": 0.5,
        "entries": [
            {"state": "settled", "actual_usd": 0.003},
            {"state": "reserved", "reserved_usd": 0.001},
        ],
    }
    (tmp_path / "r.json").write_text(json.dumps(result))
    (tmp_path / "l.json").write_text(json.dumps(ledger))
    r = run_script("smoke_summary.py", str(tmp_path / "r.json"), str(tmp_path / "l.json"), key=None)
    assert r.returncode == 0
    for text in ("`succeeded`", "claude-haiku-5-5", "| API calls | 6 |", "30000 / 900", "0.00345",
                 "HTTP 529", "1 unsettled", "does not persist across runners"):  # fmt: skip
        assert text in r.stdout, text


def test_summary_tolerates_missing_or_empty_result(tmp_path: Path) -> None:
    (tmp_path / "empty.json").write_text("")
    for path in ("missing.json", "empty.json"):
        r = run_script("smoke_summary.py", str(tmp_path / path), key=None)
        assert r.returncode == 0
        assert "No valid result" in r.stdout
