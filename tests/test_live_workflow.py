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
    """The paid job (the only one with environment and secret access)."""
    assert list(wf["jobs"]) == ["verify", "smoke"]
    smoke: dict[str, Any] = wf["jobs"]["smoke"]
    return smoke


@pytest.fixture(scope="module")
def verify(wf: dict[str, Any]) -> dict[str, Any]:
    v: dict[str, Any] = wf["jobs"]["verify"]
    return v


def steps_by_name(job: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {s.get("name", s.get("uses", "")): s for s in job["steps"]}


def test_manual_dispatch_only(wf: dict[str, Any]) -> None:
    triggers = wf.get("on", wf.get(True))  # PyYAML parses the bare key `on` as True
    assert set(triggers) == {"workflow_dispatch"}
    text = WORKFLOW.read_text()
    for forbidden in ("pull_request", "pull_request_target", "schedule:", "push:", "workflow_run"):
        assert forbidden not in text.split("jobs:")[0], forbidden


def test_least_privilege_and_serialised(wf: dict[str, Any]) -> None:
    assert wf["permissions"] == {"contents": "read"}
    for j in wf["jobs"].values():
        assert "permissions" not in j
        assert j["timeout-minutes"] <= 30
    assert wf["concurrency"] == {"group": "sandbox-agent-eval", "cancel-in-progress": False}


GUARDS = (
    "github.event_name == 'workflow_dispatch'",
    "github.repository == 'hydrangeas20/sandbox-agent'",
    "github.ref == 'refs/heads/main'",
    "inputs.expected_sha == github.sha",
    "inputs.confirm == 'RUN-PAID-HAIKU-SMOKE'",
)


def test_both_jobs_guarded_and_pinned_to_main(wf: dict[str, Any]) -> None:
    for name, j in wf["jobs"].items():
        for clause in GUARDS:
            assert clause in j["if"], (name, clause)
        guard = j["steps"][0]
        assert guard["name"].startswith("Guard")
        assert '[[ "$EXPECTED_SHA" == "$ACTUAL_SHA" ]]' in guard["run"]
        checkout = next(
            s for s in j["steps"] if str(s.get("uses", "")).startswith("actions/checkout@")
        )
        assert checkout["with"] == {"ref": "${{ github.sha }}", "persist-credentials": False}


def test_verify_job_has_no_secret_access(verify: dict[str, Any]) -> None:
    assert "environment" not in verify
    assert "secrets." not in json.dumps(verify)
    names = [s.get("name", s.get("uses", "")) for s in verify["steps"]]
    for required in (
        "Install",
        "Offline checks",
        "Build sandbox image",
        "Sandbox isolation checks",
    ):
        assert required in names


def test_paid_job_runs_on_a_fresh_runner_after_verify(job: dict[str, Any]) -> None:
    assert job["needs"] == "verify"
    assert job["environment"] == "sandbox-agent-eval"
    names = [s.get("name", s.get("uses", "")) for s in job["steps"]]
    assert "Offline checks" not in names  # test suites never run where the secret exists


def test_actions_pinned_to_full_commit_shas(wf: dict[str, Any]) -> None:
    uses = [s["uses"] for j in wf["jobs"].values() for s in j["steps"] if "uses" in s]
    assert uses
    for ref in uses:
        assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", ref), ref


UV_VERSION = "0.11.32"  # the release that generated uv.lock and ran local verification
# sha256 of uv-x86_64-unknown-linux-gnu.tar.gz for UV_VERSION, from the release's
# .sha256 asset and recomputed from the downloaded tarball.
UV_SHA256 = "aab924fd522efd06f1c5f3b93a243864fc453132c94b2dc49f1371b528a4b967"


def test_uv_version_and_checksum_pinned(wf: dict[str, Any]) -> None:
    """setup-uv must install one exact uv release and verify it against a pinned sha256.

    The pinned setup-uv (v5.4.2) only knows checksums up to uv 0.6.14; without an
    explicit `checksum`, a newer release would be installed unverified.
    """
    setups = [
        s for j in wf["jobs"].values() for s in j["steps"] if "/setup-uv@" in s.get("uses", "")
    ]
    assert len(setups) == 2  # one per job
    for step in setups:
        assert step["uses"] == "astral-sh/setup-uv@d4b2f3b6ecc6e67c4457f6d3e41ec42d3d0fcb86"
        assert str(step["with"]["version"]) == UV_VERSION
        assert step["with"]["checksum"] == UV_SHA256
        assert "github-token" not in step["with"]
        assert step["with"]["enable-cache"] is False


def test_environment_and_secret_scope(wf: dict[str, Any]) -> None:
    """Only the smoke job uses the protected environment; it is the only secret referenced."""
    envs = {name: j.get("environment") for name, j in wf["jobs"].items()}
    assert envs == {"verify": None, "smoke": "sandbox-agent-eval"}
    assert set(re.findall(r"secrets\.(\w+)", WORKFLOW.read_text())) == {"ANTHROPIC_API_KEY"}
    assert "secrets." not in json.dumps(wf["jobs"]["verify"])


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


def test_secret_is_never_echoed(wf: dict[str, Any]) -> None:
    for j in wf["jobs"].values():
        for step in j["steps"]:
            script = step.get("run", "")
            assert "set -x" not in script, step.get("name")
            assert "echo $ANTHROPIC_API_KEY" not in script
            assert '"$ANTHROPIC_API_KEY"' not in script
            if "secrets.ANTHROPIC_API_KEY" in json.dumps(step):
                for dump in ("printenv", "env |", "env >", "export -p", "declare -p", "set |"):
                    assert dump not in script, (step["name"], dump)


def test_refuses_without_secret(job: dict[str, Any]) -> None:
    step = steps_by_name(job)["Require the API key secret"]
    assert 'if [ -z "${ANTHROPIC_API_KEY:-}" ]' in step["run"]
    assert "exit 1" in step["run"]


def names(job: dict[str, Any]) -> list[str]:
    return [s.get("name", s.get("uses", "")) for s in job["steps"]]


def test_secret_first_used_after_all_non_secret_work(job: dict[str, Any]) -> None:
    order = names(job)
    first_secret = min(
        i for i, s in enumerate(job["steps"]) if "secrets.ANTHROPIC_API_KEY" in json.dumps(s)
    )
    assert order[first_secret] == "Require the API key secret"
    before = order[:first_secret]
    for required in (
        "Guard (no secrets)",
        "Fingerprint trusted step environment (no secrets)",
        "Install (no secrets)",
        "Build sandbox image and preflight (no secrets)",
        "Integrity gate before the secret is used (no secrets)",
    ):
        assert required in before, required
    assert before[-1] == "Integrity gate before the secret is used (no secrets)"
    fp = order.index("Fingerprint trusted step environment (no secrets)")
    assert order[fp - 1].startswith("astral-sh/setup-uv@")
    assert fp < order.index("Install (no secrets)")


def test_integrity_gate(job: dict[str, Any]) -> None:
    steps = steps_by_name(job)
    gate = steps["Integrity gate before the secret is used (no secrets)"]
    assert gate["env"]["EXPECTED_DIGEST"] == "${{ steps.envsnap.outputs.digest }}"
    for check in ("git diff --quiet HEAD --", "git rev-parse HEAD", "rm -rf .venv",
                  "UV_NO_CACHE=1 uv sync --frozen", "rm -rf runs && mkdir runs"):  # fmt: skip
        assert check in gate["run"], check
    snap = steps["Fingerprint trusted step environment (no secrets)"]
    fp = re.compile(r"digest=\$\(.*?cut -d' ' -f1\)", re.S)
    assert fp.search(snap["run"]).group(0) == fp.search(gate["run"]).group(0)  # type: ignore[union-attr]


def test_secret_steps_do_not_resync_packages(job: dict[str, Any]) -> None:
    for step in job["steps"]:
        if "secrets.ANTHROPIC_API_KEY" in json.dumps(step) and "uv run" in step.get("run", ""):
            assert "uv run --no-sync" in step["run"], step["name"]


def test_no_expression_interpolation_in_shell(wf: dict[str, Any]) -> None:
    """Values reach scripts via env, never as `${{ }}` spliced into shell text."""
    for j in wf["jobs"].values():
        for step in j["steps"]:
            assert "${{" not in step.get("run", ""), step.get("name")


def test_require_docker_only_where_the_image_exists(wf: dict[str, Any]) -> None:
    for j in wf["jobs"].values():
        assert "SANDBOX_AGENT_REQUIRE_DOCKER" not in json.dumps(j.get("env", {}))
        order = names(j)
        for i, step in enumerate(j["steps"]):
            if "SANDBOX_AGENT_REQUIRE_DOCKER" in json.dumps(step.get("env", {})):
                built = next(k for k, n in enumerate(order) if n.startswith("Build sandbox image"))
                assert i > built, step["name"]


def test_exactly_one_haiku_paginator_run_with_caps(wf: dict[str, Any], job: dict[str, Any]) -> None:
    run = steps_by_name(job)["Paid smoke test (secret available to the controller only)"]["run"]
    assert run.count("sandbox-agent run") == 1
    assert "sandbox-agent eval" not in WORKFLOW.read_text()
    for flag in (
        "--provider anthropic",
        "--model claude-haiku-5-5",
        "--fixture paginator",
        "--max-cost-usd 0.50",
        "--max-model-calls 12",
        "--experiment-budget-usd 0.50",
        "--ledger runs/spend-ledger.json",
    ):
        assert flag in run, flag
    assert not re.search(r"claude-(sonnet|opus|fable|mythos)", WORKFLOW.read_text())
    assert "--provider anthropic" not in json.dumps(wf["jobs"]["verify"])


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
