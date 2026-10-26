"""Summarise a smoke-test TaskResult (JSON) and the spend ledger for the job summary.

Usage: python scripts/smoke_summary.py runs/smoke-result.json runs/spend-ledger.json

Reads only redacted outputs; never touches credentials.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def render(result: dict, ledger: dict | None) -> str:
    usage = result.get("model_usage") or {}
    agent = result.get("agent") or {}
    lines = [
        "## Sandbox Agent live smoke test (claude-haiku-5-5)",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Status | `{result.get('status')}` |",
        f"| Reason | {str(result.get('reason', ''))[:200]} |",
        f"| Final tests passed | {(result.get('final_tests') or {}).get('passed')} |",
        f"| Files changed | {', '.join(result.get('files_changed') or []) or '(none)'} |",
        f"| Fixture unchanged | {result.get('fixture_unchanged')} |",
        f"| Model | {usage.get('model')} |",
        f"| API calls | {usage.get('calls')} |",
        f"| Input / output tokens | {usage.get('input_tokens')} / {usage.get('output_tokens')} |",
        f"| Cache write / read tokens | {usage.get('cache_creation_input_tokens')} / "
        f"{usage.get('cache_read_input_tokens')} |",
        f"| Estimated cost (USD) | {usage.get('cost_usd')} |",
        f"| Tool calls / policy denials / invalid outputs | {agent.get('tool_calls')} / "
        f"{agent.get('policy_denials')} / {agent.get('invalid_outputs')} |",
        f"| Duration (ms) | {result.get('duration_ms')} |",
    ]
    errors = [
        e for e in result.get("trace", []) if e.get("event") == "model_call" and e.get("failed")
    ]
    if errors:
        lines += ["", "Failed model requests:", *[f"- {e.get('error')}" for e in errors]]
    if ledger is not None:
        entries = ledger.get("entries", [])
        unsettled = [e for e in entries if e.get("state") == "reserved"]
        spent = sum(
            float(e.get("reserved_usd", 0))
            if e.get("state") == "reserved"
            else float(e.get("actual_usd", 0))
            for e in entries
        )
        lines += [
            "",
            f"Ledger (this run only; it does not persist across runners): {len(entries)} requests, "
            f"{len(unsettled)} unsettled, ${spent:.6f} of "
            f"${ledger.get('experiment_budget_usd')} budget.",
        ]
    lines += ["", "Estimates only; the Anthropic Console usage page is authoritative.", ""]
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    result_path = Path(argv[0])
    try:
        result = json.loads(result_path.read_text())
    except (OSError, json.JSONDecodeError):
        print(
            "## Sandbox Agent live smoke test\n\nNo valid result was produced (see the step log).\n"
        )
        return 0
    ledger_path = Path(argv[1]) if len(argv) > 1 else None
    ledger = json.loads(ledger_path.read_text()) if ledger_path and ledger_path.is_file() else None
    print(render(result, ledger))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
