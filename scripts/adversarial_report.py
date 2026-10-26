"""Run the security suites and write docs/ADVERSARIAL_REPORT.md from the JUnit results.

Usage: uv run python scripts/adversarial_report.py

Results are taken verbatim from pytest's JUnit XML; skipped tests are reported
as SKIPPED (never as passes).
"""

from __future__ import annotations

import datetime as dt
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SUITES = [
    "tests/test_adversarial.py",
    "tests/test_sandbox_docker.py",
    "tests/test_sandbox_args.py",
    "tests/test_workspace.py",
    "tests/test_workspace_docker.py",
    "tests/test_patch.py",
    "tests/test_tools.py",
    "tests/test_trace.py",
    "tests/test_security_review.py",
    "tests/test_security_review_docker.py",
    "tests/test_reliability.py",
    "tests/test_real_model_path.py",
]
THREATS = {
    "test_injection_following_provider_is_contained": "T1 T2 T3 T4",
    "test_default_budget_aborts_injection_quickly": "T1 T12",
    "test_hostile_test_code_is_contained": "T6 T7 T9 T11",
    "test_resource_infinite_loop_times_out": "T8",
    "test_resource_memory_exhaustion_oom_killed": "T8",
    "test_resource_fork_bomb_limited": "T8",
    "test_resource_output_flood_truncated": "T8",
    "test_traversal_and_symlink_escapes_via_pipeline": "T3 T4",
    "test_search_never_follows_symlinks": "T4",
    "test_forbidden_commands_via_pipeline": "T2",
    "test_agent_loop_is_bounded": "T12",
    "test_invalid_provider_outputs_via_pipeline": "T13",
    "test_malformed_patches_leave_workspace_unchanged": "T13",
}


def _docker_version() -> str:
    docker = shutil.which("docker")
    if not docker:
        return "unavailable"
    out = subprocess.run(
        [docker, "version", "--format", "{{.Server.Version}}"],
        capture_output=True,
        text=True,
        check=False,
    )
    return out.stdout.strip() or "unavailable"


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        junit = Path(tmp) / "junit.xml"
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", f"--junitxml={junit}", *SUITES],
            cwd=ROOT,
            check=False,
        )
        tree = ET.parse(junit)  # noqa: S314 - trusted local file
    rows: list[tuple[str, str, str]] = []
    counts = {"PASS": 0, "FAIL": 0, "SKIPPED": 0}
    adversarial: list[tuple[str, str, str]] = []
    review: list[tuple[str, str, str]] = []
    for case in tree.iter("testcase"):
        name = case.get("name", "")
        module = case.get("classname", "").rsplit(".", 1)[-1]
        if case.find("failure") is not None or case.find("error") is not None:
            status = "FAIL"
        elif case.find("skipped") is not None:
            status = "SKIPPED"
        else:
            status = "PASS"
        counts[status] += 1
        rows.append((module, name, status))
        base = name.split("[", 1)[0]
        if module == "test_adversarial":
            adversarial.append((THREATS.get(base, "-"), name, status))
        elif module.startswith("test_security_review"):
            finding = (
                base.split("_")[1].upper().replace("SR", "SR-")
                if base.startswith("test_sr")
                else "-"
            )
            review.append((finding, name, status))

    by_module: dict[str, dict[str, int]] = {}
    for module, _, status in rows:
        by_module.setdefault(module, {"PASS": 0, "FAIL": 0, "SKIPPED": 0})[status] += 1

    lines = [
        "# Adversarial Evaluation Report",
        "",
        f"Generated {dt.datetime.now(dt.UTC):%Y-%m-%d %H:%M UTC} by "
        "`scripts/adversarial_report.py` from pytest JUnit output. Docker server "
        f"{_docker_version()}. Skipped tests are listed as SKIPPED, never as passes.",
        "",
        f"**Totals:** {counts['PASS']} pass, {counts['FAIL']} fail, {counts['SKIPPED']} skipped.",
        "",
        "## Adversarial scenarios (`tests/test_adversarial.py`)",
        "",
        "| Threat | Test | Result |",
        "|---|---|---|",
        *[f"| {t} | `{n}` | {s} |" for t, n, s in adversarial],
        "",
        "## Security-review regressions (`tests/test_security_review*.py`)",
        "",
        "Finding IDs refer to `docs/SECURITY_REVIEW.md`. Before/after evidence for each is in",
        "`docs/security-review/REGRESSION_EVIDENCE.md`.",
        "",
        "| Finding | Test | Result |",
        "|---|---|---|",
        *[f"| {t} | `{n}` | {s} |" for t, n, s in sorted(review)],
        "",
        "## Security-relevant suites",
        "",
        "| Module | Pass | Fail | Skipped |",
        "|---|---|---|---|",
        *[
            f"| `{m}` | {c['PASS']} | {c['FAIL']} | {c['SKIPPED']} |"
            for m, c in sorted(by_module.items())
        ],
        "",
    ]
    (ROOT / "docs" / "ADVERSARIAL_REPORT.md").write_text("\n".join(lines))
    print("\n".join(lines))
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(main())
