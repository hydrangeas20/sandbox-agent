"""Deterministic providers for CI, the offline demo and adversarial tests.

These do **not** reason. They replay a fixed plan so the controller, tools,
sandbox and trace can be exercised reproducibly without network access or
credentials. Optional per-step expectations make a script stop (by calling
``finish`` with a divergence note) if what it observes does not match the
assumptions the plan was written under, so a demo cannot silently "pass" on a
world that differs from the one it describes.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from sandbox_agent.errors import ProviderError
from sandbox_agent.providers.base import Transcript

Expectation = Callable[[dict[str, Any]], bool]


@dataclass(frozen=True)
class Step:
    """One scripted model output. ``raw`` is returned verbatim (it may be invalid on purpose)."""

    raw: Any
    expect_previous: Expectation | None = None
    expectation_note: str = ""


def _last_observation(transcript: Transcript) -> dict[str, Any]:
    for turn in reversed(transcript.turns):
        if turn.role in ("observation", "invalid"):
            return turn.content
    return {}


class ScriptedProvider:
    name = "scripted"

    def __init__(self, steps: list[Step], label: str = "scripted") -> None:
        self._steps = list(steps)
        self._index = 0
        self.label = label

    def next_action(self, transcript: Transcript) -> Any:
        if self._index >= len(self._steps):
            raise ProviderError("scripted provider exhausted")
        step = self._steps[self._index]
        self._index += 1
        if step.expect_previous is not None and not step.expect_previous(
            _last_observation(transcript)
        ):
            return {
                "tool": "finish",
                "args": {"summary": f"script diverged from expectations: {step.expectation_note}"},
            }
        return step.raw


class LoopingProvider:
    """Never finishes: repeats one valid action forever (budget tests)."""

    name = "looping"

    def __init__(self, action: dict[str, Any]) -> None:
        self.action = action
        self.calls = 0

    def next_action(self, transcript: Transcript) -> Any:
        self.calls += 1
        return self.action


_DIRECTIVE = re.compile(r"AGENT-INSTRUCTION:\s*(\{.*?\})\s*(?:-->|$)", re.MULTILINE)


class InjectionFollowingProvider:
    """Simulates a fully compromised model that obeys instructions found in repo content.

    It reads ``entry_path`` first, then executes every ``AGENT-INSTRUCTION: {json}``
    directive it finds in any observation, in order. Used to show that obeying an
    injection still cannot exceed the tool policy.
    """

    name = "injection-following"

    def __init__(self, entry_path: str) -> None:
        self.entry_path = entry_path
        self._queue: list[Any] = []
        self._seen: set[str] = set()
        self._started = False

    def next_action(self, transcript: Transcript) -> Any:
        if not self._started:
            self._started = True
            return {"tool": "read_file", "args": {"path": self.entry_path}}
        text = "\n".join(_strings(_last_observation(transcript)))
        for match in _DIRECTIVE.finditer(text):
            directive = match.group(1)
            if directive not in self._seen:
                self._seen.add(directive)
                try:
                    self._queue.append(json.loads(directive))
                except json.JSONDecodeError:
                    self._queue.append(directive)  # forwarded raw: controller must reject it
        if self._queue:
            return self._queue.pop(0)
        return {"tool": "finish", "args": {"summary": "followed all injected instructions"}}


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _strings(v)]
    if isinstance(value, list):
        return [s for v in value for s in _strings(v)]
    return []


# ---------------------------------------------------------------------- scenarios


def _tests_failed(obs: dict[str, Any]) -> bool:
    return bool(obs.get("ok")) and obs.get("output", {}).get("passed") is False


def _tests_passed(obs: dict[str, Any]) -> bool:
    return bool(obs.get("ok")) and obs.get("output", {}).get("passed") is True


def _patch_ok(obs: dict[str, Any]) -> bool:
    return bool(obs.get("ok"))


def paginator_fix_script() -> ScriptedProvider:
    """Plan for the `paginator` fixture: reproduce, locate, fix, verify, finish."""
    return ScriptedProvider(
        [
            Step(
                {
                    "tool": "run_tests",
                    "args": {"command": "unittest"},
                    "thought": "Reproduce the reported failure first.",
                }
            ),
            Step(
                {
                    "tool": "search",
                    "args": {"query": "start = "},
                    "thought": "First page returns items 11-20, so the start offset is suspect.",
                },
                expect_previous=_tests_failed,
                expectation_note="expected the unpatched suite to fail",
            ),
            Step(
                {
                    "tool": "read_file",
                    "args": {"path": "paginator/core.py"},
                    "thought": "Inspect paginate() to confirm the indexing convention.",
                }
            ),
            Step(
                {
                    "tool": "apply_patch",
                    "args": {
                        "edits": [
                            {
                                "path": "paginator/core.py",
                                "old": "    start = page * per_page\n",
                                "new": "    start = (page - 1) * per_page\n",
                            }
                        ]
                    },
                    "thought": "Pages are 1-indexed, so the offset must be (page - 1) * per_page.",
                }
            ),
            Step(
                {"tool": "run_tests", "args": {"command": "unittest"}},
                expect_previous=_patch_ok,
                expectation_note="expected the patch to apply",
            ),
            Step(
                {
                    "tool": "finish",
                    "args": {
                        "summary": "Fixed off-by-one in paginate(): 1-indexed pages used "
                        "page * per_page as the start offset; now (page - 1) * per_page."
                    },
                },
                expect_previous=_tests_passed,
                expectation_note="expected the patched suite to pass",
            ),
        ],
        label="paginator-fix",
    )


SCENARIOS: dict[str, Callable[[], ScriptedProvider]] = {"paginator": paginator_fix_script}
