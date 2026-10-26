"""Structured execution traces.

Every event is a flat JSON object with:

* ``v`` (schema version), ``cid`` (correlation ID = task ID), ``seq`` (monotonic,
  gap-free), ``ts`` (UTC ISO-8601), ``t_ms`` (ms since the tracer started),
  ``event`` (type);
* event-specific fields (see ``docs/SPEC.md`` §8).

Redaction happens **at emit time**, so secrets never sit in memory inside the
event list, on disk, or in API responses:

* exact values registered with :meth:`Tracer.register_secrets` (provider keys)
  plus the values of well-known credential environment variables;
* common credential patterns (Anthropic/OpenAI/GitHub/Slack/AWS keys, bearer
  tokens, PEM private keys, ``password=...``-style assignments);
* any dict key that names a credential (``authorization``, ``x-api-key``, ...).
"""

from __future__ import annotations

import json
import os
import re
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
REDACTED = "[REDACTED]"

_SECRET_ENV_VARS = (
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "HF_TOKEN",
)

_PATTERNS = [
    re.compile(r"sk-ant-[A-Za-z0-9_\-]{8,}"),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"xox[abposr]-[A-Za-z0-9-]{10,}"),
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{16,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)\b(api[_-]?key|secret|token|passw(?:or)?d)(\s*[=:]\s*)['\"]?[^\s'\",}]{6,}"),
]
_SENSITIVE_KEYS = re.compile(
    r"(?i)^(authorization|x-api-key|api[_-]?key|password|secret|token|cookie)$"
)


class Tracer:
    def __init__(self, correlation_id: str, clock: Any = time.monotonic) -> None:
        self.correlation_id = correlation_id
        self.events: list[dict[str, Any]] = []
        self._seq = 0
        self._clock = clock
        self._t0 = clock()
        self._secrets: set[str] = set()
        self.register_secrets(*(os.environ.get(k, "") for k in _SECRET_ENV_VARS))

    def register_secrets(self, *values: str) -> None:
        # Very short values would redact ordinary words; real credentials are long.
        self._secrets.update(v for v in values if v and len(v) >= 8)

    def emit(self, event: str, **fields: Any) -> dict[str, Any]:
        self._seq += 1
        record: dict[str, Any] = {
            "v": SCHEMA_VERSION,
            "cid": self.correlation_id,
            "seq": self._seq,
            "ts": datetime.now(UTC).isoformat(timespec="milliseconds"),
            "t_ms": int((self._clock() - self._t0) * 1000),
            "event": event,
        }
        for key, value in fields.items():
            if key not in record:
                record[key] = value
        clean: dict[str, Any] = self.scrub(_jsonable(record))
        self.events.append(clean)
        return clean

    def redacted_events(self) -> list[dict[str, Any]]:
        """Events are scrubbed at emit time; this re-scrubs as defence in depth."""
        return [self.scrub(e) for e in self.events]

    def scrub(self, value: Any) -> Any:
        if isinstance(value, str):
            for secret in sorted(self._secrets, key=len, reverse=True):
                value = value.replace(secret, REDACTED)
            for pattern in _PATTERNS:
                value = pattern.sub(_redact_match, value)
            return value
        if isinstance(value, dict):
            return {
                k: (REDACTED if _SENSITIVE_KEYS.match(str(k)) and v else self.scrub(v))
                for k, v in value.items()
            }
        if isinstance(value, list):
            return [self.scrub(v) for v in value]
        return value

    def write_jsonl(self, path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as fh:
            for event in self.redacted_events():
                fh.write(json.dumps(event, sort_keys=True) + "\n")
        return path


def _redact_match(match: re.Match[str]) -> str:
    # Keep the variable name for assignment-style matches so traces stay readable.
    if match.lastindex and match.lastindex >= 2:
        return f"{match.group(1)}{match.group(2)}{REDACTED}"
    return REDACTED


def _jsonable(value: Any) -> Any:
    """Coerce to JSON-native types so traces always serialize."""
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, list | tuple | set):
        return [_jsonable(v) for v in value]
    if value is None or isinstance(value, bool | int | float | str):
        return value
    return str(value)


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
