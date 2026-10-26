"""Structured execution traces.

Every event is a flat JSON object with:

* ``v`` (schema version), ``cid`` (correlation ID = task ID), ``seq`` (monotonic,
  gap-free), ``ts`` (UTC ISO-8601), ``t_ms`` (ms since the tracer started),
  ``event`` (type);
* event-specific fields (see ``docs/SPEC.md`` §8).

Redaction happens **at emit time**, so secrets never sit in memory inside the
event list, on disk, or in API responses:

* exact values registered with :meth:`Tracer.register_secrets` (provider keys),
  plus their base64/base64url/hex/URL-encoded forms, plus the values of any host
  environment variable whose *name* looks like a credential;
* common credential patterns (Anthropic/OpenAI/GitHub/Slack/AWS keys, JWTs,
  bearer/basic/token auth values, URL userinfo passwords, PEM private keys,
  ``*secret*=...``-style assignments in text and JSON);
* any dict key, at any depth, whose name contains a credential word
  (``authorization``, ``api_key``, ``client_secret``, ``access_token``, ...).

Redaction is a backstop, not a guarantee: arbitrary secrets in arbitrary
encodings cannot be detected by patterns. The primary control is keeping
sensitive payloads out of traces (test stdout/stderr, file contents and
provider exception text are never traced).
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
import time
import urllib.parse
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
REDACTED = "[REDACTED]"

#: Normalised (lower-case, alphanumerics only) name fragments that mark a credential.
#: ``token(?!s)`` keeps counters such as ``max_tokens``/``input_tokens`` readable.
_CREDENTIAL_NAME = re.compile(
    r"password|passwd|secret|apikey|authorization|cookie|credential|privatekey"
    r"|accesskey|sessionid|bearer|token(?!s)"
)
# Bounded, boundary-anchored quantifiers keep every pattern linear-time on hostile input
# (an unbounded ``[\w-]*`` prefix backtracks quadratically on long word runs: SR-12b).
_NAME = (
    r"(?<![A-Za-z0-9_\-])[A-Za-z0-9_\-]{0,40}"
    r"(?:api[_-]?key|secret|token(?!s)|passw(?:or)?d|credential|private[_-]?key)"
    r"[A-Za-z0-9_\-]{0,40}"
)

_PATTERNS = [
    re.compile(r"sk-ant-[A-Za-z0-9_\-]{8,}"),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"xox[abposr]-[A-Za-z0-9-]{10,}"),
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"),  # JWT
    re.compile(
        r"-----BEGIN [A-Z ]{0,40}PRIVATE KEY-----"
        r"[\s\S]{0,16384}?"
        r"-----END [A-Z ]{0,40}PRIVATE KEY-----"
    ),
    # Authorization-style values: "Bearer x", "Basic x", "Token x".
    re.compile(r"(?i)\b(bearer|basic|token)(\s{1,8})[A-Za-z0-9._~+/=\-]{12,}"),
    # URL userinfo: scheme://user:PASSWORD@host
    re.compile(
        r"(?i)(?<![a-z0-9+.\-])([a-z][a-z0-9+.\-]{0,30}://[^/\s:@]{1,256})(:)[^/\s@]{1,256}(?=@)"
    ),
    # name=value / name: value / "name": "value" where the name contains a credential word.
    re.compile(rf"(?i)({_NAME})([\"']?\s{{0,8}}[=:]\s{{0,8}})[\"']?[^\s'\",}}]{{6,}}"),
]


def _is_credential_name(name: str) -> bool:
    return bool(_CREDENTIAL_NAME.search(re.sub(r"[^a-z0-9]", "", name.lower())))


def _encodings(value: str) -> set[str]:
    raw = value.encode()
    std = base64.b64encode(raw).decode()
    url = base64.urlsafe_b64encode(raw).decode()
    hexed = binascii.hexlify(raw).decode()
    return {
        value,
        std,
        std.rstrip("="),
        url,
        url.rstrip("="),
        hexed,
        hexed.upper(),
        urllib.parse.quote(value, safe=""),
        urllib.parse.quote_plus(value),
        json.dumps(value)[1:-1],
    }


class Tracer:
    def __init__(self, correlation_id: str, clock: Any = time.monotonic) -> None:
        self.correlation_id = correlation_id
        self.events: list[dict[str, Any]] = []
        self._seq = 0
        self._clock = clock
        self._t0 = clock()
        self._secrets: set[str] = set()
        self.register_secrets(*(v for k, v in os.environ.items() if _is_credential_name(k)))

    def register_secrets(self, *values: str) -> None:
        # Very short values would redact ordinary words; real credentials are long.
        for value in values:
            if value and len(value) >= 8:
                self._secrets.update(e for e in _encodings(value) if len(e) >= 8)

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
                k: (REDACTED if v and _is_credential_name(str(k)) else self.scrub(v))
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
