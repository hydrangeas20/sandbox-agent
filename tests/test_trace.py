"""Trace structure, redaction and persistence (AC-12)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sandbox_agent.trace import REDACTED, Tracer, load_jsonl

PLANTED = [
    "sk-ant-api03-PLANTEDsecretVALUE1234567890",
    "sk-proj4PLANTEDopenaiKEY12345678901234",
    "ghp_PLANTEDgithubTOKEN1234567890abcd",
    "AKIAPLANTED1234ABCDE",  # AKIA + 16 chars, the real AWS key-id shape
    "xoxb-PLANTED-slack-token-123",
    "Bearer PLANTEDbearerTOKENvalue123456",
    "-----BEGIN RSA PRIVATE KEY-----\nPLANTEDKEYMATERIAL\n-----END RSA PRIVATE KEY-----",
]


def test_event_envelope() -> None:
    t = Tracer("cid-1")
    t.emit("a", x=1)
    t.emit("b", nested={"y": [1, 2]}, obj=Path("/x"))
    assert [e["seq"] for e in t.events] == [1, 2]
    for e in t.events:
        assert e["v"] == 1
        assert e["cid"] == "cid-1"
        assert e["ts"].endswith("+00:00")
        assert isinstance(e["t_ms"], int)
    assert t.events[1]["obj"] == "/x"


def test_envelope_fields_cannot_be_overwritten() -> None:
    t = Tracer("cid-1")
    e = t.emit("x", seq=999, cid="spoofed", v=0, ts="1970")
    assert e["seq"] == 1
    assert e["cid"] == "cid-1"
    assert e["v"] == 1
    assert e["ts"] != "1970"


@pytest.mark.parametrize("secret", PLANTED)
def test_pattern_redaction(secret: str) -> None:
    t = Tracer("c")
    e = t.emit("x", text=f"prefix {secret} suffix", nested={"list": [secret]})
    blob = json.dumps(e)
    assert "PLANTED" not in blob
    assert REDACTED in blob


def test_registered_secret_and_env_secret_redacted(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "custom-format-key-ZZZ999")
    t = Tracer("c")
    t.register_secrets("opaque-value-QQQ111", "short")
    e = t.emit("x", a="uses custom-format-key-ZZZ999", b="and opaque-value-QQQ111", c="short")
    assert "ZZZ999" not in json.dumps(e)
    assert "QQQ111" not in json.dumps(e)
    assert e["c"] == "short"  # too short to be registered; avoids redacting ordinary words


def test_assignment_and_key_redaction() -> None:
    t = Tracer("c")
    e = t.emit(
        "x",
        text="password = hunter2hunter2 and api_key: abcdef123456",
        headers={"x-api-key": "anything", "Authorization": "Basic Zm9vOmJhcg==", "accept": "json"},
    )
    assert "hunter2hunter2" not in e["text"]
    assert "abcdef123456" not in e["text"]
    assert "password = [REDACTED]" in e["text"]
    assert e["headers"]["x-api-key"] == REDACTED
    assert e["headers"]["Authorization"] == REDACTED
    assert e["headers"]["accept"] == "json"


def test_jsonl_roundtrip(tmp_path: Path) -> None:
    t = Tracer("c")
    for i in range(5):
        t.emit("e", i=i)
    path = t.write_jsonl(tmp_path / "t.jsonl")
    events = load_jsonl(path)
    assert [e["i"] for e in events] == list(range(5))
    assert all(e["cid"] == "c" for e in events)
