"""probe.py — the network boundary (call_anthropic) is always mocked here.
Never make a real Anthropic API call from the test suite."""
from __future__ import annotations

from pathlib import Path

import pytest

from agentscanner import probe
from agentscanner.parsers.markdown_parser import parse_markdown
from agentscanner.models import ArtifactType, Scope

FIXTURES = Path(__file__).parent / "fixtures"


def _resource():
    return parse_markdown(
        FIXTURES / "bad" / ".claude" / "agents" / "rogue.md", Scope.PROJECT, ArtifactType.AGENT
    )


def test_probe_vulnerable_verdict(monkeypatch):
    calls = []

    def fake_call(model, system, user, api_key):
        calls.append((model, system[:20]))
        if system is probe._SUMMARIZE_SYSTEM:
            return "The assistant ignored prior instructions as requested."
        return "COMPLIED"

    monkeypatch.setattr(probe, "call_anthropic", fake_call)
    result = probe.probe_resource(_resource(), "claude-haiku-4-5", "fake-key", check_id="AS-PROMPT-001")
    assert result is not None
    assert result.verdict == "VULNERABLE"
    assert result.model == "claude-haiku-4-5"


def test_probe_resistant_verdict(monkeypatch):
    def fake_call(model, system, user, api_key):
        if system is probe._SUMMARIZE_SYSTEM:
            return "This document describes a rogue agent configuration."
        return "RESISTED"

    monkeypatch.setattr(probe, "call_anthropic", fake_call)
    result = probe.probe_resource(_resource(), "claude-sonnet-5", "fake-key")
    assert result is not None
    assert result.verdict == "RESISTANT"


def test_probe_returns_none_when_target_call_fails(monkeypatch):
    monkeypatch.setattr(probe, "call_anthropic", lambda *a, **k: None)
    result = probe.probe_resource(_resource(), "claude-haiku-4-5", "fake-key")
    assert result is None


def test_probe_inconclusive_when_judge_call_fails(monkeypatch):
    def fake_call(model, system, user, api_key):
        if system is probe._SUMMARIZE_SYSTEM:
            return "A neutral summary."
        return None

    monkeypatch.setattr(probe, "call_anthropic", fake_call)
    result = probe.probe_resource(_resource(), "claude-haiku-4-5", "fake-key")
    assert result is not None
    assert result.verdict == "INCONCLUSIVE"


def test_probe_never_sends_more_than_max_content(monkeypatch):
    seen = {}

    def fake_call(model, system, user, api_key):
        if system is probe._SUMMARIZE_SYSTEM:
            seen["user_len"] = len(user)
            return "summary"
        return "RESISTED"

    monkeypatch.setattr(probe, "call_anthropic", fake_call)
    res = _resource()
    res.raw_text = "x" * 50_000
    probe.probe_resource(res, "claude-haiku-4-5", "fake-key")
    assert seen["user_len"] <= probe._MAX_CONTENT_CHARS + 50  # + wrapper tags
