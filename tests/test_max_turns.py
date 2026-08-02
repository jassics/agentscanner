"""AS-AGENT-005 — agent has no effective maxTurns bound.

There is no platform default cap: an agent with no `maxTurns` (or an invalid
one) runs unbounded turns. Missing -> LOW; present-but-broken -> MEDIUM
(worse than missing, since it looks safe but doesn't actually bound anything).
"""
from __future__ import annotations

from pathlib import Path

from agentscanner.checks.agents_skills import AgentUnboundedTurns
from agentscanner.models import ArtifactType, Scope, Severity
from agentscanner.parsers.markdown_parser import parse_markdown


def _agent(tmp_path: Path, extra_frontmatter: str) -> Path:
    p = tmp_path / "agent.md"
    p.write_text(
        f"---\nname: test-agent\ndescription: fixture\n{extra_frontmatter}---\n\nBody.\n"
    )
    return parse_markdown(p, Scope.PROJECT, ArtifactType.AGENT)


def test_missing_max_turns_fires_low(tmp_path):
    resource = _agent(tmp_path, "")
    findings = list(AgentUnboundedTurns().analyze(resource))
    assert len(findings) == 1
    assert findings[0].severity == Severity.LOW


def test_valid_max_turns_is_clean(tmp_path):
    resource = _agent(tmp_path, "maxTurns: 30\n")
    findings = list(AgentUnboundedTurns().analyze(resource))
    assert not findings


def test_zero_max_turns_fires_medium(tmp_path):
    resource = _agent(tmp_path, "maxTurns: 0\n")
    findings = list(AgentUnboundedTurns().analyze(resource))
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


def test_negative_max_turns_fires_medium(tmp_path):
    resource = _agent(tmp_path, "maxTurns: -5\n")
    findings = list(AgentUnboundedTurns().analyze(resource))
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


def test_non_integer_max_turns_fires_medium(tmp_path):
    resource = _agent(tmp_path, 'maxTurns: "forty"\n')
    findings = list(AgentUnboundedTurns().analyze(resource))
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


def test_boolean_max_turns_fires_medium(tmp_path):
    """bool is a subclass of int in Python — must not slip through as 'valid'."""
    resource = _agent(tmp_path, "maxTurns: true\n")
    findings = list(AgentUnboundedTurns().analyze(resource))
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
