"""AS-AGENT-006 / AS-AGENT-007 — compound unattended/backgrounded + unbounded checks.

Neither fires on maxTurns alone (that's AS-AGENT-005's job) or on
permissionMode/background alone (that's AS-AGENT-001's job) -- only on the
combination, which is worse than either individually.
"""
from __future__ import annotations

from pathlib import Path

from agentscanner.checks.agents_skills import (
    AgentUnboundedTurns,
    BackgroundUnboundedAgent,
    UnattendedUnboundedAgent,
)
from agentscanner.models import ArtifactType, Scope
from agentscanner.parsers.markdown_parser import parse_markdown


def _agent(tmp_path: Path, extra_frontmatter: str) -> Path:
    p = tmp_path / "agent.md"
    p.write_text(
        f"---\nname: test-agent\ndescription: fixture\n{extra_frontmatter}---\n\nBody.\n"
    )
    return parse_markdown(p, Scope.PROJECT, ArtifactType.AGENT)


# ─── AS-AGENT-006: bypass/acceptEdits + no maxTurns ─────────────────────────


def test_bypass_with_no_max_turns_fires(tmp_path):
    resource = _agent(tmp_path, "permissionMode: bypassPermissions\n")
    findings = list(UnattendedUnboundedAgent().analyze(resource))
    assert len(findings) == 1


def test_accept_edits_with_invalid_max_turns_fires(tmp_path):
    resource = _agent(tmp_path, "permissionMode: acceptEdits\nmaxTurns: 0\n")
    findings = list(UnattendedUnboundedAgent().analyze(resource))
    assert len(findings) == 1


def test_bypass_with_valid_max_turns_does_not_fire(tmp_path):
    resource = _agent(tmp_path, "permissionMode: bypassPermissions\nmaxTurns: 30\n")
    findings = list(UnattendedUnboundedAgent().analyze(resource))
    assert not findings


def test_no_bypass_mode_does_not_fire_even_with_no_max_turns(tmp_path):
    """AS-AGENT-005's job, not AS-AGENT-006's -- no compounding factor present."""
    resource = _agent(tmp_path, "")
    findings = list(UnattendedUnboundedAgent().analyze(resource))
    assert not findings


# ─── AS-AGENT-007: background: true + no maxTurns ───────────────────────────


def test_background_with_no_max_turns_fires(tmp_path):
    resource = _agent(tmp_path, "background: true\n")
    findings = list(BackgroundUnboundedAgent().analyze(resource))
    assert len(findings) == 1


def test_background_with_valid_max_turns_does_not_fire(tmp_path):
    resource = _agent(tmp_path, "background: true\nmaxTurns: 20\n")
    findings = list(BackgroundUnboundedAgent().analyze(resource))
    assert not findings


def test_not_background_does_not_fire_even_with_no_max_turns(tmp_path):
    resource = _agent(tmp_path, "")
    findings = list(BackgroundUnboundedAgent().analyze(resource))
    assert not findings


def test_background_string_not_true_does_not_fire(tmp_path):
    """Only the boolean 'true' counts -- not a truthy-looking string."""
    resource = _agent(tmp_path, 'background: "yes"\n')
    findings = list(BackgroundUnboundedAgent().analyze(resource))
    assert not findings


# ─── sanity: AS-AGENT-005 still fires independently of the above two ───────


def test_missing_max_turns_alone_still_fires_005(tmp_path):
    resource = _agent(tmp_path, "")
    findings = list(AgentUnboundedTurns().analyze(resource))
    assert len(findings) == 1
