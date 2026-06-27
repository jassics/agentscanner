"""Paired fixture tests: BAD configs must fire specific checks; GOOD must be clean."""
from __future__ import annotations

from pathlib import Path

import pytest

from agentscan.discovery import discover
from agentscan.engine import run_checks
from agentscan.models import ArtifactType, Severity
from agentscan.parsers.json_parser import parse_json
from agentscan.models import Scope

FIXTURES = Path(__file__).parent / "fixtures"
REPO = Path(__file__).parent.parent


def ids_for(repo_root: Path):
    resources = discover(repo_root=repo_root)
    findings = run_checks(resources)
    return {f.check_id for f in findings}, findings


@pytest.mark.parametrize(
    "expected",
    [
        "AS-PERM-001",  # bypassPermissions
        "AS-PERM-002",  # Bash(*)
        "AS-PERM-003",  # Bash(curl:*)
        "AS-ENV-001",   # base url + auth token
        "AS-SECRET-001",  # AKIA key in env
        "AS-MCP-001",   # ghp token / password in mcp env
        "AS-MCP-002",   # http:// mcp
        "AS-MCP-003",   # enableAllProjectMcpServers
        "AS-MCP-004",   # unpinned npx package
        "AS-HOOK-001",  # curl | bash
        "AS-HOOK-002",  # bash /tmp/setup.sh (untrusted path)
        "AS-HOOK-003",  # SessionStart network
        "AS-HOOK-004",  # missing timeout on PreToolUse hook
        "AS-AGENT-001",  # rogue agent bypass + tools *
        "AS-PROMPT-001",  # injection text in agent + CLAUDE.md
        # OWASP Agentic Skills Top 10 (AS-SKILL-*)
        "AS-SKILL-001",  # identity-file write (SOUL.md / MEMORY.md)
        "AS-SKILL-002",  # social-engineering Prerequisites + curl|bash
        "AS-SKILL-003",  # Universal-Format skill missing signature
        "AS-SKILL-004",  # permissions.network: true boolean
        "AS-SKILL-005",  # permissions.shell: true
        "AS-SKILL-006",  # risk_tier: L0 contradicts shell: true
        "AS-SKILL-007",  # !!python/object YAML exec tag in body
        "AS-SKILL-008",  # sandboxed_execution: false
        "AS-SKILL-009",  # Universal-Format skill missing version
        "AS-SKILL-010",  # standalone base64 line in prose
        "AS-SKILL-011",  # Universal-Format skill missing publisher
        "AS-SKILL-012",  # multi-platform skill missing signature
    ],
)
def test_bad_fixture_triggers(expected):
    ids, _ = ids_for(FIXTURES / "bad")
    assert expected in ids, f"expected {expected}, got {sorted(ids)}"


def test_every_registered_check_has_coverage():
    """Guard: every check must fire on the bad fixtures — a rule that never
    triggers could be silently broken (false negatives on every clean scan)."""
    from agentscan.checks import CHECK_REGISTRY

    ids, _ = ids_for(FIXTURES / "bad")
    registered = set(CHECK_REGISTRY)
    uncovered = registered - ids
    assert not uncovered, f"checks with no firing fixture: {sorted(uncovered)}"


def test_good_fixture_is_clean():
    ids, findings = ids_for(FIXTURES / "good")
    assert not findings, f"good fixture should be clean, got: {[f.to_dict() for f in findings]}"


def test_hardened_reference_is_clean():
    res = parse_json(REPO / "hardened" / "settings.json", Scope.PROJECT, ArtifactType.SETTINGS)
    findings = run_checks([res])
    assert not findings, f"hardened settings should be clean, got: {[f.to_dict() for f in findings]}"


def test_scanner_never_executes():
    """Smoke test of the core invariant: parsing malicious config returns data only."""
    res = parse_json(
        FIXTURES / "bad" / ".claude" / "settings.json", Scope.PROJECT, ArtifactType.SETTINGS
    )
    assert isinstance(res.data, dict)
    # the curl|bash hook command is present as a STRING, never executed
    cmd = res.data["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    assert "curl" in cmd


def test_severity_threshold_filters():
    resources = discover(repo_root=FIXTURES / "bad")
    findings = run_checks(resources)
    crit = [f for f in findings if f.severity >= Severity.CRITICAL]
    assert all(f.severity == Severity.CRITICAL for f in crit)
    assert any(f.check_id == "AS-HOOK-001" for f in crit)
