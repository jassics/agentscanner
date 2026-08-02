"""--model-tier: static severity bump for model_sensitive checks."""
from __future__ import annotations

from pathlib import Path

from agentscanner.checks import get_checks
from agentscanner.discovery import discover
from agentscanner.engine import apply_model_tier, run_checks
from agentscanner.models import Severity

FIXTURES = Path(__file__).parent / "fixtures"


def test_model_sensitive_checks_are_marked():
    sensitive = {c.id for c in get_checks() if c.model_sensitive}
    assert sensitive == {"AS-PROMPT-001", "AS-PROMPT-002", "AS-HOOK-003", "AS-SKILL-002", "AS-SKILL-010"}


def test_high_tier_is_a_noop():
    resources = discover(repo_root=FIXTURES / "bad")
    baseline = run_checks(resources)
    baseline_sev = {(f.check_id, str(f.resource.path)): f.severity for f in baseline}

    resources2 = discover(repo_root=FIXTURES / "bad")
    findings = run_checks(resources2)
    findings = apply_model_tier(findings, "high")
    for f in findings:
        assert f.severity == baseline_sev[(f.check_id, str(f.resource.path))]


def test_low_tier_bumps_only_model_sensitive_findings():
    resources = discover(repo_root=FIXTURES / "bad")
    findings = run_checks(resources)
    before = {id(f): f.severity for f in findings}

    findings = apply_model_tier(findings, "low")

    sensitive_ids = {c.id for c in get_checks() if c.model_sensitive}
    for f in findings:
        prior = before[id(f)]
        if f.check_id in sensitive_ids and prior < Severity.CRITICAL:
            assert int(f.severity) == int(prior) + 1
        else:
            assert f.severity == prior


def test_low_tier_caps_at_critical():
    resources = discover(repo_root=FIXTURES / "bad")
    findings = run_checks(resources)
    for f in findings:
        if f.check_id == "AS-PROMPT-001":
            f.severity = Severity.CRITICAL
    findings = apply_model_tier(findings, "low")
    assert all(f.severity <= Severity.CRITICAL for f in findings)
