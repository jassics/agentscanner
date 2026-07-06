"""AS-DEP-001 / AS-MCP-005 — OSV.dev dependency-CVE checks.

The network boundary (``osv.query_dependency``) is monkeypatched throughout:
these tests must never make a real HTTP call, and must stay deterministic
regardless of network availability in CI.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from agentscanner import osv
from agentscanner.discovery import discover
from agentscanner.engine import run_checks
from agentscanner.models import Severity
from agentscanner.parsers.dependency_parser import (
    _parse_package_json,
    _parse_requirements,
)

FIXTURES = Path(__file__).parent / "fixtures"

# Captured before conftest's autouse fixture patches osv.query_dependency,
# so offline-mode tests can wrap the real implementation without recursing.
_REAL_QUERY_DEPENDENCY = osv.query_dependency

_FAKE_VULN = {
    "id": "GHSA-fake-0000",
    "summary": "fixture vulnerability for testing",
    "database_specific": {"severity": "HIGH"},
}


def _fake_query(ecosystem, name, version):
    if (ecosystem, name, version) in {
        ("PyPI", "requests", "2.6.0"),
        ("npm", "lodash", "4.17.4"),
        ("npm", "left-pad", "1.3.0"),
    }:
        return [_FAKE_VULN]
    return []


def test_requirements_parser_splits_pinned_and_unpinned():
    deps = _parse_requirements("requests==2.6.0\nunpinned-package\n# comment\n")
    assert {"ecosystem": "PyPI", "name": "requests", "version": "2.6.0", "pinned": True} in deps
    assert any(d["name"] == "unpinned-package" and not d["pinned"] for d in deps)


def test_package_json_parser_splits_pinned_and_unpinned():
    deps = _parse_package_json(
        '{"dependencies": {"lodash": "4.17.4", "floating-dep": "^1.0.0"}}'
    )
    assert {"ecosystem": "npm", "name": "lodash", "version": "4.17.4", "pinned": True} in deps
    assert any(d["name"] == "floating-dep" and not d["pinned"] for d in deps)


def test_as_dep_001_fires_for_pinned_vulnerable_dependency(monkeypatch):
    monkeypatch.setattr(osv, "query_dependency", _fake_query)
    resources = discover(repo_root=FIXTURES / "dep-bad")
    findings = run_checks(resources)
    dep_findings = [f for f in findings if f.check_id == "AS-DEP-001"]
    assert dep_findings, "expected AS-DEP-001 for pinned vulnerable requirements.txt/package.json deps"
    names = {f.message.split("==")[0].split(" ")[0] for f in dep_findings}
    # unpinned deps (unpinned-package, floating-dep) must never be queried/flagged
    assert "unpinned-package" not in names
    assert "floating-dep" not in names
    assert any(f.severity == Severity.HIGH for f in dep_findings)


def test_as_mcp_005_fires_for_pinned_vulnerable_npx_package(monkeypatch):
    monkeypatch.setattr(osv, "query_dependency", _fake_query)
    resources = discover(repo_root=FIXTURES / "dep-bad")
    findings = run_checks(resources)
    mcp_findings = [f for f in findings if f.check_id == "AS-MCP-005"]
    assert mcp_findings, "expected AS-MCP-005 for pinned vulnerable npx package"
    assert "left-pad@1.3.0" in mcp_findings[0].message


def test_offline_mode_skips_lookup_without_crashing(monkeypatch):
    monkeypatch.setenv("AGENTSCANNER_OFFLINE", "1")
    called = []

    def _spy(*args, **kwargs):
        called.append(args)
        return _REAL_QUERY_DEPENDENCY(*args, **kwargs)

    monkeypatch.setattr(osv, "query_dependency", _spy)
    resources = discover(repo_root=FIXTURES / "dep-bad")
    findings = run_checks(resources)
    assert not [f for f in findings if f.check_id in ("AS-DEP-001", "AS-MCP-005")]
    assert called, "offline mode should still call query_dependency (which then no-ops)"


def test_query_dependency_returns_none_without_version():
    assert _REAL_QUERY_DEPENDENCY("PyPI", "requests", None) is None


@pytest.mark.parametrize(
    "vuln,expected",
    [
        ({"database_specific": {"severity": "CRITICAL"}}, Severity.CRITICAL),
        ({"database_specific": {"severity": "MODERATE"}}, Severity.MEDIUM),
        ({"database_specific": {"severity": "LOW"}}, Severity.LOW),
        ({}, Severity.HIGH),  # no label -> conservative default
    ],
)
def test_to_severity_mapping(vuln, expected):
    assert osv.to_severity(vuln) == expected
