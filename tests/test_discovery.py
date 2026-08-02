"""Plugin-tree discovery: plugins/<name>/.mcp.json must be found.

Regression test for a real gap found while dogfooding AS-MCP-007: the
marketplace-repo collector globbed skills/agents/commands/manifests under
plugins/**/ but never a plugin's own .mcp.json, so every AS-MCP-* check
(secrets, cleartext, unpinned deps, timeouts) silently missed any MCP servers
a plugin bundled -- on any repo scanned this way, not just this project's.
"""
from __future__ import annotations

from pathlib import Path

from agentscanner.discovery import discover
from agentscanner.engine import run_checks
from agentscanner.models import ArtifactType, Scope

FIXTURES = Path(__file__).parent / "fixtures"


def test_plugin_scoped_mcp_json_is_discovered():
    resources = discover(repo_root=FIXTURES / "plugin-marketplace")
    mcp_resources = [r for r in resources if r.type is ArtifactType.MCP]
    assert len(mcp_resources) == 1
    assert mcp_resources[0].scope is Scope.PLUGIN
    assert mcp_resources[0].path.name == ".mcp.json"


def test_plugin_scoped_mcp_json_is_checked():
    resources = discover(repo_root=FIXTURES / "plugin-marketplace")
    findings = run_checks(resources)
    ids = {f.check_id for f in findings}
    assert "AS-MCP-007" in ids, f"expected AS-MCP-007, got {sorted(ids)}"
