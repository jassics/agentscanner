"""AS-MCP-007 — stdio MCP server has no explicit timeout.

Remote (url-based) servers get a sane ~60s default and are out of scope;
only command-launched (stdio) servers default to the ~28h MCP_TOOL_TIMEOUT
fallback, which is practically unbounded.
"""
from __future__ import annotations

from agentscanner.checks.mcp import McpStdioNoTimeout
from agentscanner.models import ArtifactType, Scope
from agentscanner.parsers.json_parser import parse_json


def _mcp(tmp_path, servers: dict):
    import json

    p = tmp_path / ".mcp.json"
    p.write_text(json.dumps({"mcpServers": servers}))
    return parse_json(p, Scope.PROJECT, ArtifactType.MCP)


def test_stdio_with_no_timeout_fires(tmp_path):
    resource = _mcp(tmp_path, {"docs": {"command": "npx", "args": ["-y", "pkg"]}})
    findings = list(McpStdioNoTimeout().analyze(resource))
    assert len(findings) == 1


def test_stdio_with_timeout_does_not_fire(tmp_path):
    resource = _mcp(
        tmp_path, {"docs": {"command": "npx", "args": ["-y", "pkg"], "timeout": 60000}}
    )
    findings = list(McpStdioNoTimeout().analyze(resource))
    assert not findings


def test_remote_url_server_with_no_timeout_does_not_fire(tmp_path):
    """Remote transports get a sane ~60s default -- out of scope for this check."""
    resource = _mcp(tmp_path, {"remote": {"url": "https://mcp.example.com/sse"}})
    findings = list(McpStdioNoTimeout().analyze(resource))
    assert not findings
