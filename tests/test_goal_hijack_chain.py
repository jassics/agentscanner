"""AS-AGENT-002 — must require two DISTINCT tools, not one tool whose name
happens to substring-match both keyword sets (e.g. an MCP "gmail...send"
tool matches both "mail" and "send")."""
from __future__ import annotations

from pathlib import Path

from agentscanner.checks.agents_skills import GoalHijackChain
from agentscanner.models import ArtifactType, Scope
from agentscanner.parsers.markdown_parser import parse_markdown

FIXTURES = Path(__file__).parent / "fixtures"


def _agent(tmp_path, tools: str):
    p = tmp_path / "agent.md"
    p.write_text(
        f"---\nname: test-agent\ndescription: fixture\ntools: \"{tools}\"\n---\n\nBody.\n"
    )
    return parse_markdown(p, Scope.PROJECT, ArtifactType.AGENT)


def test_single_tool_matching_both_keyword_sets_does_not_fire(tmp_path):
    resource = _agent(tmp_path, "mcp__claude_ai_Gmail__send_message")
    findings = list(GoalHijackChain().analyze(resource))
    assert not findings, "a single tool name shouldn't count as two distinct capabilities"


def test_two_distinct_tools_fires(tmp_path):
    resource = _agent(tmp_path, "WebFetch, Bash")
    findings = list(GoalHijackChain().analyze(resource))
    assert len(findings) == 1


def test_two_distinct_mcp_tools_fires(tmp_path):
    resource = _agent(tmp_path, "mcp__claude_ai_Gmail__search_threads, mcp__claude_ai_Gmail__send_message")
    findings = list(GoalHijackChain().analyze(resource))
    assert len(findings) == 1


def test_only_untrusted_input_does_not_fire(tmp_path):
    resource = _agent(tmp_path, "WebFetch, WebSearch")
    findings = list(GoalHijackChain().analyze(resource))
    assert not findings
