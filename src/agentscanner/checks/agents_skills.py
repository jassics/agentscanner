"""Agent & skill privilege checks (AS-AGENT-*)."""
from __future__ import annotations

from typing import Iterable, List

from ..models import ArtifactType, Finding, Severity
from .base import Check, register

_BROAD = {"*", "all", "all tools"}


def _tokens(value) -> List[str]:
    if isinstance(value, str):
        return [t.strip().lower() for t in value.split(",") if t.strip()]
    if isinstance(value, list):
        return [str(t).strip().lower() for t in value]
    return []


def _is_broad(value) -> bool:
    toks = _tokens(value)
    return any(t in _BROAD for t in toks)


@register
class OverPrivilegedAgent(Check):
    id = "AS-AGENT-001"
    severity = Severity.HIGH
    title = "Over-privileged agent or skill"
    applies_to = {ArtifactType.AGENT, ArtifactType.SKILL, ArtifactType.COMMAND}
    framework = "OWASP LLM06 Excessive Agency"
    remediation = (
        "Avoid permissionMode 'bypassPermissions'/'acceptEdits' in agents and "
        "restrict 'tools'/'allowed-tools' to the minimum the agent needs."
    )

    def analyze(self, resource) -> Iterable[Finding]:
        fm = resource.frontmatter or {}
        if not isinstance(fm, dict):
            return

        mode = fm.get("permissionMode")
        tools_field = fm.get("tools", fm.get("allowed-tools"))
        broad = _is_broad(tools_field)

        if mode == "bypassPermissions":
            yield self.finding(
                resource,
                "Agent sets permissionMode 'bypassPermissions' — it acts without "
                "approval prompts" + (" with access to all tools." if broad or tools_field is None else "."),
                line=resource.line_of("permissionMode"),
            )
        elif mode == "acceptEdits":
            f = self.finding(
                resource,
                "Agent sets permissionMode 'acceptEdits' — file edits are "
                "auto-accepted." + (" Combined with broad tool access." if broad else ""),
                line=resource.line_of("permissionMode"),
            )
            f.severity = Severity.HIGH if broad else Severity.MEDIUM
            yield f
        elif broad and resource.type == ArtifactType.SKILL:
            # an auto-invocable skill granting all tools
            auto = not fm.get("disable-model-invocation", False)
            if auto:
                f = self.finding(
                    resource,
                    "Auto-invocable skill grants all tools (allowed-tools: *). "
                    "Scope tools or set disable-model-invocation.",
                    line=resource.line_of("allowed-tools"),
                )
                f.severity = Severity.MEDIUM
                yield f


# Untrusted-external-input tools: anything that pulls content the agent did
# not author and cannot fully vet (web pages, search results, email,
# calendar invites, RSS/feeds, generic "fetch/browse/read" MCP tools).
_UNTRUSTED_INPUT_TOOLS = {"webfetch", "websearch"}
_UNTRUSTED_INPUT_KEYWORDS = ("mail", "gmail", "calendar", "fetch", "browse", "search", "feed", "rss")

# High-impact-action tools: anything that changes state outside the current
# conversation (runs code, writes files, sends/pays/deletes/deploys).
_HIGH_IMPACT_TOOLS = {"bash"}
_HIGH_IMPACT_KEYWORDS = ("send", "pay", "transfer", "delete", "deploy", "execute", "write", "post", "publish", "wire")


def _matches_any(tool: str, exact: set, keywords: tuple) -> bool:
    return tool in exact or any(k in tool for k in keywords)


@register
class GoalHijackChain(Check):
    id = "AS-AGENT-002"
    severity = Severity.MEDIUM  # bumped to HIGH when there's no approval checkpoint
    title = "Agent/skill combines untrusted external input with a high-impact action tool"
    applies_to = {ArtifactType.AGENT, ArtifactType.SKILL, ArtifactType.COMMAND}
    framework = "OWASP Agentic AI Top 10 ASI01 Agent Goal Hijack; OWASP LLM01 Prompt Injection"
    remediation = (
        "This is not automatically malicious, but it is the exact shape of the "
        "indirect-prompt-injection-to-action chain behind EchoLeak and similar "
        "incidents: content the agent didn't author (web/email/search/calendar) "
        "can steer a tool that changes state (Bash, file writes, sends, payments). "
        "Per OWASP ASI01: require human approval before the high-impact action, "
        "or split untrusted-input handling and high-impact actions into separate "
        "agents so a single injected instruction can't chain straight through."
    )

    def analyze(self, resource) -> Iterable[Finding]:
        fm = resource.frontmatter or {}
        if not isinstance(fm, dict):
            return
        tools_field = fm.get("tools", fm.get("allowed-tools"))
        tools = _tokens(tools_field)
        if not tools:
            return

        # Require the two capabilities to come from *distinct* tools. A
        # single tool name can substring-match both keyword sets (e.g. an
        # MCP "gmail...send_message" tool matches "mail" and "send"), which
        # is one capability, not the two-tool combination this check flags.
        untrusted_input_tools = {
            t for t in tools if _matches_any(t, _UNTRUSTED_INPUT_TOOLS, _UNTRUSTED_INPUT_KEYWORDS)
        }
        high_impact_tools = {
            t for t in tools if _matches_any(t, _HIGH_IMPACT_TOOLS, _HIGH_IMPACT_KEYWORDS)
        }
        if not untrusted_input_tools or not high_impact_tools:
            return
        if len(untrusted_input_tools | high_impact_tools) < 2:
            return

        key = "tools" if "tools" in fm else "allowed-tools"
        f = self.finding(
            resource,
            f"Declares both an untrusted external-input tool and a high-impact "
            f"action tool ({tools_field!r}) — an indirect prompt injection in "
            "fetched/retrieved content can redirect the agent straight into "
            "the high-impact action with no separate review step.",
            line=resource.line_of(key),
        )
        if fm.get("permissionMode") in ("bypassPermissions", "acceptEdits"):
            f.severity = Severity.HIGH
        yield f


@register
class AgentUnboundedTurns(Check):
    id = "AS-AGENT-005"
    severity = Severity.LOW  # escalated to MEDIUM when the field is present but broken
    title = "Agent has no effective maxTurns bound"
    applies_to = {ArtifactType.AGENT}
    framework = "OWASP LLM10 Unbounded Consumption"
    remediation = (
        "Set 'maxTurns' to a positive integer in the agent's frontmatter. There is "
        "no platform default cap — an agent with no maxTurns (or an invalid value) "
        "runs unbounded, risking runaway cost, a hung session, or an unattended "
        "CI/CD invocation that never terminates."
    )

    def analyze(self, resource) -> Iterable[Finding]:
        fm = resource.frontmatter or {}
        if not isinstance(fm, dict):
            return

        if "maxTurns" not in fm:
            yield self.finding(
                resource,
                "Agent frontmatter has no 'maxTurns' — it can run an unbounded "
                "number of turns (no platform default limit applies).",
            )
            return

        raw = fm.get("maxTurns")
        valid = isinstance(raw, int) and not isinstance(raw, bool) and raw > 0
        if not valid:
            f = self.finding(
                resource,
                f"Agent 'maxTurns: {raw!r}' is not a positive integer, so it will "
                "not actually bound the agent's turns.",
                line=resource.line_of("maxTurns"),
            )
            f.severity = Severity.MEDIUM
            yield f
