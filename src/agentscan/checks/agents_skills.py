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
