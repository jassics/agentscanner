"""Prompt-content checks for steering files (AS-PROMPT-*).

Scans the prose body of agents, skills, commands, and CLAUDE.md for prompt-
injection / steering indicators and hidden unicode. Patterns are deliberately
specific to keep false positives low (security docs legitimately mention
"exfiltrate" etc., so we require imperative phrasing).
"""
from __future__ import annotations

from typing import Iterable

from ..data import HIDDEN_UNICODE, INJECTION_PATTERNS, UNBOUNDED_EXECUTION_PATTERNS
from ..models import ArtifactType, Finding, Severity
from .base import Check, register


@register
class PromptInjectionIndicators(Check):
    id = "AS-PROMPT-001"
    severity = Severity.MEDIUM
    title = "Prompt-injection or hidden-content indicators in steering file"
    model_sensitive = True
    applies_to = {
        ArtifactType.AGENT, ArtifactType.SKILL,
        ArtifactType.COMMAND, ArtifactType.MEMORY,
    }
    framework = "OWASP LLM01 Prompt Injection"
    remediation = (
        "Review this file's instructions. Remove directives that override prior "
        "instructions, disable controls, suppress user notification, or exfiltrate "
        "data, and strip any hidden/zero-width unicode."
    )

    def analyze(self, resource) -> Iterable[Finding]:
        text = resource.body if resource.body is not None else resource.raw_text
        if not text:
            return

        for label, rx in INJECTION_PATTERNS:
            m = rx.search(text)
            if m:
                snippet = m.group(0).strip()
                yield self.finding(
                    resource,
                    f"Possible prompt-injection ({label}): {snippet!r}",
                    line=resource.line_of(snippet[:30]),
                )

        hidden = HIDDEN_UNICODE.search(text)
        if hidden:
            line = text.count("\n", 0, hidden.start()) + 1
            if resource.body is not None and resource.body in resource.raw_text:
                line += resource.raw_text.count("\n", 0, resource.raw_text.index(resource.body))
            yield self.finding(
                resource,
                f"File contains hidden/zero-width or bidi-control unicode "
                f"(U+{ord(hidden.group()):04X}) that can conceal instructions "
                f"from a human reviewer.",
                line=line,
            )


@register
class UnboundedExecutionLanguage(Check):
    id = "AS-PROMPT-002"
    severity = Severity.MEDIUM
    title = "Instructions tell the agent to disregard turn limits or interruption"
    model_sensitive = True
    applies_to = {ArtifactType.AGENT, ArtifactType.SKILL, ArtifactType.COMMAND}
    framework = "OWASP LLM10 Unbounded Consumption"
    remediation = (
        "maxTurns is a hard harness-level stop regardless of what the prompt says, "
        "but instructions telling the model to disregard turn limits, resist "
        "interruption, or run indefinitely make it far more likely the agent will "
        "burn its entire turn/cost budget on every invocation instead of stopping "
        "when the task is actually done -- and read as an attempt to override "
        "oversight even when the harness itself can't be overridden. Remove this "
        "language and give the agent a concrete, checkable completion condition "
        "instead."
    )

    def analyze(self, resource) -> Iterable[Finding]:
        text = resource.body if resource.body is not None else resource.raw_text
        if not text:
            return

        for label, rx in UNBOUNDED_EXECUTION_PATTERNS:
            m = rx.search(text)
            if m:
                snippet = m.group(0).strip()
                yield self.finding(
                    resource,
                    f"Instructions tell the agent to disregard stopping "
                    f"conditions ({label}): {snippet!r}",
                    line=resource.line_of(snippet[:30]),
                )
