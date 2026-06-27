"""Permission & permission-mode checks (AS-PERM-*).

Grounded in verified Claude Code matching semantics (DESIGN.md §11):
- Bash rule wildcards are space-boundary aware; `Bash(*)` / `Bash(:*)` match
  effectively everything.
- Resolution is deny > ask > allow; we only inspect `allow` for over-grant.
"""
from __future__ import annotations

import re
from typing import Iterable, List

from ..data import DANGEROUS_COMMANDS
from ..models import ArtifactType, Finding, Severity
from .base import Check, register

_RULE = re.compile(r"^(?P<tool>[A-Za-z_]+)\((?P<arg>.*)\)$", re.DOTALL)


def _allow_rules(data) -> List[str]:
    try:
        rules = data.get("permissions", {}).get("allow", [])
    except AttributeError:
        return []
    return [r for r in rules if isinstance(r, str)]


@register
class WeakPermissionMode(Check):
    id = "AS-PERM-001"
    severity = Severity.HIGH
    title = "Permission mode weakens or removes approval prompts"
    applies_to = {ArtifactType.SETTINGS}
    framework = "OWASP LLM06 Excessive Agency"
    remediation = (
        "Avoid setting defaultMode to 'bypassPermissions' or 'acceptEdits' in "
        "persisted settings. Use 'default' and grant specific allow rules instead."
    )

    def analyze(self, resource) -> Iterable[Finding]:
        if not isinstance(resource.data, dict):
            return
        perms = resource.data.get("permissions", {})
        mode = perms.get("defaultMode") or resource.data.get("permissionMode")
        if not isinstance(mode, str):
            return
        if mode == "bypassPermissions":
            yield self.finding(
                resource,
                "defaultMode is 'bypassPermissions' — Claude proceeds without "
                "asking for almost any tool call.",
                line=resource.line_of("bypassPermissions"),
            )
        elif mode == "acceptEdits":
            f = self.finding(
                resource,
                "defaultMode is 'acceptEdits' — file edits and common fs commands "
                "are auto-accepted without prompting.",
                line=resource.line_of("acceptEdits"),
            )
            f.severity = Severity.MEDIUM
            yield f


@register
class BroadBashAllow(Check):
    id = "AS-PERM-002"
    severity = Severity.HIGH
    title = "Overly broad Bash permission allow rule"
    applies_to = {ArtifactType.SETTINGS}
    framework = "OWASP LLM06 Excessive Agency; Agentic excessive autonomy"
    remediation = (
        "Replace wildcard-only rules like Bash(*) with narrowly scoped commands, "
        "e.g. Bash(npm run test:*). A single '*' matches every command."
    )

    def analyze(self, resource) -> Iterable[Finding]:
        if not isinstance(resource.data, dict):
            return
        for rule in _allow_rules(resource.data):
            m = _RULE.match(rule.strip())
            if not m:
                # a bare "*" or tool-less wildcard is the broadest possible grant
                if rule.strip() == "*":
                    yield self.finding(
                        resource,
                        "Allow rule '*' grants every tool unconditionally.",
                        line=resource.line_of(rule),
                    )
                continue
            tool, arg = m.group("tool"), m.group("arg").strip()
            if tool == "Bash" and arg in ("*", ":*", "* *", ""):
                yield self.finding(
                    resource,
                    f"Bash allow rule '{rule}' matches effectively any command.",
                    line=resource.line_of(rule),
                )
            elif arg == "*" and tool in ("Read", "Write", "Edit"):
                f = self.finding(
                    resource,
                    f"Allow rule '{rule}' grants {tool} on all paths.",
                    line=resource.line_of(rule),
                )
                f.severity = Severity.MEDIUM
                yield f


@register
class DangerousCommandAllowed(Check):
    id = "AS-PERM-003"
    severity = Severity.MEDIUM
    title = "Dangerous command allowed without tight scoping"
    applies_to = {ArtifactType.SETTINGS}
    framework = "OWASP LLM06 Excessive Agency"
    remediation = (
        "Move sensitive commands (curl, sudo, rm, eval, chmod, nc, ...) to 'ask' "
        "or scope them to a specific, safe invocation rather than 'allow'."
    )

    def analyze(self, resource) -> Iterable[Finding]:
        if not isinstance(resource.data, dict):
            return
        for rule in _allow_rules(resource.data):
            m = _RULE.match(rule.strip())
            if not m or m.group("tool") != "Bash":
                continue
            arg = m.group("arg").strip()
            # first token before a space or ':' is the command being permitted
            first = re.split(r"[\s:]", arg, maxsplit=1)[0]
            # Only flag when the rule contains a wildcard — a fully-specified
            # command (e.g. Bash(curl -s "https://api.github.com/...")) is
            # tightly scoped and safe; Bash(curl:*) / Bash(rm -rf *) are not.
            if first in DANGEROUS_COMMANDS and "*" in arg:
                yield self.finding(
                    resource,
                    f"Allow rule '{rule}' broadly permits the sensitive command "
                    f"'{first}' with wildcard arguments.",
                    line=resource.line_of(rule),
                )
