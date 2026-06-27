"""Hook checks (AS-HOOK-*).

Hooks run arbitrary commands at lifecycle events — the highest-impact artifact.
We inspect the command strings as DATA only; agentscan never executes them.
Hooks can live in settings.json and in agent frontmatter, so checks iterate both.
"""
from __future__ import annotations

import re
from typing import Iterable, Iterator, Tuple

from ..data import REMOTE_EXEC
from ..models import ArtifactType, Finding, Severity
from .base import Check, register

# Events whose hook stdout is injected into the model context (injection-relevant).
CONTEXT_INJECTING = {
    "SessionStart", "Setup", "UserPromptSubmit",
    "UserPromptExpansion", "InstructionsLoaded",
}
_NETWORK = re.compile(r"(?i)\b(curl|wget|nc|ncat|netcat|ssh|scp|telnet|http[s]?://)\b")
_UNTRUSTED_PATH = re.compile(r"(?:^|\s)(?:\./|\.\./|/tmp/|/var/tmp/|/dev/shm/)")
_SCRIPT_TOKEN = re.compile(r"([^\s'\"]+\.(?:py|sh|js|rb|pl|ps1))")


def iter_hooks(resource) -> Iterator[Tuple[str, dict]]:
    """Yield (event_name, hook_entry) for every command-type hook in a resource."""
    container = None
    if resource.type == ArtifactType.SETTINGS and isinstance(resource.data, dict):
        container = resource.data.get("hooks")
    elif resource.frontmatter:
        container = resource.frontmatter.get("hooks")
    if not isinstance(container, dict):
        return
    for event, groups in container.items():
        if not isinstance(groups, list):
            continue
        for group in groups:
            if not isinstance(group, dict):
                continue
            for entry in group.get("hooks", []):
                if isinstance(entry, dict):
                    yield event, entry


def _command_of(entry: dict) -> str:
    cmd = entry.get("command", "")
    if isinstance(cmd, list):
        return " ".join(str(c) for c in cmd)
    return cmd if isinstance(cmd, str) else ""


@register
class HookRemoteExec(Check):
    id = "AS-HOOK-001"
    severity = Severity.CRITICAL
    title = "Hook fetches and executes remote code"
    applies_to = {ArtifactType.SETTINGS, ArtifactType.AGENT}
    framework = "OWASP LLM03 Supply Chain; LLM05 Improper Output Handling"
    remediation = (
        "Never pipe network downloads into a shell in a hook (curl|sh, eval $(curl)). "
        "Vendor and pin the script locally and invoke the local file."
    )

    def analyze(self, resource) -> Iterable[Finding]:
        for event, entry in iter_hooks(resource):
            cmd = _command_of(entry)
            if cmd and REMOTE_EXEC.search(cmd):
                yield self.finding(
                    resource,
                    f"{event} hook downloads and executes remote code: {cmd!r}",
                    line=resource.line_of(cmd[:40]),
                )


@register
class HookUntrustedPath(Check):
    id = "AS-HOOK-002"
    severity = Severity.HIGH
    title = "Hook runs a script from a relative or world-writable path"
    applies_to = {ArtifactType.SETTINGS, ArtifactType.AGENT}
    framework = "OWASP LLM03 Supply Chain"
    remediation = (
        "Reference hook scripts by absolute path under a trusted, non-writable "
        "directory (e.g. ~/.claude/hooks/), not relative paths or /tmp."
    )

    def analyze(self, resource) -> Iterable[Finding]:
        for event, entry in iter_hooks(resource):
            cmd = _command_of(entry)
            if not cmd:
                continue
            script = _SCRIPT_TOKEN.search(cmd)
            relative_or_tmp = bool(_UNTRUSTED_PATH.search(cmd)) or (
                script is not None and "/" not in script.group(1)
            )
            if relative_or_tmp:
                yield self.finding(
                    resource,
                    f"{event} hook executes a script from an untrusted/relative "
                    f"path: {cmd!r}",
                    line=resource.line_of(cmd[:40]),
                )


@register
class HookContextInjectionNetwork(Check):
    id = "AS-HOOK-003"
    severity = Severity.MEDIUM
    title = "Context-injecting hook makes network calls"
    applies_to = {ArtifactType.SETTINGS, ArtifactType.AGENT}
    framework = "OWASP LLM01 Prompt Injection"
    remediation = (
        "Hooks on SessionStart/UserPromptSubmit/InstructionsLoaded inject their "
        "output into the model context. Fetching remote content here is an "
        "indirect prompt-injection vector — use vetted local content only."
    )

    def analyze(self, resource) -> Iterable[Finding]:
        for event, entry in iter_hooks(resource):
            if event not in CONTEXT_INJECTING:
                continue
            cmd = _command_of(entry)
            if cmd and _NETWORK.search(cmd):
                yield self.finding(
                    resource,
                    f"{event} hook injects context and makes a network call: {cmd!r}",
                    line=resource.line_of(cmd[:40]),
                )


@register
class HookNoTimeout(Check):
    id = "AS-HOOK-004"
    severity = Severity.LOW
    title = "Hook has no timeout"
    applies_to = {ArtifactType.SETTINGS, ArtifactType.AGENT}
    framework = "Operational hardening"
    remediation = "Set an explicit 'timeout' on command hooks to bound runtime."

    def analyze(self, resource) -> Iterable[Finding]:
        for event, entry in iter_hooks(resource):
            if entry.get("type", "command") != "command":
                continue
            if "timeout" not in entry and _command_of(entry):
                yield self.finding(
                    resource,
                    f"{event} hook command has no timeout set.",
                    line=resource.line_of(_command_of(entry)[:40]),
                )
