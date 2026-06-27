"""OWASP Agentic Skills Top 10 checks (AS-SKILL-*).

All ten AST risks are covered with deterministic, zero-FP detections:

  AS-SKILL-001  AST01 – Identity-file write access (Malicious Skills)
  AS-SKILL-002  AST01 – Social-engineering Prerequisites section (Malicious Skills)
  AS-SKILL-003  AST02 – Missing signature on Universal-Format skill (Supply Chain)
  AS-SKILL-004  AST03 – network: true boolean over-grant (Over-Privileged Skills)
  AS-SKILL-005  AST03 – shell: true explicit access (Over-Privileged Skills)
  AS-SKILL-006  AST04 – risk_tier/permissions contradiction (Insecure Metadata)
  AS-SKILL-007  AST05 – YAML unsafe execution tags in raw file (Unsafe Deserialization)
  AS-SKILL-008  AST06 – sandboxed_execution: false (Weak Isolation)
  AS-SKILL-009  AST07 – Missing version on Universal-Format skill (Update Drift)
  AS-SKILL-010  AST08 – Standalone base64 block in prose (Poor Scanning evasion)
  AS-SKILL-011  AST09 – Missing publisher on Universal-Format skill (No Governance)
  AS-SKILL-012  AST10 – Multi-platform skill missing signature (Cross-Platform Reuse)

Absence checks (AS-SKILL-003, 009, 011, 012) are gated: they only fire when the skill
already declares at least one Universal Agentic Skill Format field (risk_tier, platforms,
signature, publisher, content_hash, scan_status, signing_key).  This avoids drowning every
legacy Claude Code skill in provenance findings for fields the format never required.

Reference: OWASP Agentic Skills Top 10 v0.5, June 2026
           https://owasp.org/www-project-agentic-skills-top-10/
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, List

from ..models import ArtifactType, Finding, Severity
from .base import Check, register

# ── Universal Agentic Skill Format opt-in detection ─────────────────────────
# Keys proposed by the OWASP AST doc's Universal Skill Format (v0.5 pp.39-40).
# Presence of ANY of these means the author adopted the format; absence checks
# are only surfaced in that case.
_UNIVERSAL_FORMAT_KEYS = frozenset({
    "signature", "content_hash", "risk_tier", "publisher",
    "scan_status", "platforms", "signing_key",
})


def _uses_universal_format(fm: dict) -> bool:
    return bool(_UNIVERSAL_FORMAT_KEYS & set(fm.keys()))


# ── Identity files a skill must never be granted write access to ─────────────
_IDENTITY_FILES = frozenset({
    "soul.md", "memory.md", "agents.md",
    ".soul.md", ".memory.md", ".agents.md",
    "claude.md",
})


def _names_identity_file(path_str: str) -> bool:
    return Path(path_str).name.lower() in _IDENTITY_FILES


def _collect_write_paths(fm: dict) -> List[str]:
    """Return all write-path strings from a skill's permission manifest."""
    perms = fm.get("permissions", {})
    if not isinstance(perms, dict):
        return []
    write: List[str] = []
    files = perms.get("files", {})
    if isinstance(files, dict):
        w = files.get("write", [])
        if isinstance(w, list):
            write.extend(str(p) for p in w)
        elif isinstance(w, str):
            write.append(w)
    flat_w = perms.get("write", [])
    if isinstance(flat_w, list):
        write.extend(str(p) for p in flat_w)
    elif isinstance(flat_w, str):
        write.append(flat_w)
    return write


# ── Social-engineering Prerequisites pattern ─────────────────────────────────
_PREREQS_HEADING = re.compile(r"(?im)^#+\s*prerequisites\s*$")
_PIPE_TO_SHELL = re.compile(
    r"(?i)\b(curl|wget)\b[^|\n]{0,120}\|\s*(?:(?:ba|da)?sh|python\d?|pwsh)\b"
)

# ── YAML unsafe execution tags ───────────────────────────────────────────────
_YAML_EXEC_TAGS = re.compile(
    r"!!\s*(python/object|python/apply|python/name|python/module|python/reduce)\b",
    re.IGNORECASE,
)

# ── Standalone base64 block (obfuscated payload) ─────────────────────────────
# A line consisting only of base64 characters, ≥ 60 chars — too long to be an
# inline value and too clean to be prose; used to hide NL payloads from scanners.
_BASE64_LINE = re.compile(r"(?m)^[A-Za-z0-9+/]{60,}={0,2}$")

# ── Safe risk tiers (L0 / L1 / equivalent) ───────────────────────────────────
_SAFE_TIERS = frozenset({"l0", "l1", "low", "0", "1", "safe"})


# ─────────────────────────────────────────────────────────────────────────────
# AS-SKILL-001  AST01 – Identity-file write access
# ─────────────────────────────────────────────────────────────────────────────

@register
class SkillIdentityFileWrite(Check):
    id = "AS-SKILL-001"
    severity = Severity.CRITICAL
    title = "Skill requests write access to agent identity files"
    applies_to = {ArtifactType.SKILL}
    framework = "OWASP Agentic Skills AST01 – Malicious Skills"
    remediation = (
        "Remove SOUL.md, MEMORY.md, AGENTS.md, and CLAUDE.md from permissions.files.write. "
        "Skills that write identity files persist backdoor instructions beyond uninstall."
    )

    def analyze(self, resource) -> Iterable[Finding]:
        fm = resource.frontmatter or {}
        if not isinstance(fm, dict):
            return
        for path_str in _collect_write_paths(fm):
            if _names_identity_file(path_str):
                yield self.finding(
                    resource,
                    f"Skill declares write access to identity file {path_str!r} — "
                    "enables persistent backdoor instructions that survive skill uninstall.",
                    line=resource.line_of(path_str),
                )


# ─────────────────────────────────────────────────────────────────────────────
# AS-SKILL-002  AST01 – Social-engineering Prerequisites section
# ─────────────────────────────────────────────────────────────────────────────

@register
class SkillSocialEngineeringPrereqs(Check):
    id = "AS-SKILL-002"
    severity = Severity.HIGH
    title = "Skill has social-engineering Prerequisites section with pipe-to-shell"
    applies_to = {ArtifactType.SKILL}
    framework = "OWASP Agentic Skills AST01 – Malicious Skills"
    remediation = (
        "Remove Prerequisites sections that instruct users to run curl|sh or wget|sh. "
        "Vendor dependencies locally and invoke them from an absolute, trusted path."
    )

    def analyze(self, resource) -> Iterable[Finding]:
        body = resource.body or ""
        m = _PREREQS_HEADING.search(body)
        if not m:
            return
        window = body[m.end(): m.end() + 600]
        pipe_m = _PIPE_TO_SHELL.search(window)
        if pipe_m:
            snippet = pipe_m.group(0).strip()
            yield self.finding(
                resource,
                f"Skill 'Prerequisites' section instructs users to pipe a remote download "
                f"into a shell: {snippet!r}",
                line=resource.line_of("Prerequisites"),
            )


# ─────────────────────────────────────────────────────────────────────────────
# AS-SKILL-003  AST02 – Missing signature (Universal-Format opt-in)
# ─────────────────────────────────────────────────────────────────────────────

@register
class SkillMissingSignature(Check):
    id = "AS-SKILL-003"
    severity = Severity.HIGH
    title = "Universal-Format skill missing cryptographic signature"
    applies_to = {ArtifactType.SKILL}
    framework = "OWASP Agentic Skills AST02 – Supply Chain Compromise"
    remediation = (
        "Add a 'signature' field (ed25519 over the canonical content hash). "
        "Without it, any compromise of the distribution channel is undetectable."
    )

    def analyze(self, resource) -> Iterable[Finding]:
        fm = resource.frontmatter or {}
        if not isinstance(fm, dict) or not _uses_universal_format(fm):
            return
        if not fm.get("signature"):
            yield self.finding(
                resource,
                "Skill uses Universal Agentic Skill Format fields but has no 'signature' — "
                "integrity cannot be verified across distribution channels.",
                line=1,
            )


# ─────────────────────────────────────────────────────────────────────────────
# AS-SKILL-004  AST03 – network: true boolean over-grant
# ─────────────────────────────────────────────────────────────────────────────

@register
class SkillNetworkBooleanOverGrant(Check):
    id = "AS-SKILL-004"
    severity = Severity.HIGH
    title = "Skill sets permissions.network: true (binary boolean, not domain allowlist)"
    applies_to = {ArtifactType.SKILL}
    framework = "OWASP Agentic Skills AST03 – Over-Privileged Skills"
    remediation = (
        "Replace 'network: true' with a domain allowlist: "
        "network: {allow: [\"api.example.com\"], deny: \"*\"}. "
        "A boolean true grants unrestricted egress to any host."
    )

    def analyze(self, resource) -> Iterable[Finding]:
        fm = resource.frontmatter or {}
        if not isinstance(fm, dict):
            return
        perms = fm.get("permissions", {})
        if isinstance(perms, dict) and perms.get("network") is True:
            yield self.finding(
                resource,
                "permissions.network is 'true' — grants unrestricted outbound network "
                "access instead of a scoped domain allowlist.",
                line=resource.line_of("network"),
            )


# ─────────────────────────────────────────────────────────────────────────────
# AS-SKILL-005  AST03 – shell: true explicit access
# ─────────────────────────────────────────────────────────────────────────────

@register
class SkillShellAccess(Check):
    id = "AS-SKILL-005"
    severity = Severity.HIGH
    title = "Skill declares explicit shell access"
    applies_to = {ArtifactType.SKILL}
    framework = "OWASP Agentic Skills AST03 – Over-Privileged Skills"
    remediation = (
        "Remove 'shell: true'. Use parameterized tool calls scoped to the specific "
        "operations the skill requires. Shell access grants arbitrary code execution."
    )

    def analyze(self, resource) -> Iterable[Finding]:
        fm = resource.frontmatter or {}
        if not isinstance(fm, dict):
            return
        perms = fm.get("permissions", {})
        if isinstance(perms, dict) and perms.get("shell") is True:
            yield self.finding(
                resource,
                "permissions.shell is 'true' — grants arbitrary shell command execution "
                "beyond the skill's stated function.",
                line=resource.line_of("shell"),
            )


# ─────────────────────────────────────────────────────────────────────────────
# AS-SKILL-006  AST04 – risk_tier / permissions contradiction
# ─────────────────────────────────────────────────────────────────────────────

@register
class SkillRiskTierContradiction(Check):
    id = "AS-SKILL-006"
    severity = Severity.HIGH
    title = "Skill risk_tier contradicts declared permissions (risk tier spoofing)"
    applies_to = {ArtifactType.SKILL}
    framework = "OWASP Agentic Skills AST04 – Insecure Metadata"
    remediation = (
        "Align risk_tier with actual permissions. L0/L1 may not be combined with "
        "shell: true, sandboxed_execution: false, or identity-file write access."
    )

    def analyze(self, resource) -> Iterable[Finding]:
        fm = resource.frontmatter or {}
        if not isinstance(fm, dict):
            return
        tier = str(fm.get("risk_tier", "")).strip().lower()
        if not tier or tier not in _SAFE_TIERS:
            return  # not claiming to be safe/low-risk

        perms = fm.get("permissions", {}) if isinstance(fm.get("permissions"), dict) else {}
        dangerous = []
        if perms.get("shell") is True:
            dangerous.append("permissions.shell: true")
        if fm.get("sandboxed_execution") is False:
            dangerous.append("sandboxed_execution: false")
        for p in _collect_write_paths(fm):
            if _names_identity_file(p):
                dangerous.append(f"write to {p!r}")

        if dangerous:
            yield self.finding(
                resource,
                f"Skill declares risk_tier={tier!r} (safe) but also has: "
                f"{', '.join(dangerous)} — contradicts the declared safety level.",
                line=resource.line_of("risk_tier"),
            )


# ─────────────────────────────────────────────────────────────────────────────
# AS-SKILL-007  AST05 – YAML unsafe execution tags
# ─────────────────────────────────────────────────────────────────────────────

@register
class SkillYamlExecTags(Check):
    id = "AS-SKILL-007"
    severity = Severity.CRITICAL
    title = "Skill file contains YAML unsafe execution tags"
    applies_to = {ArtifactType.SKILL}
    framework = "OWASP Agentic Skills AST05 – Unsafe Deserialization"
    remediation = (
        "Remove !!python/object, !!python/apply, and related YAML constructor tags. "
        "These execute arbitrary code when parsed by an unsafe YAML loader."
    )

    def analyze(self, resource) -> Iterable[Finding]:
        m = _YAML_EXEC_TAGS.search(resource.raw_text)
        if m:
            snippet = m.group(0)
            line = resource.raw_text.count("\n", 0, m.start()) + 1
            yield self.finding(
                resource,
                f"File contains YAML unsafe execution tag {snippet!r} — triggers "
                "arbitrary code execution when parsed by an unsafe YAML loader.",
                line=line,
            )


# ─────────────────────────────────────────────────────────────────────────────
# AS-SKILL-008  AST06 – sandboxed_execution: false
# ─────────────────────────────────────────────────────────────────────────────

@register
class SkillSandboxDisabled(Check):
    id = "AS-SKILL-008"
    severity = Severity.HIGH
    title = "Skill explicitly disables sandboxed execution"
    applies_to = {ArtifactType.SKILL}
    framework = "OWASP Agentic Skills AST06 – Weak Isolation"
    remediation = (
        "Remove 'sandboxed_execution: false'. Skills should run isolated in a container "
        "or sandbox; opting out removes all containment guarantees."
    )

    def analyze(self, resource) -> Iterable[Finding]:
        fm = resource.frontmatter or {}
        if not isinstance(fm, dict):
            return
        if fm.get("sandboxed_execution") is False:
            yield self.finding(
                resource,
                "sandboxed_execution: false — skill opts out of all isolation, "
                "enabling direct access to the host environment.",
                line=resource.line_of("sandboxed_execution"),
            )
            return
        security = fm.get("security", {})
        if isinstance(security, dict) and (
            security.get("sandboxed_execution") is False
            or security.get("sandbox") is False
        ):
            key = "sandboxed_execution" if security.get("sandboxed_execution") is False else "sandbox"
            yield self.finding(
                resource,
                f"security.{key}: false — skill opts out of all isolation.",
                line=resource.line_of(key),
            )


# ─────────────────────────────────────────────────────────────────────────────
# AS-SKILL-009  AST07 – Missing version (Universal-Format opt-in)
# ─────────────────────────────────────────────────────────────────────────────

@register
class SkillMissingVersion(Check):
    id = "AS-SKILL-009"
    severity = Severity.MEDIUM
    title = "Universal-Format skill missing version field (update drift risk)"
    applies_to = {ArtifactType.SKILL}
    framework = "OWASP Agentic Skills AST07 – Update Drift"
    remediation = (
        "Add a 'version' field (semver). Without it, agents cannot detect whether an "
        "installed skill has drifted from a known-good pinned version."
    )

    def analyze(self, resource) -> Iterable[Finding]:
        fm = resource.frontmatter or {}
        if not isinstance(fm, dict) or not _uses_universal_format(fm):
            return
        if not fm.get("version"):
            yield self.finding(
                resource,
                "Skill uses Universal Agentic Skill Format fields but has no 'version' — "
                "update drift and malicious patch substitution cannot be detected.",
                line=1,
            )


# ─────────────────────────────────────────────────────────────────────────────
# AS-SKILL-010  AST08 – Standalone base64 block (Poor Scanning evasion)
# ─────────────────────────────────────────────────────────────────────────────

@register
class SkillStandaloneBase64(Check):
    id = "AS-SKILL-010"
    severity = Severity.MEDIUM
    title = "Skill body contains standalone base64-encoded block (obfuscated payload)"
    applies_to = {ArtifactType.SKILL}
    framework = "OWASP Agentic Skills AST08 – Poor Scanning"
    remediation = (
        "Remove base64-encoded content from skill instructions. Encoded blobs hide "
        "malicious payloads from human reviewers and pattern-matching scanners while "
        "remaining decodable and executable by the agent at runtime."
    )

    def analyze(self, resource) -> Iterable[Finding]:
        body = resource.body or ""
        m = _BASE64_LINE.search(body)
        if m:
            snippet = m.group(0)[:20] + "…"
            yield self.finding(
                resource,
                f"Skill body contains a standalone base64-encoded line starting with "
                f"{snippet!r} — potential obfuscated payload invisible to pattern-matching scanners.",
                line=resource.line_of(m.group(0)[:30]),
            )


# ─────────────────────────────────────────────────────────────────────────────
# AS-SKILL-011  AST09 – Missing publisher (Universal-Format opt-in)
# ─────────────────────────────────────────────────────────────────────────────

@register
class SkillMissingPublisher(Check):
    id = "AS-SKILL-011"
    severity = Severity.MEDIUM
    title = "Universal-Format skill missing publisher field (governance gap)"
    applies_to = {ArtifactType.SKILL}
    framework = "OWASP Agentic Skills AST09 – No Governance"
    remediation = (
        "Add a 'publisher' field with a verified identity. Without it the skill cannot "
        "be tied to an accountable party, inventoried, or revoked by a governance process."
    )

    def analyze(self, resource) -> Iterable[Finding]:
        fm = resource.frontmatter or {}
        if not isinstance(fm, dict) or not _uses_universal_format(fm):
            return
        if not fm.get("publisher"):
            yield self.finding(
                resource,
                "Skill uses Universal Agentic Skill Format fields but has no 'publisher' — "
                "cannot be inventoried, audited, or revoked by a governance process.",
                line=1,
            )


# ─────────────────────────────────────────────────────────────────────────────
# AS-SKILL-012  AST10 – Multi-platform skill missing signature
# ─────────────────────────────────────────────────────────────────────────────

@register
class SkillMultiPlatformMissingSignature(Check):
    id = "AS-SKILL-012"
    severity = Severity.MEDIUM
    title = "Multi-platform skill missing signature (security metadata lost in translation)"
    applies_to = {ArtifactType.SKILL}
    framework = "OWASP Agentic Skills AST10 – Cross-Platform Reuse"
    remediation = (
        "Add a 'signature' field when declaring multiple platforms. Security metadata "
        "(risk_tier, permissions) is stripped when skills are ported between formats; "
        "a cryptographic signature is the only cross-platform integrity anchor."
    )

    def analyze(self, resource) -> Iterable[Finding]:
        fm = resource.frontmatter or {}
        if not isinstance(fm, dict):
            return
        platforms = fm.get("platforms", [])
        if not isinstance(platforms, list) or len(platforms) <= 1:
            return  # single-platform or unspecified — not a cross-platform reuse scenario
        if not fm.get("signature"):
            yield self.finding(
                resource,
                f"Skill targets {len(platforms)} platforms {platforms!r} but has no "
                "'signature' — security properties are unverifiable after cross-platform porting.",
                line=resource.line_of("platforms"),
            )
