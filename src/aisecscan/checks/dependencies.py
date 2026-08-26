"""Dependency CVE checks (AS-DEP-*) — live OSV.dev lookups for pinned
dependencies bundled with a skill (``requirements.txt`` / ``package.json``).

Deliberately separate from AS-MCP-004 (unpinned supply chain): that check
flags the *absence* of a pinned version; AS-DEP-001 flags a *known
vulnerability* in a version that IS pinned. A skill can fail either, both,
or neither — pinning a vulnerable version is not automatically safer than
floating on latest.
"""
from __future__ import annotations

from typing import Iterable

from .. import osv
from ..models import ArtifactType, Finding, Severity
from .base import Check, register


@register
class DependencyKnownVulnerability(Check):
    id = "AS-DEP-001"
    severity = Severity.HIGH  # per-finding severity is overridden from OSV data
    title = "Skill dependency has a known vulnerability (OSV.dev)"
    applies_to = {ArtifactType.DEPENDENCY}
    framework = "OWASP LLM03 Supply Chain"
    remediation = (
        "Upgrade the dependency to a version outside the affected range "
        "(see the linked OSV advisory for the fixed version), or remove it "
        "if the skill does not actually need it."
    )

    def analyze(self, resource) -> Iterable[Finding]:
        deps = resource.data if isinstance(resource.data, list) else []
        for dep in deps:
            if not dep.get("pinned") or not dep.get("version"):
                continue
            vulns = osv.query_dependency(dep["ecosystem"], dep["name"], dep["version"])
            if not vulns:
                continue
            for vuln in vulns:
                vid = vuln.get("id", "UNKNOWN")
                summary = (vuln.get("summary") or vuln.get("details") or "no summary provided")[:200]
                finding = self.finding(
                    resource,
                    f"{dep['name']}=={dep['version']} ({dep['ecosystem']}) has known "
                    f"vulnerability {vid}: {summary}",
                    line=resource.line_of(dep["name"]),
                )
                finding.severity = osv.to_severity(vuln)
                yield finding
