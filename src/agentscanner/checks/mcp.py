"""MCP server checks (AS-MCP-*).

MCP servers are arbitrary processes (stdio) or remote endpoints (http/sse).
Risks: plaintext secrets, cleartext transport, auto-trust, unpinned supply chain.
"""
from __future__ import annotations

import re
from typing import Dict, Iterable

from .. import osv
from ..data import SECRET_KEY_NAME, find_secret, is_env_reference
from ..models import ArtifactType, Finding, Severity
from .base import Check, register


def _servers(resource) -> Dict[str, dict]:
    data = None
    if resource.type in (ArtifactType.MCP, ArtifactType.SETTINGS) and isinstance(resource.data, dict):
        data = resource.data
    elif resource.frontmatter:
        data = resource.frontmatter
    if not isinstance(data, dict):
        return {}
    servers = data.get("mcpServers")
    return servers if isinstance(servers, dict) else {}


@register
class McpPlaintextSecret(Check):
    id = "AS-MCP-001"
    severity = Severity.HIGH
    title = "Plaintext secret in MCP server env"
    applies_to = {ArtifactType.MCP, ArtifactType.SETTINGS, ArtifactType.AGENT}
    framework = "OWASP LLM02 Sensitive Information Disclosure"
    remediation = (
        "Do not hardcode credentials in MCP env. Reference an environment "
        "variable (${VAR}) or use settings.apiKeyHelper to inject at runtime."
    )

    def analyze(self, resource) -> Iterable[Finding]:
        for name, cfg in _servers(resource).items():
            if not isinstance(cfg, dict):
                continue
            env = cfg.get("env", {})
            if not isinstance(env, dict):
                continue
            for k, v in env.items():
                if not isinstance(v, str) or is_env_reference(v):
                    continue
                hit = find_secret(v)
                if hit:
                    label, _ = hit
                    yield self.finding(
                        resource,
                        f"MCP server '{name}' env '{k}' contains a hardcoded "
                        f"{label}.",
                        line=resource.line_of(k),
                    )
                elif SECRET_KEY_NAME.search(k) and len(v) >= 8:
                    yield self.finding(
                        resource,
                        f"MCP server '{name}' env '{k}' looks like a hardcoded "
                        f"credential value.",
                        line=resource.line_of(k),
                    )


@register
class McpCleartextTransport(Check):
    id = "AS-MCP-002"
    severity = Severity.HIGH
    title = "Remote MCP server over cleartext http://"
    applies_to = {ArtifactType.MCP, ArtifactType.SETTINGS, ArtifactType.AGENT}
    framework = "OWASP LLM02; MCP secure-use guidance"
    remediation = "Use https:// (or a localhost stdio server) for MCP endpoints."

    def analyze(self, resource) -> Iterable[Finding]:
        for name, cfg in _servers(resource).items():
            if not isinstance(cfg, dict):
                continue
            url = cfg.get("url", "")
            if isinstance(url, str) and url.lower().startswith("http://"):
                host = url.split("/")[2] if "://" in url else ""
                if not host.startswith(("localhost", "127.0.0.1", "[::1]")):
                    yield self.finding(
                        resource,
                        f"MCP server '{name}' uses cleartext URL {url!r}.",
                        line=resource.line_of(url),
                    )


@register
class McpAutoTrustAll(Check):
    id = "AS-MCP-003"
    severity = Severity.HIGH
    title = "All project MCP servers auto-trusted"
    applies_to = {ArtifactType.SETTINGS}
    framework = "OWASP LLM03 Supply Chain"
    remediation = (
        "Remove 'enableAllProjectMcpServers'. Approve project MCP servers "
        "explicitly via enabledMcpjsonServers or the interactive trust prompt."
    )

    def analyze(self, resource) -> Iterable[Finding]:
        if isinstance(resource.data, dict) and resource.data.get("enableAllProjectMcpServers") is True:
            yield self.finding(
                resource,
                "enableAllProjectMcpServers=true auto-connects every MCP server "
                "declared in the project .mcp.json without prompting.",
                line=resource.line_of("enableAllProjectMcpServers"),
            )


_UNPINNED_NPX = re.compile(r"^(?:@[^/]+/)?[^@\s]+$")  # package with no @version
_PKG_ECOSYSTEM = {"npx": "npm", "bunx": "npm", "pnpm": "npm", "uvx": "PyPI"}


def _iter_command_packages(cfg: dict):
    """Yield ``(ecosystem, pkg_arg, base_name, version_or_None)`` for each
    package-like arg in a stdio MCP server's command/args.

    Single source of truth for pin-detection: AS-MCP-004 (flags *no* pin) and
    AS-MCP-005 (flags a *vulnerable* pin) must agree on what "pinned" means,
    or a package could be silently invisible to one check while flagged by
    the other.
    """
    command = cfg.get("command", "")
    args = cfg.get("args", [])
    ecosystem = _PKG_ECOSYSTEM.get(command)
    if not ecosystem or not isinstance(args, list):
        return
    for a in args:
        if not isinstance(a, str) or a.startswith("-"):
            continue
        if "==" in a:  # uvx pkg==1.2.3
            base, _, version = a.partition("==")
            yield ecosystem, a, base, (version or None)
            continue
        # npx/bunx/pnpm: "pkg@1.2.3" or "@scope/pkg@1.2.3"
        body = a[1:] if a.startswith("@") else a
        if "@" in body:
            name_body, _, version = body.partition("@")
            base = f"@{name_body}" if a.startswith("@") else name_body
            yield ecosystem, a, base, (version if version and version != "latest" else None)
        else:
            yield ecosystem, a, a, None


@register
class McpUnpinnedSupplyChain(Check):
    id = "AS-MCP-004"
    severity = Severity.MEDIUM
    title = "stdio MCP server pulls an unpinned remote package"
    applies_to = {ArtifactType.MCP, ArtifactType.SETTINGS, ArtifactType.AGENT}
    framework = "OWASP LLM03 Supply Chain"
    remediation = (
        "Pin the package version (e.g. npx -y pkg@1.2.3 / uvx pkg==1.2.3) so a "
        "compromised or new upstream release cannot run automatically."
    )

    def analyze(self, resource) -> Iterable[Finding]:
        for name, cfg in _servers(resource).items():
            if not isinstance(cfg, dict):
                continue
            command = cfg.get("command", "")
            for _ecosystem, pkg, base, version in _iter_command_packages(cfg):
                if version is None and _UNPINNED_NPX.match(base):
                    yield self.finding(
                        resource,
                        f"MCP server '{name}' runs unpinned package '{pkg}' via "
                        f"'{command}'.",
                        line=resource.line_of(pkg),
                    )
                    break


@register
class McpDependencyKnownVulnerability(Check):
    id = "AS-MCP-005"
    severity = Severity.HIGH  # per-finding severity is overridden from OSV data
    title = "stdio MCP server pins a package with a known vulnerability (OSV.dev)"
    applies_to = {ArtifactType.MCP, ArtifactType.SETTINGS, ArtifactType.AGENT}
    framework = "OWASP LLM03 Supply Chain"
    remediation = (
        "Upgrade the pinned package to a version outside the affected range "
        "(see the linked OSV advisory for the fixed version)."
    )

    def analyze(self, resource) -> Iterable[Finding]:
        for name, cfg in _servers(resource).items():
            if not isinstance(cfg, dict):
                continue
            for ecosystem, _pkg_arg, pkg, version in _iter_command_packages(cfg):
                if version is None:
                    continue
                vulns = osv.query_dependency(ecosystem, pkg, version)
                if not vulns:
                    continue
                for vuln in vulns:
                    vid = vuln.get("id", "UNKNOWN")
                    summary = (vuln.get("summary") or vuln.get("details") or "no summary provided")[:200]
                    finding = self.finding(
                        resource,
                        f"MCP server '{name}' pins vulnerable package {pkg}@{version} "
                        f"({vid}): {summary}",
                        line=resource.line_of(pkg),
                    )
                    finding.severity = osv.to_severity(vuln)
                    yield finding
