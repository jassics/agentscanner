"""Environment-posture and hardcoded-secret checks (AS-ENV-*, AS-SECRET-*)."""
from __future__ import annotations

from typing import Iterable, Iterator, Tuple

from ..data import SECRET_KEY_NAME, find_secret, is_env_reference
from ..models import ArtifactType, Finding, Severity
from .base import Check, register

# Hosts considered first-party for Anthropic API traffic.
TRUSTED_API_SUFFIXES = ("anthropic.com",)


def _walk_strings(obj, prefix="") -> Iterator[Tuple[str, str]]:
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk_strings(v, f"{prefix}.{k}" if prefix else str(k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk_strings(v, f"{prefix}[{i}]")
    elif isinstance(obj, str):
        yield prefix, obj


def _host_of(url: str) -> str:
    if "://" not in url:
        return ""
    rest = url.split("://", 1)[1]
    return rest.split("/")[0].split("@")[-1].split(":")[0].lower()


@register
class EndpointRedirect(Check):
    id = "AS-ENV-001"
    severity = Severity.HIGH
    title = "API endpoint or auth token redirected away from Anthropic"
    applies_to = {ArtifactType.SETTINGS}
    framework = "OWASP LLM02 Sensitive Information Disclosure"
    remediation = (
        "Do not point ANTHROPIC_BASE_URL at a non-Anthropic host or hardcode "
        "ANTHROPIC_AUTH_TOKEN/ANTHROPIC_API_KEY in settings — this can route "
        "prompts/credentials through a third party (exfil/MITM)."
    )

    def analyze(self, resource) -> Iterable[Finding]:
        if not isinstance(resource.data, dict):
            return
        env = resource.data.get("env", {})
        if not isinstance(env, dict):
            return

        base = env.get("ANTHROPIC_BASE_URL")
        if isinstance(base, str) and base and not is_env_reference(base):
            host = _host_of(base)
            if host and not host.endswith(TRUSTED_API_SUFFIXES) and not host.startswith(("localhost", "127.0.0.1")):
                yield self.finding(
                    resource,
                    f"ANTHROPIC_BASE_URL points to non-Anthropic host {host!r}.",
                    line=resource.line_of("ANTHROPIC_BASE_URL"),
                )

        for tok in ("ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_API_KEY"):
            val = env.get(tok)
            if isinstance(val, str) and val and not is_env_reference(val):
                yield self.finding(
                    resource,
                    f"{tok} is hardcoded in settings env rather than injected at "
                    f"runtime.",
                    line=resource.line_of(tok),
                )


@register
class HardcodedSecret(Check):
    id = "AS-SECRET-001"
    severity = Severity.HIGH
    title = "Hardcoded secret in configuration"
    applies_to = {ArtifactType.SETTINGS, ArtifactType.AGENT, ArtifactType.PLUGIN_MANIFEST}
    framework = "OWASP LLM02 Sensitive Information Disclosure"
    remediation = (
        "Remove the credential and load it from the environment or a secrets "
        "manager. Rotate any secret that was committed."
    )

    def analyze(self, resource) -> Iterable[Finding]:
        root = resource.data if isinstance(resource.data, dict) else resource.frontmatter
        if not isinstance(root, dict):
            return
        seen = set()
        for keypath, value in _walk_strings(root):
            if is_env_reference(value):
                continue
            leaf = keypath.split(".")[-1].split("[")[0]
            hit = find_secret(value)
            if hit:
                label, _ = hit
                key = (keypath, label)
                if key in seen:
                    continue
                seen.add(key)
                yield self.finding(
                    resource,
                    f"{keypath} contains a hardcoded {label}.",
                    line=resource.line_of(leaf),
                )
            elif SECRET_KEY_NAME.search(leaf) and len(value) >= 12 and " " not in value:
                key = (keypath, "value")
                if key in seen:
                    continue
                seen.add(key)
                yield self.finding(
                    resource,
                    f"{keypath} looks like a hardcoded credential value.",
                    line=resource.line_of(leaf),
                )
