"""AIVSS-Agentic scoring (OWASP AI Vulnerability Scoring System v0.5).

Source: "AIVSS Scoring System For OWASP Agentic AI Core Security Risks v0.5"
(https://aivss.owasp.org). The formula, the 10 factor names, the 0.0/0.5/1.0
factor scale, and the default Threat Multiplier are taken from that spec.
The *per-check factor values* below are ours — the official spec scores its
own 10 Core Risk categories with worked examples from expert threat
modeling, not agentscanner's specific checks. We map each check to the
archetype that best matches its blast radius and publish the mapping (see
``CHECK_ARCHETYPES`` and ``docs/aivss.md``) so the number is reproducible
and auditable: identical (check_id, severity, ThM) in, identical score out,
every time — no live model call, no hidden state.

    AIVSS_Score = ((CVSS_Base_Score + AARS) / 2) x ThM

CVSS_Base_Score: a full CVSS v4.0 calculation needs per-instance
exploitability detail (attack vector, privileges required, user
interaction, scope, ...) that a static config scanner does not have — our
findings are misconfigurations, not a specific exploited software flaw.
Building a full CVSS v4.0 macro-vector engine on inputs we don't have would
manufacture false precision. Instead each check's existing Severity is
anchored to the score NVD itself uses as the midpoint of the equivalent
qualitative CVSS band (CRITICAL 9.5 / HIGH 7.5 / MEDIUM 5.5 / LOW 2.5). This
is a documented approximation, not a substitute for scoring a specific live
instance with the real CVSS v4.0 calculator.

AARS: the sum of the 10 official Agentic AI Risk Factors, each scored
0.0/0.5/1.0 per check archetype.

ThM (Threat Multiplier): defaults to the spec's own recommended starting
point, 0.97 ("an exploit technique is known but not confirmed weaponized
for your instance"). Override with ``--aivss-thm`` if you have specific
threat intel (spec guidance: 1.0 if actively exploited in the wild, ~0.91
if no known exploit exists at all).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Tuple

from .models import Severity

FACTOR_NAMES: Tuple[str, ...] = (
    "autonomyOfAction",
    "toolUse",
    "memoryUse",
    "dynamicIdentity",
    "multiAgentInteractions",
    "nonDeterminism",
    "selfModification",
    "goalDrivenPlanning",
    "contextualAwareness",
    "opacityAndReflexivity",
)

DEFAULT_THM = 0.97

_CVSS_BASE_BY_SEVERITY: Dict[Severity, float] = {
    Severity.CRITICAL: 9.5,
    Severity.HIGH: 7.5,
    Severity.MEDIUM: 5.5,
    Severity.LOW: 2.5,
    Severity.INFO: 0.0,
}

# archetype -> 10-factor vector, in FACTOR_NAMES order. Each captures a
# distinct agentic blast-radius pattern common across our checks; see
# docs/aivss.md for the rationale behind each vector.
_ARCHETYPES: Dict[str, Tuple[float, ...]] = {
    # An external actor can get code running with the agent's own tool
    # access (curl|sh, unsafe deserialization, vulnerable pinned deps).
    "remote_exec":         (1.0, 1.0, 0.5, 0.0, 0.5, 0.5, 0.5, 0.0, 0.5, 0.5),
    # The artifact grants the agent broader standing authority than its
    # task needs (bypassed permissions, unrestricted shell/network, auto-trust).
    "excessive_privilege": (1.0, 1.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.5, 0.0, 0.5),
    # Untrusted content can redirect agent behavior via context the agent
    # is designed to read and act on (prompt injection, social engineering,
    # obfuscated payloads, context-injecting network hooks).
    "injection_surface":   (0.5, 0.0, 0.5, 0.0, 0.0, 0.5, 0.0, 1.0, 1.0, 1.0),
    # A secret or sensitive value is reachable by the agent and/or crosses
    # the trust boundary (hardcoded creds, cleartext transport, endpoint redirect).
    "data_exposure":       (0.0, 0.5, 0.5, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0),
    # Compromise that survives beyond a single session or skill install
    # (identity-file write access).
    "persistence":         (0.5, 0.5, 1.0, 0.5, 0.0, 0.0, 0.5, 0.5, 0.5, 0.5),
    # Missing provenance/signature/version metadata: not itself an active
    # exploit, but removes the ability to detect or attribute one later.
    "governance_gap":      (0.0, 0.0, 0.0, 0.0, 0.5, 0.0, 0.0, 0.0, 0.0, 0.5),
    # Real but low agentic amplification — bounds blast radius rather than
    # enabling it (e.g. a missing hook timeout).
    "hygiene":             (0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0),
}

# check_id -> archetype. Every registered check must appear here — enforced
# by tests/test_aivss.py so a new check can't silently ship unscored.
CHECK_ARCHETYPES: Dict[str, str] = {
    "AS-HOOK-001": "remote_exec",
    "AS-HOOK-002": "remote_exec",
    "AS-HOOK-003": "injection_surface",
    "AS-HOOK-004": "hygiene",
    "AS-PERM-001": "excessive_privilege",
    "AS-PERM-002": "excessive_privilege",
    "AS-PERM-003": "excessive_privilege",
    "AS-MCP-001": "data_exposure",
    "AS-MCP-002": "data_exposure",
    "AS-MCP-003": "excessive_privilege",
    "AS-MCP-004": "remote_exec",
    "AS-MCP-005": "remote_exec",
    "AS-ENV-001": "data_exposure",
    "AS-SECRET-001": "data_exposure",
    "AS-AGENT-001": "excessive_privilege",
    "AS-PROMPT-001": "injection_surface",
    "AS-DEP-001": "remote_exec",
    "AS-SKILL-001": "persistence",
    "AS-SKILL-002": "injection_surface",
    "AS-SKILL-003": "governance_gap",
    "AS-SKILL-004": "excessive_privilege",
    "AS-SKILL-005": "excessive_privilege",
    "AS-SKILL-006": "governance_gap",
    "AS-SKILL-007": "remote_exec",
    "AS-SKILL-008": "excessive_privilege",
    "AS-SKILL-009": "governance_gap",
    "AS-SKILL-010": "injection_surface",
    "AS-SKILL-011": "governance_gap",
    "AS-SKILL-012": "governance_gap",
    "AS-AGENT-002": "injection_surface",
    "AS-HOOK-005": "persistence",
    "AS-AGENT-005": "hygiene",
    "AS-AGENT-006": "excessive_privilege",
    "AS-AGENT-007": "excessive_privilege",
}

# check_id -> explicit factor-vector override, for checks that don't fit
# their archetype's baseline cleanly. Reviewed individually — see comments.
CHECK_OVERRIDES: Dict[str, Tuple[float, ...]] = {
    # enableAllProjectMcpServers auto-trusts *every* declared external MCP
    # server at once with no per-server review -- this is fundamentally a
    # multi-service/multi-agent trust-sprawl issue, not just one over-broad
    # permission, so multiAgentInteractions is bumped above the
    # excessive_privilege archetype's baseline of 0.0.
    "AS-MCP-003": (1.0, 1.0, 0.0, 1.0, 1.0, 0.0, 0.0, 0.5, 0.0, 0.5),
    # Goal-hijack chain: the risk isn't just "untrusted content in context"
    # (that's the injection_surface baseline) but that a high-impact tool is
    # directly reachable from it -- toolUse and goalDrivenPlanning bumped
    # above the injection_surface archetype's baseline of 0.0/1.0.
    "AS-AGENT-002": (0.5, 1.0, 0.0, 0.0, 0.0, 0.5, 0.0, 1.0, 1.0, 0.5),
    # Memory/context poisoning via hook: memoryUse is maxed (this is
    # specifically about persistence beyond the current session, unlike
    # AS-HOOK-003's same-session injection), contextualAwareness maxed
    # (external content is the poisoning vector).
    "AS-HOOK-005": (0.0, 0.5, 1.0, 0.0, 0.0, 0.5, 0.5, 0.5, 1.0, 0.5),
    # Unattended (no approval prompts) AND unbounded (no maxTurns): worse than
    # excessive_privilege's baseline alone -- goalDrivenPlanning bumped to 1.0
    # because with no approval checkpoint and no turn cap, the agent pursues
    # its goal autonomously to completion with no human intervention point.
    "AS-AGENT-006": (1.0, 1.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.5),
    # Backgrounded (detached, no one watching) AND unbounded: not itself an
    # excessive-privilege grant, but autonomyOfAction and goalDrivenPlanning
    # are maxed (runs and pursues its goal with nobody present to notice),
    # and opacityAndReflexivity is maxed (a background agent's progress isn't
    # visible the way a foreground one's is).
    "AS-AGENT-007": (1.0, 0.5, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 1.0),
}


@dataclass
class AivssScore:
    check_id: str
    cvss_base: float
    aars: float
    thm: float
    score: float
    vector: str

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "cvss_base": self.cvss_base,
            "aars": self.aars,
            "thm": self.thm,
            "vector": self.vector,
        }


def factor_vector(check_id: str) -> Tuple[float, ...]:
    """Return the 10-factor AARS vector for *check_id* (FACTOR_NAMES order).

    Raises KeyError if the check has no archetype mapping — callers should
    treat that as a bug (a new check shipped without AIVSS coverage), not a
    silent zero.
    """
    if check_id in CHECK_OVERRIDES:
        return CHECK_OVERRIDES[check_id]
    archetype = CHECK_ARCHETYPES[check_id]
    return _ARCHETYPES[archetype]


def score_finding(check_id: str, severity: Severity, thm: float = DEFAULT_THM) -> AivssScore:
    """Compute an AIVSS-Agentic score for one finding.

    Deterministic: identical (check_id, severity, thm) always yields the
    same score.
    """
    cvss_base = _CVSS_BASE_BY_SEVERITY[severity]
    aars = round(sum(factor_vector(check_id)), 2)
    score = round(((cvss_base + aars) / 2) * thm, 1)
    score = max(0.0, min(10.0, score))
    vector = f"(CVSS:{cvss_base}/AARS:{aars})xThM:{thm}"
    return AivssScore(check_id=check_id, cvss_base=cvss_base, aars=aars, thm=thm, score=score, vector=vector)
