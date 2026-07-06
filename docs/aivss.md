# AIVSS-Agentic scoring

`agentscanner scan --aivss` adds an [OWASP AIVSS](https://aivss.owasp.org) score to every finding — a risk score purpose-built for agentic systems, on top of (not instead of) each check's normal `Severity`.

## Why not just severity?

`Severity` (CRITICAL/HIGH/MEDIUM/LOW) tells you how bad a check is in isolation. It does not distinguish "this misconfiguration exists in a system with no autonomy, no persistent memory, no tool access" from "this misconfiguration exists in a system that can act on its own, remember across sessions, and call arbitrary tools." AIVSS is designed specifically to capture that second dimension — how much an agent's own capabilities amplify a given flaw.

## What we implemented — and what we didn't

The official formula, source: *AIVSS Scoring System For OWASP Agentic AI Core Security Risks v0.5* ([spec](https://aivss.owasp.org/assets/publications/AIVSS%20Scoring%20System%20For%20OWASP%20Agentic%20AI%20Core%20Security%20Risks%20v0.5.pdf); also referenced conceptually in `OWASP-Top-10-for-Agentic-Applications-2026-12.6-1.pdf` in the local GenAI study library, which cross-maps its ASI Top 10 entries to AIVSS Core Risk categories):

```
AIVSS_Score = ((CVSS_Base_Score + AARS) / 2) x ThM
```

- **AARS** (Agentic AI Risk Score) — the sum of 10 official factors, each scored 0.0 / 0.5 / 1.0: `autonomyOfAction`, `toolUse`, `memoryUse`, `dynamicIdentity`, `multiAgentInteractions`, `nonDeterminism`, `selfModification`, `goalDrivenPlanning`, `contextualAwareness`, `opacityAndReflexivity`. **We implemented this in full** — `src/agentscanner/aivss.py` uses the official factor names and 0/0.5/1 scale.
- **ThM** (Threat Multiplier) — defaults to the spec's own recommended starting point, `0.97` ("exploit technique known, not confirmed weaponized"). Override with `--aivss-thm` (spec guidance: `1.0` if actively exploited in the wild, `~0.91` if no known exploit exists).
- **CVSS_Base_Score** — **we deliberately did not build a full CVSS v4.0 calculator.** That requires per-instance exploitability metrics (attack vector, attack complexity, privileges required, user interaction, scope, ...) that a static config scanner does not have — our findings are misconfigurations, not a specific exploited flaw in a specific running instance. A hand-rolled CVSS v4.0 macro-vector engine fed with fabricated instance data would produce false precision, not accuracy. Instead, each check's existing `Severity` is anchored to the score NVD itself uses as the midpoint of the equivalent qualitative CVSS band: `CRITICAL→9.5, HIGH→7.5, MEDIUM→5.5, LOW→2.5`. This is a documented approximation — recompute per-instance with the real CVSS v4.0 calculator if you need a fully official number for a specific finding.

## Per-check AARS values are ours, not the spec's

The v0.5 spec scores its own 10 **Core Risk categories** (e.g. "Agentic AI Tool Misuse", AARS=8.5) via expert threat-modeling worked examples — it does not score arbitrary third-party scanner checks. To keep our numbers reproducible rather than inventing 29 bespoke justifications, each check is mapped to one of 7 **archetypes** — a shared 10-factor vector representing a common agentic blast-radius pattern:

| Archetype | Represents | Example checks |
|---|---|---|
| `remote_exec` | External actor gets code running with the agent's tool access | `AS-HOOK-001`, `AS-SKILL-007`, `AS-DEP-001`, `AS-MCP-004/005` |
| `excessive_privilege` | Artifact grants broader standing authority than the task needs | `AS-PERM-001/002`, `AS-AGENT-001`, `AS-SKILL-004/005/008` |
| `injection_surface` | Untrusted content can redirect agent behavior via context it's designed to act on | `AS-PROMPT-001`, `AS-HOOK-003`, `AS-SKILL-002/010` |
| `data_exposure` | Secret/sensitive data reachable by the agent or crossing the trust boundary | `AS-MCP-001/002`, `AS-ENV-001`, `AS-SECRET-001` |
| `persistence` | Compromise survives beyond a single session or skill install | `AS-SKILL-001` |
| `governance_gap` | Missing provenance/signature/version — not an active exploit, removes detectability | `AS-SKILL-003/006/009/011/012` |
| `hygiene` | Real but low agentic amplification (bounds blast radius rather than enabling it) | `AS-HOOK-004` |

The full mapping and vectors are in `src/agentscanner/aivss.py` (`CHECK_ARCHETYPES`, `_ARCHETYPES`) — read the source, not this table, for the authoritative values; a test (`tests/test_aivss.py::test_every_registered_check_has_an_archetype`) fails CI if a new check ships without one.

## Usage

```bash
agentscanner scan . --aivss                       # add AIVSS column/field, default ThM=0.97
agentscanner scan . --aivss --aivss-thm 1.0        # known actively-exploited technique
agentscanner scan . --aivss --output json          # adds an "aivss" object per finding
```

Not yet in `--output sarif` — SARIF 2.1.0's result shape doesn't have a natural slot for a second numeric score; open to adding it as a property bag if that's useful.

## Reproducing the number

Given a check ID, severity, and ThM, the score is pure arithmetic — no LLM call, no network, no randomness:

```python
from agentscanner import aivss
from agentscanner.models import Severity

result = aivss.score_finding("AS-HOOK-001", Severity.CRITICAL, thm=0.97)
print(result.score, result.vector)  # 7.0 (CVSS:9.5/AARS:5.0)xThM:0.97
```
