# Check Catalog

`agentscanner` ships 31 checks across seven categories. Each check is identified by an `AS-<CATEGORY>-NNN` ID and declares a severity, a description, and a framework mapping (OWASP LLM Top 10, OWASP Top 10 for Agentic Applications (ASI01–ASI10), NIST AI RMF).

Most checks catch misconfiguration (over-broad permissions, missing pins, hardcoded secrets). A smaller set targets *agentic attack patterns specifically* — combinations of capabilities that enable goal hijacking, memory poisoning, or rogue-agent behavior even when each individual setting looks reasonable on its own: `AS-AGENT-002` (ASI01 Agent Goal Hijack) and `AS-HOOK-005` (ASI06 Memory & Context Poisoning). These don't require reading a skill's bundled script content — they're detectable from the same frontmatter/config `agentscanner` already parses, by looking at *combinations* of declared capabilities rather than any single one.

Severities: `CRITICAL` › `HIGH` › `MEDIUM` › `LOW`

---

## Hooks (`AS-HOOK-*`)

Hooks are arbitrary shell commands that run at 30+ Claude Code lifecycle events. They are the highest-risk artifact in the config surface.

| ID | Severity | What it catches |
|---|---|---|
| `AS-HOOK-001` | CRITICAL | Hook fetches & executes remote code (`curl\|sh`, `eval $(curl)`) |
| `AS-HOOK-002` | HIGH | Hook runs a script from a relative / world-writable path |
| `AS-HOOK-003` | MEDIUM | Context-injecting hook (SessionStart/UserPromptSubmit) makes network calls |
| `AS-HOOK-004` | LOW | Hook has no `timeout` |
| `AS-HOOK-005` | HIGH | Hook fetches external content and writes it into persistent memory/context (`CLAUDE.md`, `MEMORY.md`, `.claude/memory/*`) |

**Framework mapping:** OWASP LLM05 (Improper Output Handling), Agentic Tool Misuse; `AS-HOOK-005` maps to OWASP Agentic AI Top 10 ASI06 (Memory & Context Poisoning).

`AS-HOOK-005` is distinct from `AS-HOOK-003`: `AS-HOOK-003` flags a context-injecting hook making a network call, which only affects the *current* session's context. `AS-HOOK-005` requires the command to also redirect (`>>`, `>`, `tee`) that fetched content into a persistent memory path — a narrower, higher-confidence pattern because the poisoned content survives and re-influences every future session, not just this one.

---

## Permissions (`AS-PERM-*`)

Permission rules decide what Claude Code may do without asking the user. Over-broad or bypassed rules remove the human-in-the-loop.

| ID | Severity | What it catches |
|---|---|---|
| `AS-PERM-001` | HIGH | `defaultMode: bypassPermissions` / `acceptEdits` weakens prompts |
| `AS-PERM-002` | HIGH | Overly broad Bash allow (`Bash(*)`, `Bash(:*)`) |
| `AS-PERM-003` | MEDIUM | Dangerous command allowed unscoped (`curl`, `sudo`, `rm`, `eval`, …) |

**Framework mapping:** OWASP LLM06 (Excessive Agency), NIST AI RMF GOVERN/MANAGE.

---

## MCP Servers (`AS-MCP-*`)

MCP servers are arbitrary processes (stdio) or remote endpoints (HTTP/SSE) given privileged access to the agent's context. Supply-chain and transport risks are high.

| ID | Severity | What it catches |
|---|---|---|
| `AS-MCP-001` | HIGH | Plaintext secret in MCP server `env` |
| `AS-MCP-002` | HIGH | Remote MCP server over cleartext `http://` |
| `AS-MCP-003` | HIGH | `enableAllProjectMcpServers: true` (auto-trust all project MCP) |
| `AS-MCP-004` | MEDIUM | stdio MCP pulls an unpinned remote package (`npx -y pkg`) |
| `AS-MCP-005` | HIGH* | stdio MCP pins a package with a known vulnerability (live OSV.dev lookup) |

**Framework mapping:** OWASP LLM03 (Supply Chain), MCP security guidance.

\* `AS-MCP-005` severity is taken from the matched OSV advisory (CRITICAL/HIGH/MEDIUM/LOW), not fixed.

---

## Environment & Secrets (`AS-ENV-*`, `AS-SECRET-*`)

Endpoint redirect and hardcoded credentials are both exfiltration and MITM vectors.

| ID | Severity | What it catches |
|---|---|---|
| `AS-ENV-001` | HIGH | API endpoint/token redirected away from Anthropic (`ANTHROPIC_BASE_URL`, `ANTHROPIC_AUTH_TOKEN`) |
| `AS-SECRET-001` | HIGH | Hardcoded secret/API key in a config file |

**Framework mapping:** OWASP LLM02 (Sensitive Information Disclosure).

---

## Dependencies (`AS-DEP-*`)

Skills can bundle a `requirements.txt` or `package.json`. A pinned dependency with a known CVE is a supply-chain risk independent of whether the pin itself is "good practice" (see `AS-MCP-004`, which flags the opposite problem — no pin at all).

| ID | Severity | What it catches |
|---|---|---|
| `AS-DEP-001` | HIGH* | Skill dependency pinned to a version with a known vulnerability (live OSV.dev lookup) |

**Framework mapping:** OWASP LLM03 (Supply Chain).

\* Severity is taken from the matched OSV advisory. Only pinned versions (`pkg==1.2.3`) are checked — OSV lookups need a concrete version to test against an affected range. Unpinned dependencies aren't silently treated as safe; they're simply out of scope for *this* check.

**Network and offline behavior:** this check calls [OSV.dev](https://osv.dev) (no API key required) and caches results to `~/.cache/agentscanner/osv_cache.json` for 24h. Pass `--offline` to skip the lookup entirely — the check then finds nothing rather than reporting stale or fabricated results. Unlike scanners that ship a bundled "offline CVE list," agentscanner does not: a static list goes stale the day it's written and makes an offline scan look identical to a fully-informed one. `--offline` makes the tradeoff explicit instead of hiding it.

---

## Agents & Subagents (`AS-AGENT-*`)

Agents inherit permissions and can spawn further agents. Over-privilege compounds across the call chain.

| ID | Severity | What it catches |
|---|---|---|
| `AS-AGENT-001` | HIGH | Over-privileged agent/skill (`bypassPermissions`, `tools: *`) |
| `AS-AGENT-002` | MEDIUM* | Agent/skill combines an untrusted-input tool (`WebFetch`, `WebSearch`, mail/calendar/feed-like MCP tools) with a high-impact action tool (`Bash`, write/send/pay/deploy/delete-like tools) |

**Framework mapping:** OWASP LLM06 (Excessive Agency); `AS-AGENT-002` maps to OWASP Agentic AI Top 10 ASI01 (Agent Goal Hijack) and LLM01 (Prompt Injection).

\* `AS-AGENT-002` escalates to HIGH when `permissionMode` is `bypassPermissions`/`acceptEdits` (no approval checkpoint at all). This check flags a *combination of capabilities*, not a single bad setting — an agent with `WebFetch` + `Bash` is common and often legitimate; the finding is a prompt to add a human-approval or agent-separation checkpoint per OWASP ASI01 guidance, not necessarily a bug.

---

## Prompts & Steering (`AS-PROMPT-*`)

`CLAUDE.md`, skills, and agents are untrusted text that steers the model. Malicious contributions can inject instructions or hide payloads.

| ID | Severity | What it catches |
|---|---|---|
| `AS-PROMPT-001` | MEDIUM | Prompt-injection / hidden-unicode indicators in steering files |

**Framework mapping:** OWASP LLM01 (Prompt Injection).

---

## Skills (`AS-SKILL-*`)

Skills extend Claude Code's capabilities. Malicious or misconfigured skills can grant shell access, bypass sandboxing, or hide obfuscated payloads.

| ID | Severity | What it catches |
|---|---|---|
| `AS-SKILL-001` | CRITICAL | Skill requests write access to agent identity files |
| `AS-SKILL-002` | HIGH | Skill has a social-engineering `Prerequisites` section with pipe-to-shell |
| `AS-SKILL-003` | HIGH | Universal-Format skill missing a cryptographic signature |
| `AS-SKILL-004` | HIGH | Skill sets `permissions.network: true` (binary boolean, not a domain allowlist) |
| `AS-SKILL-005` | HIGH | Skill declares explicit shell access |
| `AS-SKILL-006` | HIGH | Skill `risk_tier` contradicts declared permissions (risk-tier spoofing) |
| `AS-SKILL-007` | CRITICAL | Skill file contains YAML unsafe-execution tags |
| `AS-SKILL-008` | HIGH | Skill explicitly disables sandboxed execution |
| `AS-SKILL-009` | MEDIUM | Universal-Format skill missing `version` field (update-drift risk) |
| `AS-SKILL-010` | MEDIUM | Skill body contains a standalone base64-encoded block (obfuscated payload) |
| `AS-SKILL-011` | MEDIUM | Universal-Format skill missing `publisher` field (governance gap) |
| `AS-SKILL-012` | MEDIUM | Multi-platform skill missing a signature (security metadata lost in translation) |

**Framework mapping:** OWASP LLM03 (Supply Chain), LLM06 (Excessive Agency), LLM01 (Prompt Injection).

---

## Model sensitivity

Some checks flag content whose real-world exploitability depends on which model executes it — prompt injection, social-engineering framing, obfuscated payloads, and injected hook context are all things a frontier model is more likely to resist than a smaller/less-aligned one. These checks are marked `model_sensitive`: `AS-PROMPT-001`, `AS-HOOK-003`, `AS-SKILL-002`, `AS-SKILL-010`.

**Static (default, deterministic, offline):**

```bash
agentscanner scan . --model-tier low
```

Bumps `model_sensitive` findings one severity level (capped at CRITICAL), reflecting that the content is riskier if it ends up running on a smaller model. `--model-tier high` (the default) leaves severities unchanged. This is a static adjustment based on general model-capability reasoning — it does not test any specific model.

**Dynamic (optional, live, costs tokens — `agentscanner probe`):**

```bash
export ANTHROPIC_API_KEY=sk-ant-...
agentscanner probe . --model claude-haiku-4-5 --model claude-sonnet-5
```

Actually sends each `model_sensitive` finding's content to the named model(s), using your own API key, and has a judge model assess whether the target complied with an embedded instruction rather than just describing it. Reports `VULNERABLE` / `RESISTANT` / `INCONCLUSIVE` per model per finding.

This is a fundamentally different kind of check from everything else in agentscanner: it is non-deterministic (the same content can probe differently across runs), spends tokens, and is never invoked by `scan`. Treat a `probe` result as a signal to investigate, not a definitive verdict — a single judge call can be wrong. It exists because a static scanner cannot answer "does this specific model actually fall for this," only "does this content look like something that would try."

---

## AIVSS scoring

Every check also carries an [OWASP AIVSS-Agentic](https://aivss.owasp.org) score, surfaced with `agentscanner scan --aivss`. This layers agent-specific risk amplification (autonomy, tool use, memory, multi-agent interaction, etc.) on top of `Severity` — see [AIVSS Scoring](aivss.md) for the formula, what's official-spec vs. our own mapping, and how to reproduce a number by hand.

---

## Suppressing findings

Add an inline directive on the offending line to suppress a specific check:

```json
"defaultMode": "acceptEdits"  // agentscanner:ignore AS-PERM-001
```

Or pass `--skip-check AS-PERM-001` on the CLI to skip globally for a run.

---

## Roadmap

Checks planned for v1.x / v2:

| ID | Description |
|---|---|
| `AS-ENV-002` | Code-exec helpers (`apiKeyHelper`, `statusLine`, `awsCredentialExport`) pointing to external scripts |
| `AS-HOOK-006` | Unsafe `tool_input` interpolation in hook commands (shell injection via agent output) |
| `AS-MCP-006` | MCP server not on an explicit allowlist |
| `AS-XFILE-001` | Project scope re-allows a managed/user-scope deny (cross-file pass) |
| `AS-XFILE-002` | Committed permissive `settings.local.json` not gitignored |
| `AS-AGENT-003` | Skill declares both `permissions.network: true` and write access to a memory-persisted path (ASI06, skill-level companion to `AS-HOOK-005`) |
| `AS-AGENT-004` | Multi-agent config with no message-integrity/authentication between agents (ASI07 Insecure Inter-Agent Communication) |
