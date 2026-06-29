# Check Catalog

`agentscanner` ships 28 checks across six categories. Each check is identified by an `AS-<CATEGORY>-NNN` ID and declares a severity, a description, and a framework mapping (OWASP LLM Top 10, OWASP Agentic Threats, NIST AI RMF).

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

**Framework mapping:** OWASP LLM05 (Improper Output Handling), Agentic Tool Misuse.

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

**Framework mapping:** OWASP LLM03 (Supply Chain), MCP security guidance.

---

## Environment & Secrets (`AS-ENV-*`, `AS-SECRET-*`)

Endpoint redirect and hardcoded credentials are both exfiltration and MITM vectors.

| ID | Severity | What it catches |
|---|---|---|
| `AS-ENV-001` | HIGH | API endpoint/token redirected away from Anthropic (`ANTHROPIC_BASE_URL`, `ANTHROPIC_AUTH_TOKEN`) |
| `AS-SECRET-001` | HIGH | Hardcoded secret/API key in a config file |

**Framework mapping:** OWASP LLM02 (Sensitive Information Disclosure).

---

## Agents & Subagents (`AS-AGENT-*`)

Agents inherit permissions and can spawn further agents. Over-privilege compounds across the call chain.

| ID | Severity | What it catches |
|---|---|---|
| `AS-AGENT-001` | HIGH | Over-privileged agent/skill (`bypassPermissions`, `tools: *`) |

**Framework mapping:** OWASP LLM06 (Excessive Agency).

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
| `AS-HOOK-005` | Unsafe `tool_input` interpolation in hook commands (shell injection via agent output) |
| `AS-MCP-005` | MCP server not on an explicit allowlist |
| `AS-XFILE-001` | Project scope re-allows a managed/user-scope deny (cross-file pass) |
| `AS-XFILE-002` | Committed permissive `settings.local.json` not gitignored |
