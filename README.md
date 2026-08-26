<p align="center">
  <img src="assets/banner.png" alt="aisecscan — static security scanner for AI/LLM/agentic repos" width="100%">
</p>

# aisecscan

**Static security scanner for AI/LLM/agentic repos** — the config and code
that make an AI agent do things: settings, permissions, hooks, MCP servers,
agents/subagents, skills, slash commands, and `CLAUDE.md`. Think *Checkov /
Terrascan, but for your AI stack.*

> **v1.0 scope:** full check coverage today is Claude Code (`.claude/`,
> `.mcp.json`, `CLAUDE.md`). Discovery for other AI coding assistants (Cursor,
> Copilot, Windsurf, Cline) plus LLM app-code and AI-supply-chain checks are
> on the roadmap — see [Roadmap](#roadmap) below. Renamed from `agentscanner`
> to reflect that direction.

AI coding assistants are customized through powerful, trust-bearing artifacts: a
hook is arbitrary code that runs on every tool call; an MCP server is an arbitrary
process; a permission rule decides what the agent may do without asking; a skill
or steering file (`CLAUDE.md`, `.cursor/rules`, ...) is untrusted text that
steers the model. Misconfigurations and malicious contributions create real
risk — code execution, credential exfil, permission bypass, supply-chain
compromise, and prompt injection. `aisecscan` finds them, and maps findings to
OWASP's LLM/Agentic/Agentic-Skills Top 10 and AIVSS severity where applicable.

## Core safety invariant

> **aisecscan never executes what it parses.** It does not run hook commands,
> launch MCP servers, resolve `apiKeyHelper`/`statusLine` scripts, or fetch any
> URL. It reads untrusted config as *data only* — the moment a scanner execs its
> input, it becomes the vulnerability.

## Install

```bash
pip install aisecscan        # or: pipx install aisecscan / uvx aisecscan
```

## Usage

```bash
aisecscan scan .                       # scan the current repo's .claude/, .mcp.json, CLAUDE.md
aisecscan scan . --include-user        # also scan ~/.claude (user scope)
aisecscan scan . --severity-threshold HIGH
aisecscan scan . --output sarif --output-file aisecscan.sarif   # for GitHub code scanning
aisecscan scan . --fail-on HIGH        # CI gate: nonzero exit on HIGH+ findings
aisecscan list-checks                  # show the check catalog
```

Every resource is tagged with its **scope** (project / local / user / managed /
plugin), so a single run cleanly covers a repo, your global config, or both.

## Check catalog (v1)

| ID | Severity | What it catches |
|---|---|---|
| `AS-HOOK-001` | CRITICAL | Hook fetches & executes remote code (`curl\|sh`, `eval $(curl)`) |
| `AS-HOOK-002` | HIGH | Hook runs a script from a relative / world-writable path |
| `AS-HOOK-003` | MEDIUM | Context-injecting hook (SessionStart/UserPromptSubmit) makes network calls |
| `AS-HOOK-004` | LOW | Hook has no `timeout` |
| `AS-PERM-001` | HIGH | `defaultMode: bypassPermissions` / `acceptEdits` weakens prompts |
| `AS-PERM-002` | HIGH | Overly broad Bash allow (`Bash(*)`, `Bash(:*)`) |
| `AS-PERM-003` | MEDIUM | Dangerous command allowed unscoped (`curl`, `sudo`, `rm`, `eval`, …) |
| `AS-MCP-001` | HIGH | Plaintext secret in MCP server `env` |
| `AS-MCP-002` | HIGH | Remote MCP server over cleartext `http://` |
| `AS-MCP-003` | HIGH | `enableAllProjectMcpServers: true` (auto-trust all project MCP) |
| `AS-MCP-004` | MEDIUM | stdio MCP pulls an unpinned remote package (`npx -y pkg`) |
| `AS-ENV-001` | HIGH | API endpoint/token redirected away from Anthropic |
| `AS-SECRET-001` | HIGH | Hardcoded secret/API key in a config file |
| `AS-AGENT-001` | HIGH | Over-privileged agent/skill (`bypassPermissions`, `tools: *`) |
| `AS-PROMPT-001` | MEDIUM | Prompt-injection / hidden-unicode indicators in steering files |
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

See [`DESIGN.md`](DESIGN.md) for the architecture, threat model, and the verified
Claude Code semantics the permission checks are grounded in. A secure baseline
config lives in [`hardened/`](hardened/).

## CI

GitHub Actions (SARIF upload to code scanning):

```yaml
- run: pipx install aisecscan
- run: aisecscan scan . --output sarif --output-file aisecscan.sarif --soft-fail
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: aisecscan.sarif }
```

pre-commit:

```yaml
- repo: local
  hooks:
    - id: aisecscan
      name: aisecscan
      entry: aisecscan scan . --fail-on HIGH
      language: system
      pass_filenames: false
```

## Roadmap

- **Multi-assistant discovery** — Cursor `.cursor/rules`, GitHub Copilot instructions, Windsurf, Cline configs, alongside Claude Code (not just `.claude/`).
- **LLM app-code checks** — unsafe prompt concatenation of untrusted input, hardcoded model API keys, missing/unsafe output handling.
- **AI supply-chain checks** — model source pinning/provenance, unpinned model/skill registries; cross-links to [`ModelScan`](https://github.com/protectai/modelscan) for model-file deserialization rather than duplicating it.
- **Zero-trust / agent-identity checks** — shared credentials across agent identities, no credential TTL/refresh, confused-deputy pattern (untrusted-input ingestion + write/publish capability with no re-authorization gate), permission inheritance on sub-agent spawn. Maps to OWASP Agentic Top 10 ASI03 (Identity and Privilege Abuse) and AIVSS Agent Identity Impersonation / Agent Untraceability.

Track progress and file requests in [Issues](https://github.com/jassics/aisecscan/issues).

## Prior art & license

Inspired by [`awesome-claude-security`](https://github.com/jassics/awesome-claude-security)
(used as inspiration and as a corpus to scan, not as a source of rule text).
All rules are independently authored. **License: Apache-2.0.**
