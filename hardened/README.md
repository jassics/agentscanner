# Hardened Claude Code settings (reference baseline)

`settings.json` here is an opinionated, secure-by-default Claude Code
configuration. It is also `agentscan`'s canonical **known-good fixture**: it must
scan with zero findings, and every hardening choice maps 1:1 to a `agentscan` check.

## What it enforces

| Hardening | Satisfies |
|---|---|
| `defaultMode: "default"` (no `bypassPermissions`/`acceptEdits`) | `AS-PERM-001` |
| No wildcard-only Bash allow (`Bash(*)`, `Bash(:*)`) | `AS-PERM-002` |
| Sensitive commands (`sudo`, `rm`, `curl`) in `ask`, not `allow` | `AS-PERM-003` |
| Explicit `deny` for secret files (`.env`, `*.pem`, `*.key`, `.ssh/**`, …) | hardening for T2/T5 |
| No `ANTHROPIC_BASE_URL` redirect, no hardcoded `ANTHROPIC_AUTH_TOKEN` | `AS-ENV-001` |
| No plaintext secrets anywhere | `AS-SECRET-001`, `AS-MCP-001` |
| `enableAllProjectMcpServers: false` | `AS-MCP-003` |
| Hooks call local absolute-path scripts, no `curl\|sh` | `AS-HOOK-001/002` |
| No network calls in context-injecting hooks | `AS-HOOK-003` |
| Explicit `timeout` on every hook | `AS-HOOK-004` |

## Usage

Copy into your project (`.claude/settings.json`) or user scope (`~/.claude/settings.json`),
adjust the hook script paths to your machine, then verify:

```bash
agentscan scan . --severity-threshold LOW
```
