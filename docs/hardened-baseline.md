# Hardened Baseline

`hardened/settings.json` is an opinionated, secure-by-default Claude Code configuration. It is also `agentscanner`'s canonical **known-good fixture**: it must scan with zero findings, and every hardening choice maps 1:1 to an `agentscanner` check.

## What it enforces

| Hardening | Satisfies |
|---|---|
| `defaultMode: "default"` (no `bypassPermissions`/`acceptEdits`) | `AS-PERM-001` |
| No wildcard-only Bash allow (`Bash(*)`, `Bash(:*)`) | `AS-PERM-002` |
| Sensitive commands (`sudo`, `rm`, `curl`) in `ask`, not `allow` | `AS-PERM-003` |
| Explicit `deny` for secret files (`.env`, `*.pem`, `*.key`, `.ssh/**`, …) | Hardening for T2/T5 |
| No `ANTHROPIC_BASE_URL` redirect, no hardcoded `ANTHROPIC_AUTH_TOKEN` | `AS-ENV-001` |
| No plaintext secrets anywhere | `AS-SECRET-001`, `AS-MCP-001` |
| `enableAllProjectMcpServers: false` | `AS-MCP-003` |
| Hooks call local absolute-path scripts, no `curl\|sh` | `AS-HOOK-001/002` |
| No network calls in context-injecting hooks | `AS-HOOK-003` |
| Explicit `timeout` on every hook | `AS-HOOK-004` |

## Usage

Copy into your project (`.claude/settings.json`) or user scope (`~/.claude/settings.json`), adjust the hook script paths to your machine, then verify:

```bash
agentscanner scan . --severity-threshold LOW
```

A clean run (zero findings) confirms the hardened config is intact. Any finding indicates a deviation from the baseline.

## Using it as a CI gate

```bash
# Fail if the committed settings deviate from hardened baseline on any severity
agentscanner scan . --fail-on LOW
```

## Adopting incrementally

If you can't adopt the full baseline immediately, start by gating on CRITICAL and HIGH:

```bash
agentscanner scan . --fail-on HIGH
```

Then tighten the threshold over time as you address MEDIUM and LOW findings.

!!! tip
    The `hardened/` directory also serves as the canonical good-fixture for the test suite. Every check has a paired bad fixture (in `tests/fixtures/bad/`) that *must* trigger, and the hardened config as the good fixture that *must not* trigger anything. This dual-fixture approach is the primary false-positive control.
