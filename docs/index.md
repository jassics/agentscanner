# agentscanner

**Static security scanner for Claude Code configuration** — settings, permissions, hooks, MCP servers, agents/subagents, skills, slash commands, and `CLAUDE.md`. Think *Checkov / Terrascan, but for your `.claude/` directory.*

Claude Code is customized through powerful, trust-bearing artifacts: a hook is arbitrary code that runs on every tool call; an MCP server is an arbitrary process; a permission rule decides what the agent may do without asking; a skill or `CLAUDE.md` is untrusted text that steers the model. Misconfigurations and malicious contributions create real risk — code execution, credential exfil, permission bypass, supply-chain compromise, and prompt injection. `agentscanner` finds them.

## Core safety invariant

!!! important
    **agentscanner never executes what it parses.** It does not run hook commands, launch MCP servers, resolve `apiKeyHelper`/`statusLine` scripts, or fetch any URL. It reads untrusted config as *data only* — the moment a scanner execs its input, it becomes the vulnerability.

## Install

```bash
pip install agentscanner        # standard
pipx install agentscanner       # isolated env (recommended for CLI tools)
uvx agentscanner                # ephemeral run — no install needed
```

## Quick start

```bash
# Scan the current repo's .claude/, .mcp.json, CLAUDE.md
agentscanner scan .

# Also scan your ~/.claude (user scope)
agentscanner scan . --include-user

# Only report HIGH and above
agentscanner scan . --severity-threshold HIGH

# CI gate: nonzero exit on any HIGH+ finding
agentscanner scan . --fail-on HIGH

# SARIF output for GitHub code scanning
agentscanner scan . --output sarif --output-file agentscanner.sarif

# Browse the full check catalog
agentscanner list-checks
```

Every resource is tagged with its **scope** (project / local / user / managed / plugin), so a single run cleanly covers a repo, your global config, or both.

## What it scans

| Artifact | Locations | Threats it catches |
|---|---|---|
| Settings | `.claude/settings.json`, `~/.claude/settings.json` | Permission bypass, endpoint redirect, secrets |
| Hooks | `hooks` key in settings, agent frontmatter | Remote code exec, shell injection, network calls |
| MCP servers | `.mcp.json`, settings `mcpServers` | Plaintext secrets, cleartext transport, unpinned packages |
| Agents / subagents | `.claude/agents/*.md` | Over-privilege, prompt injection |
| Skills | `.claude/skills/*/SKILL.md` | Shell access, unsigned code, obfuscated payloads |
| Memory / steering | `CLAUDE.md`, imported memory | Prompt injection, hidden unicode |

See the [Check Catalog](checks.md) for the full list of 28 checks, or the [Architecture](architecture.md) page for the threat model and design rationale.

## Prior art & license

Inspired by [`awesome-claude-security`](https://github.com/jassics/awesome-claude-security) (used as inspiration and as a corpus to scan, not as a source of rule text). All rules are independently authored. **License: Apache-2.0.**
