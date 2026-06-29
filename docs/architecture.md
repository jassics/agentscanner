# Architecture

## Problem statement

Developers and product teams increasingly drive their SDLC through Claude Code, customizing it with `settings.json`, hooks, skills, subagents, MCP servers, and `CLAUDE.md` instructions — at **global (`~/.claude`), project (`.claude/`), local, and enterprise/managed** scopes. These artifacts are *powerful by design*: a hook is arbitrary code that runs on every tool call; an MCP server is an arbitrary process; a permission rule decides what the agent may do without asking; a skill or `CLAUDE.md` is untrusted text that steers the model.

Misconfigurations and malicious contributions in these files create real risk: **code execution, credential exfiltration, permission bypass, supply-chain compromise, and prompt injection** — yet there is no `checkov` for them. Reviewers eyeball JSON and Markdown by hand, and CI has nothing to gate on.

`agentscanner` fills that gap: a fast, **static, read-only** scanner that discovers Claude Code artifacts, evaluates them against a curated policy catalog, and emits prioritized, framework-mapped findings (CLI table, JSON, SARIF) suitable for local use, pre-commit, and CI.

### Non-goals (v1)

- Not a runtime/EDR monitor — it does not observe a live Claude Code session.
- Not a full "effective permission" simulator — cross-file precedence is handled by a *targeted* check class, not a complete merge engine (deferred to v2).
- Not an LLM-based reviewer — checks are deterministic. (An optional `--llm-assist` triage pass is a roadmap item, off by default.)

---

## Core security invariant

!!! danger "The scanner never executes what it parses"
    `agentscanner` ingests *untrusted* config and prompt files. The single most important property: **it MUST NOT execute, source, shell-expand, resolve, or network-fetch anything it reads.**

    - No running hook commands, `apiKeyHelper`, `statusLine`, or `awsCredentialExport` scripts.
    - No launching MCP servers (`command`/`args` are inspected as data, never spawned).
    - No shell evaluation of interpolated strings; no `eval`, no `subprocess` of parsed content; no following of `url`/`command` targets over the network.
    - File reads are bounded (size cap, no symlink-following outside the scan root).

    This is both a safety property (the moment a scanner execs untrusted input, it *becomes* the vulnerability) and a selling point.

---

## Artifact taxonomy

| Artifact | Locations | Format | Why it matters |
|---|---|---|---|
| **Settings** | `~/.claude/settings.json`, `.claude/settings.json`, `.claude/settings.local.json`, managed `/managed-settings.json`, plugin settings | JSON | permissions, hooks, env, MCP, code-exec helpers, permission mode |
| **Hooks** | inside settings (`hooks`), agent frontmatter (`hooks`) | JSON | arbitrary command/http/mcp/agent execution at 30+ lifecycle events |
| **MCP servers** | `.mcp.json`, settings `mcpServers`, agent `mcpServers` | JSON | arbitrary process / remote endpoint; plaintext secrets; supply chain |
| **Agents / subagents** | `~/.claude/agents/*.md`, `.claude/agents/*.md`, plugin `agents/` | Markdown + YAML frontmatter | tool grants, `permissionMode`, model, prompt content |
| **Skills** | `~/.claude/skills/*/SKILL.md`, `.claude/skills/...`, plugin `skills/` | Markdown + YAML frontmatter | `allowed-tools`, auto-invocation, prompt content |
| **Slash commands** | `~/.claude/commands/*.md`, `.claude/commands/*.md` | Markdown + optional frontmatter | `allowed-tools`, prompt content |
| **Memory / instructions** | `CLAUDE.md`, `.claude/CLAUDE.md`, imported memory files | Markdown | prompt-injection / steering vector |
| **Plugin manifest** | `.claude-plugin/marketplace.json`, `plugin.json` | JSON | provenance / trust of bundled artifacts |

---

## Threat model

Mapped to OWASP LLM Top 10, OWASP Agentic threats, and NIST AI RMF.

| # | Threat | Example | Framework |
|---|---|---|---|
| T1 | **Arbitrary code execution via hooks/helpers** | Hook runs `curl … \| sh`; `apiKeyHelper` points to a fetched script | OWASP LLM05 / Agentic "tool misuse" |
| T2 | **Permission over-grant** | `Bash(*)`, `Bash(curl:*)`, unscoped `sudo`/`rm`/`eval` in `allow` | Agentic "excessive autonomy"; LLM06 |
| T3 | **Permission bypass / weakened posture** | `defaultMode: bypassPermissions`, `dontAsk` misuse, project re-allows a managed deny | LLM06; NIST GOVERN/MANAGE |
| T4 | **Credential exfil / MITM via endpoint redirect** | `ANTHROPIC_BASE_URL`/`ANTHROPIC_AUTH_TOKEN` pointed at a non-Anthropic host | LLM02 Sensitive Info Disclosure |
| T5 | **Hardcoded secrets** | Plaintext API keys/tokens in `env`, MCP `env`, settings | LLM02 |
| T6 | **MCP supply chain / untrusted server** | `npx -y`/`uvx` unpinned remote package; auto-trust all project MCP; remote `http://` MCP | LLM03 Supply Chain |
| T7 | **Prompt injection in steering files** | `CLAUDE.md`/skill/agent text saying "ignore previous instructions"; zero-width/bidi unicode | LLM01 Prompt Injection |
| T8 | **Over-privileged agents/skills** | Agent `tools: *` + `permissionMode: bypassPermissions` | LLM06 Excessive Agency |
| T9 | **Hook shell injection** | Hook does `sh -c "… $tool_input …"` interpolating untrusted input | LLM05 |

---

## Pipeline

```
             ┌────────────┐
scan target → │ Discovery  │  walk user/project/local/managed/plugin scopes,
              └─────┬──────┘  classify each file → ArtifactType
                    │
              ┌─────▼──────┐
              │  Parsers   │  JSON (position-preserving) + Markdown/YAML
              └─────┬──────┘  frontmatter → normalized IR with line map
                    │
              ┌─────▼──────┐    Resource{ type, path, attrs, raw, line_index }
              │     IR     │
              └─────┬──────┘
                    │
              ┌─────▼──────┐  registry of Check objects; each declares
              │   Engine   │  applies_to + run(resource) → [Finding]
              └─────┬──────┘  (single-file checks now; cross-file class = v2)
                    │
              ┌─────▼──────┐  baseline/suppression, severity threshold,
              │  Findings  │  inline `# agentscanner:ignore AS-XXX` directives
              └─────┬──────┘
                    │
              ┌─────▼──────┐  CLI table · JSON · SARIF (GitHub code scanning)
              │ Reporters  │  exit code from --fail-on / --soft-fail
              └────────────┘
```

### Key design decisions

1. **Line mapping is in the IR from day one.** Every `Resource` carries a `value → (line, col)` index. JSON via a position-preserving parse; YAML frontmatter via `ruamel.yaml` (line-aware). Findings always cite `file:line`.
2. **Per-file scanning for v1.** No global effective-merge resolver. Cross-file posture issues (project re-allowing a managed/user deny) are a *separate check class* run after all files parse — explicitly deferred to v2 to bound scope.
3. **Curated, high-precision MVP** (~28 checks). Noise on day one kills adoption; breadth is additive later.
4. **Two check authoring styles.** (a) Python `Check` subclasses for logic-heavy rules; (b) declarative **YAML policies** (jsonpath/regex/conditions) for simple, community-contributable rules — loaded from a built-in dir and `--policy-dir`.
5. **Rules are independently authored.** The `awesome-claude-security` repo (GPL-3.0) is used as *inspiration and as a fixture corpus to scan*, never as copied rule text — keeping `agentscanner` free to license permissively (Apache-2.0).

---

## Module layout

```
src/agentscanner/
  cli.py            # Typer CLI
  models.py         # Severity, ArtifactType, Resource (IR), Finding
  discovery.py      # scope walking + classification
  parsers/
    json_parser.py  # line-aware JSON parser
    markdown_parser.py  # YAML frontmatter + body extraction
  checks/
    base.py         # Check ABC + @register; severity/framework metadata
    permissions.py  # AS-PERM-*
    mcp.py          # AS-MCP-*
    hooks.py        # AS-HOOK-*
    env_secrets.py  # AS-ENV-*, AS-SECRET-*
    agents_skills.py  # AS-AGENT-*, AS-SKILL-*
    prompts.py      # AS-PROMPT-*
  reporters/        # cli.py  json.py  sarif.py
  data.py           # secret regexes, dangerous-command list, allow/deny patterns

hardened/           # reference hardened settings — canonical known-good fixture
tests/              # pytest suite with paired bad/good fixtures per check
```

---

## Verified semantics

The permission checks are grounded in verified Claude Code behavior, not guesses:

- Bash rule wildcards are **space-boundary aware** (`Bash(ls:*)` does not match `lsof`).
- Compound commands split on `&& || ; | & \n`; each subcommand is matched independently.
- Wrappers `timeout/time/nice/nohup/stdbuf/xargs` are stripped, but `npx/docker exec/uvx` are **NOT**.
- Resolution order: **deny → ask → allow**; scope precedence: **managed > CLI > local > project > user**; managed deny is unoverridable.
- Permission modes: `default, acceptEdits, plan, auto, dontAsk, bypassPermissions`.
- Context-injecting hook events (SessionStart, UserPromptSubmit, InstructionsLoaded) add stdout to model context — these are injection-relevant.
