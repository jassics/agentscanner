# Claude Code Configuration Security Scanner — Design Document

> Working title: **`agentscanner`** (Claude + audit). A Checkov/Terrascan-style static
> analyzer for Claude Code configuration artifacts: settings, permissions, hooks,
> MCP servers, agents/subagents, skills, slash commands, and `CLAUDE.md` memory.

Status: **DRAFT for review** · Owner: sanjeev.k2 · Last updated: 2026-06-15

---

## 1. Problem statement

Developers and product teams increasingly drive their SDLC through Claude Code,
customizing it with `settings.json`, hooks, skills, subagents, MCP servers, and
`CLAUDE.md` instructions — at **global (`~/.claude`), project (`.claude/`), local,
and enterprise/managed** scopes. These artifacts are *powerful by design*: a hook
is arbitrary code that runs on every tool call; an MCP server is an arbitrary
process; a permission rule decides what the agent may do without asking; a skill
or `CLAUDE.md` is untrusted text that steers the model.

Misconfigurations and malicious contributions in these files create real risk:
**code execution, credential exfiltration, permission bypass, supply-chain
compromise, and prompt injection** — yet there is no `checkov` for them. Reviewers
eyeball JSON and Markdown by hand, and CI has nothing to gate on.

`agentscanner` fills that gap: a fast, **static, read-only** scanner that discovers
Claude Code artifacts, evaluates them against a curated policy catalog, and emits
prioritized, framework-mapped findings (CLI table, JSON, SARIF) suitable for local
use, pre-commit, and CI.

### Non-goals (v1)
- Not a runtime/EDR monitor — it does not observe a live Claude Code session.
- Not a full "effective permission" simulator — cross-file precedence is handled by
  a *targeted* check class, not a complete merge engine (see §6, deferred to v2).
- Not an LLM-based reviewer — checks are deterministic. (An optional
  `--llm-assist` triage pass is a roadmap item, off by default.)

---

## 2. Core security invariant — the scanner never executes what it parses

`agentscanner` ingests *untrusted* config and prompt files. The single most important
property: **it MUST NOT execute, source, shell-expand, resolve, or network-fetch
anything it reads.**

- No running hook commands, `apiKeyHelper`, `statusLine`, or `awsCredentialExport`
  scripts.
- No launching MCP servers (`command`/`args` are inspected as data, never spawned).
- No shell evaluation of interpolated strings; no `eval`, no `subprocess` of parsed
  content; no following of `url`/`command` targets over the network.
- File reads are bounded (size cap, no symlink-following outside the scan root).

This is both a safety property (the moment a scanner execs untrusted input, it
*becomes* the vulnerability) and a selling point we state in the README.

---

## 3. What we scan (artifact taxonomy)

Grounded in the **current** Claude Code schema (verified against live docs,
2026-06; see §11 sources), not memory.

| Artifact | Locations (user / project / local / managed / plugin) | Format | Why it matters |
|---|---|---|---|
| **Settings** | `~/.claude/settings.json`, `.claude/settings.json`, `.claude/settings.local.json`, managed `/managed-settings.json`, plugin settings | JSON | permissions, hooks, env, MCP, code-exec helpers, permission mode |
| **Hooks** | inside settings (`hooks`), agent frontmatter (`hooks`) | JSON | arbitrary command/http/mcp/agent execution at 30+ lifecycle events |
| **MCP servers** | `.mcp.json`, settings `mcpServers`, agent `mcpServers` | JSON | arbitrary process / remote endpoint; plaintext secrets; supply chain |
| **Agents / subagents** | `~/.claude/agents/*.md`, `.claude/agents/*.md`, plugin `agents/` | Markdown + YAML frontmatter | tool grants, `permissionMode`, model, prompt content |
| **Skills** | `~/.claude/skills/*/SKILL.md`, `.claude/skills/...`, plugin `skills/` | Markdown + YAML frontmatter | `allowed-tools`, auto-invocation, prompt content |
| **Slash commands** | `~/.claude/commands/*.md`, `.claude/commands/*.md` | Markdown + (optional) frontmatter | `allowed-tools`, prompt content |
| **Memory / instructions** | `CLAUDE.md`, `.claude/CLAUDE.md`, imported memory files | Markdown | prompt-injection / steering vector |
| **Plugin manifest** | `.claude-plugin/marketplace.json`, `plugin.json` | JSON | provenance / trust of bundled artifacts |

---

## 4. Threat model (what the checks defend against)

Mapped to OWASP LLM Top 10, OWASP Agentic threats, and NIST AI RMF where relevant.

| # | Threat | Example | Primary framework |
|---|---|---|---|
| T1 | **Arbitrary code execution via hooks/helpers** | hook runs `curl … \| sh`; `apiKeyHelper` points to a fetched script | OWASP LLM05 (Improper Output Handling) / Agentic "tool misuse" |
| T2 | **Permission over-grant** | `Bash(*)`, `Bash(curl:*)`, unscoped `sudo`/`rm`/`eval` in `allow` | Agentic "excessive autonomy"; LLM06 Excessive Agency |
| T3 | **Permission bypass / weakened posture** | `defaultMode: bypassPermissions`, `dontAsk` misuse, project file re-allowing a managed/user deny | LLM06; NIST GOVERN/MANAGE |
| T4 | **Credential exfil / MITM via endpoint redirect** | `ANTHROPIC_BASE_URL`/`ANTHROPIC_AUTH_TOKEN` pointed at a non-Anthropic host | LLM02 Sensitive Info Disclosure |
| T5 | **Hardcoded secrets** | plaintext API keys/tokens in `env`, MCP `env`, settings | LLM02 |
| T6 | **MCP supply chain / untrusted server** | `npx -y`/`uvx` unpinned remote package; auto-trust all project MCP; remote `http://` MCP | LLM03 Supply Chain; MCP guidance |
| T7 | **Prompt injection in steering files** | `CLAUDE.md`/skill/agent text saying "ignore previous instructions", "disable hooks", exfil instructions; zero-width/bidi unicode | LLM01 Prompt Injection |
| T8 | **Over-privileged agents/skills** | agent `tools: *` + `permissionMode: bypassPermissions`; skill auto-invocable with broad tools | LLM06 Excessive Agency |
| T9 | **Hook command/shell injection** | hook does `sh -c "… $tool_input …"` interpolating untrusted input | LLM05 |

---

## 5. Check catalog (v1 MVP — high precision over breadth)

IDs follow **`CC-<CATEGORY>-NNN`** (CC = Claude Code). Each check declares the
resource type(s) it applies to, a severity, a message, a remediation, and a
framework mapping. Severities: `CRITICAL / HIGH / MEDIUM / LOW / INFO`.

**MVP set (~14, implemented first):**

| ID | Severity | Title | Applies to |
|---|---|---|---|
| `AS-HOOK-001` | CRITICAL | Hook fetches & executes remote code (`curl\|sh`, `wget\|sh`, `eval $(curl)`) | hooks |
| `AS-HOOK-002` | HIGH | Hook command runs script from relative/world-writable/untrusted path | hooks |
| `AS-HOOK-003` | MEDIUM | Context-injecting hook (SessionStart/UserPromptSubmit/InstructionsLoaded) makes network calls | hooks |
| `AS-HOOK-004` | LOW | Hook has no `timeout` (or excessive timeout) | hooks |
| `AS-PERM-001` | HIGH | Permission mode weakens prompts (`bypassPermissions` / `dontAsk` as default) | settings |
| `AS-PERM-002` | HIGH | Overly broad Bash allow (`Bash(*)`, `Bash(:*)`, bare-wildcard rules) | settings |
| `AS-PERM-003` | MEDIUM | Dangerous command allowed unscoped (`curl`, `sudo`, `rm`, `eval`, `chmod`, `nc`) | settings |
| `AS-MCP-001` | HIGH | Plaintext secret in MCP `env` (key/token pattern) | mcp |
| `AS-MCP-002` | HIGH | Remote MCP server over non-HTTPS `http://` | mcp |
| `AS-MCP-003` | HIGH | `enableAllProjectMcpServers: true` (auto-trusts all project MCP) | settings |
| `AS-MCP-004` | MEDIUM | stdio MCP uses unpinned remote fetch (`npx -y`, `uvx` w/o version) | mcp |
| `AS-ENV-001` | HIGH | API endpoint/token redirected to non-Anthropic host (`ANTHROPIC_BASE_URL`/`_AUTH_TOKEN`) | settings |
| `AS-SECRET-001` | HIGH | Hardcoded secret/API key anywhere in a config file | settings, mcp, agent |
| `AS-AGENT-001` | HIGH | Over-privileged agent/skill (`tools: *`/`All` **and** `permissionMode: bypassPermissions`/`acceptEdits`) | agent, skill |
| `AS-PROMPT-001` | MEDIUM | Prompt-injection / steering indicators in `CLAUDE.md`/skill/agent (incl. zero-width & bidi unicode) | agent, skill, command, memory |

**Roadmap (v1.x / v2):** `AS-ENV-002` (code-exec helpers `apiKeyHelper`/`statusLine`/`awsCredentialExport` → review), `AS-HOOK-005` (unsafe `tool_input` interpolation), `AS-MCP-005` (unknown/untrusted server vs. allowlist), `CC-XFILE-001` (project re-allows a denied rule — needs cross-file pass), `CC-XFILE-002` (committed permissive `settings.local.json` not gitignored), `AS-PROMPT-002` (large base64/obfuscated blobs).

> **Bypass checks rest on verified matching semantics, not guesses.** Claude Code
> matches Bash rules with space-boundary-aware wildcards, splits compound commands
> on `&& || ; | & \n` and matches each subcommand independently, strips a fixed set
> of wrappers (`timeout`, `nice`, …) but NOT `npx`/`docker exec`, and resolves
> `deny > ask > allow` with managed scope unoverridable. `AS-PERM-002/003` encode
> exactly this so we don't ship confident false positives (see §11).

---

## 6. Architecture

```
                 ┌────────────┐
  scan target →  │ Discovery  │  walk user/project/local/managed/plugin scopes,
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
                 │  Findings  │  inline `# agentscanner:ignore CC-XXX` directives
                 └─────┬──────┘
                       │
                 ┌─────▼──────┐  CLI table · JSON · SARIF (GitHub code scanning)
                 │ Reporters  │  exit code from --fail-on / --soft-fail
                 └────────────┘
```

### Key design decisions (locked now — costly to retrofit)
1. **Line mapping is in the IR from day one.** Every `Resource` carries a
   `value → (line, col)` index. JSON via a position-preserving parse; YAML
   frontmatter via `ruamel.yaml` (line-aware). Findings always cite `file:line`.
2. **Per-file scanning for v1.** No global effective-merge resolver. Cross-file
   posture issues (project re-allowing a managed/user deny) are a *separate check
   class* run after all files parse — explicitly deferred to v2 to bound scope.
3. **Curated, high-precision MVP** (~14 checks). Noise on day one kills adoption;
   breadth is additive later.
4. **Two check authoring styles.** (a) Python `Check` subclasses for logic-heavy
   rules; (b) declarative **YAML policies** (jsonpath/regex/conditions) for simple,
   community-contributable rules — loaded from a built-in dir and `--policy-dir`.
5. **Rules are independently authored.** The `awesome-claude-security` repo
   (GPL-3.0) is used as *inspiration and as a fixture corpus to scan*, never as
   copied rule text/taxonomy — keeping `agentscanner` free to license permissively
   (Apache-2.0 proposed). See §10.

### Module layout
```
src/agentscanner/
  cli.py            # Typer CLI
  models.py         # Severity, ArtifactType, Resource (IR), Finding
  discovery.py      # scope walking + classification
  parsers/          # json_parser.py (line-aware), markdown_parser.py (frontmatter)
  checks/
    base.py         # Check ABC + @register; severity/framework metadata
    permissions.py  mcp.py  hooks.py  env_secrets.py  agents_skills.py  prompts.py
  policies/         # built-in declarative YAML rules
  reporters/        # cli.py  json.py  sarif.py
  data/             # secret regexes, dangerous-command list, allow/deny patterns
hardened/           # reference hardened settings (item 5) — the canonical GOOD fixture
tests/fixtures/{bad,good}/   # paired per-check fixtures (see §8)
```

---

## 7. CLI UX (Checkov-flavored)

```
agentscanner scan [PATH]                 # default: scan ./ (+ optional --include-user)
  --include-user                    # also scan ~/.claude
  --framework all|settings|hooks|mcp|agents|skills|prompts
  --check AS-HOOK-001,...           # run only these
  --skip-check AS-PERM-003,...      # skip these
  --severity-threshold HIGH         # only report >= threshold
  --output cli|json|sarif           # default cli
  --output-file results.sarif
  --baseline .agentscanner.baseline.json # suppress known/accepted findings
  --config .agentscanner.yaml            # project config (skips, thresholds, policy-dir)
  --policy-dir ./policies           # load custom YAML policies
  --fail-on HIGH                    # exit nonzero if any finding >= level (CI gate)
  --soft-fail                       # always exit 0
agentscanner list-checks                 # print catalog (id, severity, title)
agentscanner version
```

> **v1 implements a subset of the flags above.** Shipped now: `scan` (with
> `--include-user`, `--check`, `--skip-check`, `--severity-threshold`, `--output`
> cli/json/sarif, `--output-file`, `--fail-on`, `--soft-fail`), `list-checks`,
> `version`. **Roadmap:** `--baseline`, `--config`, `--policy-dir` and the
> declarative-YAML policy engine (the `policies/` dir). v1 ships Python-coded
> checks only; shared patterns live in `data.py` (not a separate `data/` dir).
Distribution: **PyPI** (`pip install agentscanner` / `pipx`/`uvx`), plus a published
**pre-commit hook** and a **GitHub Action** wrapper. Python 3.9+.

---

## 8. Verification plan (item 3)

**Paired fixtures, not one clean run.** `tests/fixtures/bad/` has one minimal
artifact per check that MUST trigger exactly that finding; `tests/fixtures/good/`
holds clean artifacts that MUST scan with zero findings. The **`hardened/`
reference settings are the canonical known-good fixture**, and every hardening
choice maps 1:1 to a check — the hardened config and the catalog are duals.

Additional verification:
- Run `agentscanner` against **real corpora**: this machine's `~/.claude` (settings,
  hooks, agents, skills) and a checkout of `awesome-claude-security` — confirm
  signal, measure false-positive rate, hand-triage.
- Golden-output snapshot tests for JSON/SARIF.
- SARIF validated against the schema so GitHub code scanning ingests it.

---

## 9. Hardened reference settings (item 5)

Ship `hardened/settings.json` (+ commentary in `hardened/README.md`) as an
opinionated secure baseline teams can adopt: explicit `deny` for secret-file
reads/edits, scoped `ask` for `sudo`/`git push`, no `bypassPermissions` default,
no endpoint redirection, fail-open security hooks with timeouts, pinned MCP
servers, and no plaintext secrets. Each line is annotated with the `CC-*` check it
satisfies, making the file both documentation and the primary good-fixture.

---

## 10. Licensing & provenance

- **`agentscanner` license: Apache-2.0** (permissive; PyPI-friendly).
- `awesome-claude-security` is **GPL-3.0**. We treat it strictly as *inspiration*
  and as an input corpus to scan; we do **not** copy its rule text, taxonomy, or
  structure into the package (which could force GPL on `agentscanner`). Cited as prior
  art in README, not vendored.

---

## 11. Sources (verified, current as of 2026-06)

Permission/settings/hook/agent semantics confirmed against live Claude Code docs
(`code.claude.com/docs`: `permissions`, `settings`, `env-vars`, `hooks`,
`mcp-quickstart`, `sub-agents`, `commands`). Threat framing draws on the curated
AI-security corpus: OWASP LLM Top 10 (`LLMAll_en-US_FINAL.pdf`), OWASP Agentic
threats (`Agentic-AI-Threats-and-Mitigations_v1.0a.pdf`,
`OWASP-Top-10-for-Agentic-Applications-2026-12.6-1.pdf`), MCP security
(`A-Practical-Guide-for-Secure-MCP-Server-Development…pdf`,
`…Securely-Using-third-party-MCP-Servers1.0.pdf`), and NIST AI RMF
(`AI_RMF_Playbook.pdf`).

Key verified semantics encoded by checks:
- Bash rule wildcards are space-boundary aware (`Bash(ls:*)` ≠ `lsof`); compound
  commands split on `&& || ; | & \n`, each subcommand matched independently;
  wrappers `timeout/time/nice/nohup/stdbuf/xargs` stripped, but `npx/docker exec/
  uvx` are NOT.
- Resolution order **deny → ask → allow**; scope precedence **managed > CLI >
  local > project > user**; managed deny is unoverridable.
- Permission modes: `default, acceptEdits, plan, auto, dontAsk, bypassPermissions`;
  `--dangerously-skip-permissions` = session `bypassPermissions`.
- Code-exec settings keys: `hooks, apiKeyHelper, awsCredentialExport,
  awsAuthRefresh, gcpAuthRefresh, otelHeadersHelper, statusLine, mcpServers`.
- Posture env vars: `ANTHROPIC_BASE_URL, ANTHROPIC_AUTH_TOKEN, ANTHROPIC_API_KEY`,
  `CLAUDE_CODE_CERT_STORE`, `DISABLE_*`.
- 30+ hook events; context-injecting ones (SessionStart, UserPromptSubmit,
  InstructionsLoaded) add stdout to model context (injection-relevant).
```
