# CI Integration

## CLI reference

```
agentscanner scan [PATH]
  --include-user              also scan ~/.claude (user scope)
  --framework all|settings|hooks|mcp|agents|skills|prompts
  --check AS-HOOK-001,...     run only these checks
  --skip-check AS-PERM-003,...  skip these checks
  --severity-threshold HIGH   only report findings >= threshold
  --output cli|json|sarif     output format (default: cli)
  --output-file results.sarif write output to file
  --fail-on HIGH              exit nonzero if any finding >= level
  --soft-fail                 always exit 0 (useful for SARIF-only pipelines)

agentscanner list-checks      print catalog (id, severity, title)
agentscanner version
```

---

## GitHub Actions — SARIF upload

Upload findings to GitHub code scanning so they appear as security alerts on PRs and in the Security tab.

```yaml
name: agentscanner

on:
  push:
    branches: [main]
  pull_request:

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - run: pipx install agentscanner
      - run: agentscanner scan . --output sarif --output-file agentscanner.sarif --soft-fail
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: agentscanner.sarif
```

`--soft-fail` ensures the workflow step exits 0 so SARIF upload always runs, even when findings exist. The alerts surface in GitHub's Security tab instead of blocking the workflow step.

To block PRs on HIGH+ findings, drop `--soft-fail` and add `--fail-on HIGH`:

```yaml
- run: agentscanner scan . --output sarif --output-file agentscanner.sarif --fail-on HIGH
```

---

## pre-commit hook

Block commits that introduce HIGH or above findings:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: agentscanner
        name: agentscanner
        entry: agentscanner scan . --fail-on HIGH
        language: system
        pass_filenames: false
```

Install with:

```bash
pip install pre-commit
pre-commit install
```

---

## JSON output for custom pipelines

```bash
agentscanner scan . --output json --output-file findings.json
```

Output schema:

```json
[
  {
    "check_id": "AS-HOOK-001",
    "severity": "CRITICAL",
    "message": "Hook fetches and executes remote code",
    "file": ".claude/settings.json",
    "line": 12,
    "resource": "hooks[0].command"
  }
]
```

---

## Severity threshold reference

| Flag value | Findings reported |
|---|---|
| `CRITICAL` | CRITICAL only |
| `HIGH` | HIGH + CRITICAL |
| `MEDIUM` | MEDIUM + HIGH + CRITICAL |
| `LOW` | All findings |

Default (no flag): all findings are reported. `--fail-on` follows the same ladder: `--fail-on HIGH` exits nonzero only if a HIGH or CRITICAL finding exists.
