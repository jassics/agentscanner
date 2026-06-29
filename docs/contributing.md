# Contributing

## Setup

```bash
git clone https://github.com/jassics/agentscanner
cd agentscanner
pip install -e ".[dev]"
```

If there is no `[dev]` extra yet, install test dependencies directly:

```bash
pip install pytest
```

## Running tests

```bash
pytest
```

The test suite uses paired fixtures: `tests/fixtures/bad/` holds one minimal artifact per check that *must* trigger exactly that finding; `tests/fixtures/good/` holds clean artifacts that *must* scan with zero findings.

## Writing a new check

1. Choose the right module under `src/agentscanner/checks/` (or add a new one for a new category).
2. Subclass `Check` from `checks/base.py` and implement `run(resource) -> list[Finding]`.
3. Declare `check_id`, `severity`, `title`, `applies_to`, and `message` as class attributes.
4. Register the check with the `@register` decorator.
5. Add a bad fixture to `tests/fixtures/bad/<check_id>.json` (or `.md`) that triggers exactly one finding.
6. Verify the `hardened/settings.json` still scans clean after your change.

```python
from agentscanner.checks.base import Check, register
from agentscanner.models import Finding, Severity, ArtifactType

@register
class MyNewCheck(Check):
    check_id = "AS-CATEGORY-NNN"
    severity = Severity.HIGH
    title = "Short description"
    applies_to = [ArtifactType.SETTINGS]
    message = "Detailed finding message shown to the user."

    def run(self, resource):
        findings = []
        # inspect resource.attrs / resource.raw
        if "bad_pattern" in resource.raw:
            findings.append(Finding(
                check_id=self.check_id,
                severity=self.severity,
                message=self.message,
                file=resource.path,
                line=resource.line_index.get("bad_pattern", 0),
            ))
        return findings
```

## Check ID conventions

| Category | Prefix | Example |
|---|---|---|
| Hooks | `AS-HOOK-` | `AS-HOOK-005` |
| Permissions | `AS-PERM-` | `AS-PERM-004` |
| MCP servers | `AS-MCP-` | `AS-MCP-005` |
| Environment / secrets | `AS-ENV-`, `AS-SECRET-` | `AS-ENV-002` |
| Agents | `AS-AGENT-` | `AS-AGENT-002` |
| Skills | `AS-SKILL-` | `AS-SKILL-013` |
| Prompts / steering | `AS-PROMPT-` | `AS-PROMPT-002` |
| Cross-file | `AS-XFILE-` | `AS-XFILE-001` |

## Licensing

All contributed checks must be independently authored. Do not copy rule text, patterns, or taxonomy from GPL-licensed sources (e.g. `awesome-claude-security`). `agentscanner` is Apache-2.0 and must remain compatible with that license.
