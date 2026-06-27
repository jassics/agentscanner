"""Core data model: severities, artifact types, the normalized resource IR, and findings.

Design note: the ``Resource`` IR carries a line lookup from day one so every
finding can cite ``file:line`` (see DESIGN.md §6). v1 uses raw-text re-find for
line mapping, which is accurate enough for the distinctive strings checks search
for (rule text, URLs, env values).
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


class Severity(enum.IntEnum):
    """Ordered so thresholds can be compared numerically (CRITICAL highest)."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.name

    @classmethod
    def parse(cls, value: str) -> "Severity":
        return cls[value.strip().upper()]


class ArtifactType(str, enum.Enum):
    SETTINGS = "settings"
    MCP = "mcp"
    AGENT = "agent"
    SKILL = "skill"
    COMMAND = "command"
    MEMORY = "memory"  # CLAUDE.md / imported memory
    PLUGIN_MANIFEST = "plugin_manifest"
    UNKNOWN = "unknown"


class Scope(str, enum.Enum):
    """Where the artifact lives. Discovery tags each resource so the same engine
    cleanly scans repo + user (+ managed/plugin) config in one run."""

    USER = "user"          # ~/.claude
    PROJECT = "project"    # <repo>/.claude/settings.json, .mcp.json, CLAUDE.md
    LOCAL = "local"        # <repo>/.claude/settings.local.json
    MANAGED = "managed"    # enterprise/managed-settings.json
    PLUGIN = "plugin"      # bundled plugin artifacts
    UNKNOWN = "unknown"


@dataclass
class Resource:
    """One parsed artifact file — the unit a Check runs against."""

    type: ArtifactType
    path: Path
    scope: Scope
    raw_text: str
    data: Any = None                     # parsed JSON dict (settings/mcp/manifest)
    frontmatter: Optional[dict] = None   # YAML frontmatter (agent/skill/command)
    body: Optional[str] = None           # markdown body (agent/skill/command/memory)
    parse_error: Optional[str] = None

    _lines: list = field(default_factory=list, repr=False)

    def __post_init__(self) -> None:
        if not self._lines:
            self._lines = self.raw_text.splitlines()

    def line_of(self, needle: str, default: int = 1) -> int:
        """1-based line number of the first line containing ``needle``."""
        if not needle:
            return default
        for i, line in enumerate(self._lines, start=1):
            if needle in line:
                return i
        return default


@dataclass
class Finding:
    check_id: str
    severity: Severity
    title: str
    message: str
    resource: Resource
    line: int = 1
    remediation: str = ""
    framework: str = ""

    @property
    def location(self) -> str:
        return f"{self.resource.path}:{self.line}"

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "severity": self.severity.name,
            "title": self.title,
            "message": self.message,
            "file": str(self.resource.path),
            "line": self.line,
            "artifact_type": self.resource.type.value,
            "scope": self.resource.scope.value,
            "remediation": self.remediation,
            "framework": self.framework,
        }
