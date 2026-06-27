"""Discover and parse Claude Code artifacts across scopes.

Scope-driven and modular: each scope (user / project / local / managed / plugin)
is an independent source. The CLI selects which scopes are active, so the same
engine cleanly scans a repo, the user's ~/.claude, or both in one run — every
resource is tagged with its Scope.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable, List, Optional

from .models import ArtifactType, Resource, Scope
from .parsers.json_parser import parse_json
from .parsers.markdown_parser import parse_markdown

MAX_FILE_BYTES = 2 * 1024 * 1024  # never read absurdly large files


def _safe_iter(root: Path, pattern: str) -> Iterable[Path]:
    if not root.exists():
        return []
    try:
        return [p for p in root.glob(pattern) if p.is_file()]
    except OSError:
        return []


def _too_big(path: Path) -> bool:
    try:
        return path.stat().st_size > MAX_FILE_BYTES
    except OSError:
        return True


def _classify_md(path: Path) -> ArtifactType:
    parts = {p.lower() for p in path.parts}
    name = path.name.lower()
    if name == "skill.md" or "skills" in parts:
        return ArtifactType.SKILL
    if "agents" in parts:
        return ArtifactType.AGENT
    if "commands" in parts:
        return ArtifactType.COMMAND
    if name == "claude.md":
        return ArtifactType.MEMORY
    return ArtifactType.UNKNOWN


def _collect_claude_dir(claude_dir: Path, scope: Scope) -> List[Resource]:
    """Collect artifacts under a `.claude` (or `~/.claude`) directory."""
    out: List[Resource] = []

    # settings JSON
    for name, sc in (
        ("settings.json", scope),
        ("settings.local.json", Scope.LOCAL),
        ("managed-settings.json", Scope.MANAGED),
    ):
        f = claude_dir / name
        if f.is_file() and not _too_big(f):
            out.append(parse_json(f, sc, ArtifactType.SETTINGS))

    # markdown artifacts: agents, skills, commands
    for pattern in ("agents/**/*.md", "skills/**/*.md", "commands/**/*.md"):
        for f in _safe_iter(claude_dir, pattern):
            if _too_big(f):
                continue
            out.append(parse_markdown(f, scope, _classify_md(f)))

    # plugin manifests bundled under .claude
    for f in _safe_iter(claude_dir, "plugins/**/.claude-plugin/*.json"):
        if not _too_big(f):
            out.append(parse_json(f, Scope.PLUGIN, ArtifactType.PLUGIN_MANIFEST))

    return out


def _collect_plugin_tree(root: Path) -> List[Resource]:
    """Collect artifacts laid out as a plugin/marketplace repo:
    ``plugins/<name>/{skills,agents,commands}/`` and plugin manifests.
    """
    out: List[Resource] = []
    for pattern, atype in (
        ("plugins/**/skills/**/*.md", ArtifactType.SKILL),
        ("plugins/**/agents/**/*.md", ArtifactType.AGENT),
        ("plugins/**/commands/**/*.md", ArtifactType.COMMAND),
    ):
        for f in _safe_iter(root, pattern):
            if not _too_big(f):
                out.append(parse_markdown(f, Scope.PLUGIN, atype))
    for f in _safe_iter(root, "plugins/**/.claude-plugin/*.json"):
        if not _too_big(f):
            out.append(parse_json(f, Scope.PLUGIN, ArtifactType.PLUGIN_MANIFEST))
    return out


def discover(
    repo_root: Optional[Path] = None,
    include_user: bool = False,
    user_home: Optional[Path] = None,
) -> List[Resource]:
    """Return parsed resources for the selected scopes.

    - repo_root: scan ``<repo>/.claude``, ``<repo>/.mcp.json``, ``<repo>/CLAUDE.md``
      and the ``.claude-plugin`` marketplace manifest if present.
    - include_user: additionally scan ``~/.claude``.
    """
    resources: List[Resource] = []

    if repo_root is not None:
        repo_root = repo_root.resolve()
        claude_dir = repo_root / ".claude"
        if claude_dir.is_dir():
            resources += _collect_claude_dir(claude_dir, Scope.PROJECT)

        # project-level files outside .claude
        for name, atype, sc in (
            (".mcp.json", ArtifactType.MCP, Scope.PROJECT),
            ("CLAUDE.md", ArtifactType.MEMORY, Scope.PROJECT),
        ):
            f = repo_root / name
            if f.is_file() and not _too_big(f):
                if atype is ArtifactType.MCP:
                    resources.append(parse_json(f, sc, atype))
                else:
                    resources.append(parse_markdown(f, sc, atype))

        # marketplace manifest + plugin trees (plugin/marketplace repos)
        mkt = repo_root / ".claude-plugin" / "marketplace.json"
        if mkt.is_file() and not _too_big(mkt):
            resources.append(parse_json(mkt, Scope.PLUGIN, ArtifactType.PLUGIN_MANIFEST))
        if (repo_root / "plugins").is_dir():
            resources += _collect_plugin_tree(repo_root)

    if include_user:
        home = user_home or Path(os.path.expanduser("~"))
        user_claude = home / ".claude"
        if user_claude.is_dir():
            resources += _collect_claude_dir(user_claude, Scope.USER)

    return resources
