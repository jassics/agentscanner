"""Discover and parse Claude Code artifacts across scopes.

Scope-driven and modular: each scope (user / project / local / managed / plugin)
is an independent source. The CLI selects which scopes are active, so the same
engine cleanly scans a repo, the user's ~/.claude, or both in one run — every
resource is tagged with its Scope.

Discovery is repo-wide: skills, agents, commands, plugin manifests, MCP
servers, settings, and hooks are matched by filename/parent-dir pattern
wherever they live in the tree — not just under a canonical ``.claude`` or
``plugins`` root. Marketplace/registry repos (e.g. a bundle of
``skills/<category>/<name>/<version>/SKILL.md`` trees, each with its own
``.claude-plugin/plugin.json`` and ``hooks/hooks.json``) are scanned the same
as a single project's ``.claude`` directory.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

from .models import ArtifactType, Resource, Scope
from .parsers.dependency_parser import parse_dependency_manifest
from .parsers.json_parser import parse_json
from .parsers.markdown_parser import parse_markdown

_DEPENDENCY_MANIFESTS = ("requirements.txt", "package.json")

MAX_FILE_BYTES = 2 * 1024 * 1024  # never read absurdly large files

# Directories that are never worth walking into: VCS internals, dependency
# trees, build/cache output, and editor-specific state. Notably NOT excluded:
# ``.claude``, ``.claude-plugin`` (Claude Code artifacts we want), which may
# recur at any depth (one per skill/plugin bundle), not just at repo root.
_VENDOR_DIRS = {
    ".git", ".hg", ".svn",
    "node_modules", "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    ".venv", "venv", "env", "dist", "build", ".tox", ".idea", ".vscode",
    ".cursor", ".cursor-plugin",  # Cursor-specific configs, not Claude Code
}

_SETTINGS_FILES = {"settings.json", "settings.local.json", "managed-settings.json"}


def _settings_scope(name: str, base_scope: Scope) -> Scope:
    """settings.local.json / managed-settings.json are always LOCAL/MANAGED,
    regardless of which directory they're found in; plain settings.json takes
    the scope of the directory it's in."""
    if name == "settings.local.json":
        return Scope.LOCAL
    if name == "managed-settings.json":
        return Scope.MANAGED
    return base_scope


@dataclass
class ScanManifest:
    """Optional out-param for :func:`discover`: records exactly what was
    walked and matched, so a caller can report "which file, which folder"."""

    dirs_walked: List[Path] = field(default_factory=list)
    dirs_excluded: List[Path] = field(default_factory=list)
    files_matched: List[Tuple[Path, ArtifactType, Scope]] = field(default_factory=list)


def _too_big(path: Path) -> bool:
    try:
        return path.stat().st_size > MAX_FILE_BYTES
    except OSError:
        return True


def _classify_md(path: Path) -> ArtifactType:
    """Classify a Markdown file by its own name or immediate parent dir.

    Uses the *immediate* parent only (not any ancestor) so a repo-wide walk
    doesn't misclassify unrelated docs (e.g. ``skills/foo/1.0/references/
    template.md``) just because "skills" appears somewhere in the path. A
    skill's own file is either literally named ``SKILL.md``, or any markdown
    file sitting directly inside a directory named ``skills`` (flat layout).
    """
    name = path.name.lower()
    parent = path.parent.name.lower()
    if name == "skill.md" or parent == "skills":
        return ArtifactType.SKILL
    if parent == "agents":
        return ArtifactType.AGENT
    if parent == "commands":
        return ArtifactType.COMMAND
    if name == "claude.md":
        return ArtifactType.MEMORY
    return ArtifactType.UNKNOWN


def _load_md(path: Path, scope: Scope, manifest: Optional[ScanManifest]) -> Optional[Resource]:
    atype = _classify_md(path)
    if atype is ArtifactType.UNKNOWN or _too_big(path):
        return None
    if manifest is not None:
        manifest.files_matched.append((path, atype, scope))
    return parse_markdown(path, scope, atype)


def _load_json(
    path: Path, scope: Scope, atype: ArtifactType, manifest: Optional[ScanManifest]
) -> Optional[Resource]:
    if _too_big(path):
        return None
    if manifest is not None:
        manifest.files_matched.append((path, atype, scope))
    return parse_json(path, scope, atype)


def _load_dependency(
    path: Path, scope: Scope, manifest: Optional[ScanManifest]
) -> Optional[Resource]:
    if _too_big(path):
        return None
    if manifest is not None:
        manifest.files_matched.append((path, ArtifactType.DEPENDENCY, scope))
    return parse_dependency_manifest(path, scope)


def _walk_tree(
    root: Path,
    scope: Scope,
    manifest: Optional[ScanManifest],
    skip_root_dot_claude: bool = False,
    root_level_scope: Optional[Scope] = None,
) -> List[Resource]:
    """Single recursive walk of *root*, matching every Claude Code artifact
    kind (skills, agents, commands, plugin manifests, MCP servers, settings,
    hooks, bundled dependency manifests) regardless of depth or which
    directory contains them.

    ``skip_root_dot_claude``: when *root* has already had its top-level
    ``.claude`` collected separately (canonical project scope), don't
    re-walk that one node here — but still descend into any ``.claude``
    directory found deeper in the tree (one per skill/plugin bundle).
    """
    out: List[Resource] = []
    if not root.exists():
        return out

    root_dot_claude = (root / ".claude").resolve() if skip_root_dot_claude else None

    for dirpath, dirnames, filenames in os.walk(root):
        current = Path(dirpath)

        pruned = []
        for d in dirnames:
            if d in _VENDOR_DIRS:
                if manifest is not None:
                    manifest.dirs_excluded.append(current / d)
                continue
            if root_dot_claude is not None and (current / d).resolve() == root_dot_claude:
                if manifest is not None:
                    manifest.dirs_excluded.append(current / d)
                continue
            pruned.append(d)
        dirnames[:] = pruned

        if manifest is not None:
            manifest.dirs_walked.append(current)

        is_walk_root = current == root
        base_scope = root_level_scope if (is_walk_root and root_level_scope is not None) else scope

        for name in filenames:
            f = current / name
            lname = name.lower()

            if lname.endswith(".md"):
                # CLAUDE.md at the walk root keeps its own (possibly
                # PROJECT-level) scope; nested memory files use base scope.
                res = _load_md(
                    f, base_scope if lname == "claude.md" else scope, manifest
                )
                if res is not None:
                    out.append(res)
                continue

            if name in _SETTINGS_FILES:
                res = _load_json(
                    f, _settings_scope(name, base_scope), ArtifactType.SETTINGS, manifest
                )
                if res is not None:
                    out.append(res)
                continue

            if lname == ".mcp.json":
                res = _load_json(f, base_scope, ArtifactType.MCP, manifest)
                if res is not None:
                    out.append(res)
                continue

            if lname == "hooks.json":
                res = _load_json(f, scope, ArtifactType.SETTINGS, manifest)
                if res is not None:
                    out.append(res)
                continue

            if lname == "plugin.json" and current.name == ".claude-plugin":
                res = _load_json(f, Scope.PLUGIN, ArtifactType.PLUGIN_MANIFEST, manifest)
                if res is not None:
                    out.append(res)
                continue

            if lname == "marketplace.json" and current.name == ".claude-plugin":
                res = _load_json(f, Scope.PLUGIN, ArtifactType.PLUGIN_MANIFEST, manifest)
                if res is not None:
                    out.append(res)
                continue

            if name in _DEPENDENCY_MANIFESTS:
                # Only meaningful bundled next to a skill (avoid flagging every
                # unrelated requirements.txt/package.json in a large monorepo).
                if (current / "SKILL.md").is_file() or (current.parent / "SKILL.md").is_file():
                    res = _load_dependency(f, scope, manifest)
                    if res is not None:
                        out.append(res)
                continue

    return out


def discover(
    repo_root: Optional[Path] = None,
    include_user: bool = False,
    user_home: Optional[Path] = None,
    manifest: Optional[ScanManifest] = None,
) -> List[Resource]:
    """Return parsed resources for the selected scopes.

    - repo_root: recursively scans the whole repo for Claude Code artifacts —
      settings, ``.mcp.json``, ``CLAUDE.md``, agents/skills/commands, plugin
      manifests, and hooks — at any depth, not just under a top-level
      ``.claude`` or ``plugins`` directory. A canonical ``<repo>/.claude``
      directory (if present) is still tagged PROJECT/LOCAL/MANAGED scope;
      everything else found repo-wide is tagged PLUGIN scope (bundled
      skill/plugin artifacts, wherever they live).
    - include_user: additionally scans ``~/.claude``.
    - manifest: optional :class:`ScanManifest` populated in place with every
      directory walked/excluded and file matched, for reporting.
    """
    resources: List[Resource] = []

    if repo_root is not None:
        repo_root = repo_root.resolve()

        claude_dir = repo_root / ".claude"
        if claude_dir.is_dir():
            resources += _walk_tree(claude_dir, Scope.PROJECT, manifest)

        resources += _walk_tree(
            repo_root,
            Scope.PLUGIN,
            manifest,
            skip_root_dot_claude=True,
            root_level_scope=Scope.PROJECT,
        )

    if include_user:
        home = user_home or Path(os.path.expanduser("~"))
        user_claude = home / ".claude"
        if user_claude.is_dir():
            resources += _walk_tree(user_claude, Scope.USER, manifest)

    return resources
