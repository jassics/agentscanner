"""Parse Markdown artifacts (agents, skills, commands, CLAUDE.md) into a Resource.

Splits optional YAML frontmatter (delimited by ``---``) from the body. Frontmatter
is parsed with a safe YAML loader; the body is kept as text for prompt-content
checks. Parsing never executes anything.
"""
from __future__ import annotations

import re
from pathlib import Path

import yaml

from ..models import ArtifactType, Resource, Scope

_FRONTMATTER = re.compile(r"^---\s*\n(.*?)\n---\s*\n?(.*)$", re.DOTALL)


def parse_markdown(path: Path, scope: Scope, artifact_type: ArtifactType) -> Resource:
    raw = path.read_text(encoding="utf-8", errors="replace")
    res = Resource(type=artifact_type, path=path, scope=scope, raw_text=raw)

    m = _FRONTMATTER.match(raw)
    if m:
        fm_text, body = m.group(1), m.group(2)
        try:
            loaded = yaml.safe_load(fm_text)
            res.frontmatter = loaded if isinstance(loaded, dict) else {}
        except yaml.YAMLError as exc:
            res.parse_error = f"invalid frontmatter: {exc}"
            res.frontmatter = {}
        res.body = body
    else:
        res.frontmatter = {}
        res.body = raw

    return res
