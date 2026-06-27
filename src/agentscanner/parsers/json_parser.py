"""Parse JSON config (settings, .mcp.json, plugin manifests) into a Resource.

Tolerant of JSONC-style ``//`` and ``/* */`` comments and trailing commas, which
Claude Code settings files sometimes carry, so a comment never aborts a scan.
The raw text is preserved verbatim for line mapping.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from ..models import ArtifactType, Resource, Scope

_LINE_COMMENT = re.compile(r"(^|\s)//.*$", re.MULTILINE)
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_TRAILING_COMMA = re.compile(r",(\s*[}\]])")


def _loads_tolerant(text: str):
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        cleaned = _BLOCK_COMMENT.sub("", text)
        cleaned = _LINE_COMMENT.sub(r"\1", cleaned)
        cleaned = _TRAILING_COMMA.sub(r"\1", cleaned)
        return json.loads(cleaned)


def parse_json(path: Path, scope: Scope, artifact_type: ArtifactType) -> Resource:
    raw = path.read_text(encoding="utf-8", errors="replace")
    res = Resource(type=artifact_type, path=path, scope=scope, raw_text=raw)
    try:
        res.data = _loads_tolerant(raw)
    except (json.JSONDecodeError, ValueError) as exc:
        res.parse_error = f"invalid JSON: {exc}"
    return res
