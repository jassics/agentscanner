"""Parse dependency manifests (requirements.txt, package.json) bundled with a
skill into a normalized list of ``{ecosystem, name, version, pinned}`` dicts.

Only *pinned* entries are queryable against OSV.dev — a vulnerability affects
a version range, so there is nothing to check without a concrete version.
Unpinned entries are still recorded (for future "unpinned dependency" checks)
but are skipped by the CVE lookup.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import List

from ..models import ArtifactType, Resource, Scope

_REQ_PINNED = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*==\s*([A-Za-z0-9][A-Za-z0-9._+-]*)\s*(?:;.*)?$"
)
_REQ_NAME = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)")
_SEMVER_EXACT = re.compile(r"^\d+\.\d+\.\d+[A-Za-z0-9.+-]*$")


def _parse_requirements(text: str) -> List[dict]:
    deps: List[dict] = []
    for line in text.splitlines():
        stripped = line.split("#", 1)[0].strip()
        if not stripped or stripped.startswith("-"):
            continue
        m = _REQ_PINNED.match(stripped)
        if m:
            deps.append(
                {"ecosystem": "PyPI", "name": m.group(1), "version": m.group(2), "pinned": True}
            )
            continue
        m2 = _REQ_NAME.match(stripped)
        if m2:
            deps.append(
                {"ecosystem": "PyPI", "name": m2.group(1), "version": None, "pinned": False}
            )
    return deps


def _parse_package_json(text: str) -> List[dict]:
    deps: List[dict] = []
    data = json.loads(text)  # let JSONDecodeError propagate to caller
    if not isinstance(data, dict):
        return deps
    for section in ("dependencies", "devDependencies"):
        block = data.get(section)
        if not isinstance(block, dict):
            continue
        for name, spec in block.items():
            if not isinstance(spec, str):
                continue
            spec = spec.strip()
            if _SEMVER_EXACT.match(spec):
                deps.append({"ecosystem": "npm", "name": name, "version": spec, "pinned": True})
            else:
                deps.append({"ecosystem": "npm", "name": name, "version": spec, "pinned": False})
    return deps


def parse_dependency_manifest(path: Path, scope: Scope) -> Resource:
    """Read *path* (a requirements.txt or package.json) into a
    :class:`~agentscanner.models.Resource` of type ``DEPENDENCY``."""
    raw = path.read_text(encoding="utf-8", errors="replace")
    res = Resource(type=ArtifactType.DEPENDENCY, path=path, scope=scope, raw_text=raw)
    try:
        if path.name == "package.json":
            res.data = _parse_package_json(raw)
        else:
            res.data = _parse_requirements(raw)
    except (json.JSONDecodeError, ValueError) as exc:
        res.parse_error = f"could not parse dependency manifest: {exc}"
    return res
