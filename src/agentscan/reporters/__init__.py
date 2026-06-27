"""Output reporters: cli, json, sarif."""
from __future__ import annotations

from typing import List

from ..models import Finding
from . import cli as _cli
from . import json as _json
from . import sarif as _sarif


def render(fmt: str, findings: List[Finding], scanned: int) -> str:
    if fmt == "json":
        return _json.render(findings, scanned)
    if fmt == "sarif":
        return _sarif.render(findings)
    return _cli.render(findings, scanned)
