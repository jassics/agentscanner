"""Output reporters: cli, json, sarif."""
from __future__ import annotations

from typing import List

from .. import aivss
from ..models import Finding
from . import cli as _cli
from . import json as _json
from . import sarif as _sarif


def render(
    fmt: str,
    findings: List[Finding],
    scanned: int,
    show_aivss: bool = False,
    thm: float = aivss.DEFAULT_THM,
) -> str:
    if fmt == "json":
        return _json.render(findings, scanned, show_aivss=show_aivss, thm=thm)
    if fmt == "sarif":
        return _sarif.render(findings)  # AIVSS is not part of the SARIF 2.1.0 result shape
    return _cli.render(findings, scanned, show_aivss=show_aivss, thm=thm)
