"""JSON reporter."""
from __future__ import annotations

import json as _json
from collections import Counter
from typing import List

from .. import aivss
from ..models import Finding


def render(
    findings: List[Finding],
    scanned: int,
    show_aivss: bool = False,
    thm: float = aivss.DEFAULT_THM,
) -> str:
    by_sev = Counter(f.severity.name for f in findings)
    finding_dicts = []
    for f in findings:
        d = f.to_dict()
        if show_aivss:
            d["aivss"] = aivss.score_finding(f.check_id, f.severity, thm).to_dict()
        finding_dicts.append(d)
    doc = {
        "tool": "agentscanner",
        "summary": {
            "resources_scanned": scanned,
            "findings": len(findings),
            "by_severity": dict(by_sev),
        },
        "findings": finding_dicts,
    }
    return _json.dumps(doc, indent=2)
