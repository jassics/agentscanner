"""JSON reporter."""
from __future__ import annotations

import json as _json
from collections import Counter
from typing import List

from ..models import Finding


def render(findings: List[Finding], scanned: int) -> str:
    by_sev = Counter(f.severity.name for f in findings)
    doc = {
        "tool": "agentscan",
        "summary": {
            "resources_scanned": scanned,
            "findings": len(findings),
            "by_severity": dict(by_sev),
        },
        "findings": [f.to_dict() for f in findings],
    }
    return _json.dumps(doc, indent=2)
