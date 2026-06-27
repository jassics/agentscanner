"""SARIF 2.1.0 reporter for GitHub code scanning / CI ingestion."""
from __future__ import annotations

import json as _json
from typing import List

from .. import __version__
from ..checks import get_checks
from ..models import Finding, Severity

_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def _rules() -> List[dict]:
    rules = []
    for chk in get_checks():
        rules.append(
            {
                "id": chk.id,
                "name": chk.id.replace("-", ""),
                "shortDescription": {"text": chk.title},
                "fullDescription": {"text": chk.remediation or chk.title},
                "defaultConfiguration": {"level": _LEVEL.get(chk.severity, "warning")},
                "properties": {"security-severity": str(int(chk.severity) * 2.5)},
            }
        )
    return rules


def render(findings: List[Finding]) -> str:
    results = []
    for f in findings:
        results.append(
            {
                "ruleId": f.check_id,
                "level": _LEVEL.get(f.severity, "warning"),
                "message": {"text": f.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": str(f.resource.path)},
                            "region": {"startLine": max(1, f.line)},
                        }
                    }
                ],
            }
        )
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "agentscanner",
                        "informationUri": "https://github.com/jassics/agentscanner",
                        "version": __version__,
                        "rules": _rules(),
                    }
                },
                "results": results,
            }
        ],
    }
    return _json.dumps(doc, indent=2)
