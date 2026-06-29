"""Scan engine: dispatch resources to applicable checks and collect findings."""
from __future__ import annotations

from typing import Iterable, List

from .checks import get_checks
from .models import Finding, Resource, Severity


def run_checks(
    resources: Iterable[Resource],
    only: Iterable[str] = (),
    skip: Iterable[str] = (),
) -> List[Finding]:
    """Run all registered checks against *resources* and return sorted findings.

    Args:
        resources: Parsed artifacts from :func:`~agentscanner.discovery.discover`.
        only: If non-empty, run only checks whose IDs are in this iterable.
        skip: Check IDs to exclude from the run.

    Returns:
        Findings sorted by descending severity, then check ID, then file path.
        A buggy check never aborts the scan — it produces an INFO finding instead.
    """
    checks = get_checks(only=only, skip=skip)
    findings: List[Finding] = []

    for resource in resources:
        if resource.parse_error:
            findings.append(
                Finding(
                    check_id="CC-PARSE-000",
                    severity=Severity.LOW,
                    title="Artifact could not be parsed",
                    message=resource.parse_error,
                    resource=resource,
                    line=1,
                    remediation="Fix the syntax so the file can be security-scanned.",
                    framework="Operational",
                )
            )
            continue
        for check in checks:
            if resource.type not in check.applies_to:
                continue
            try:
                findings.extend(check.analyze(resource))
            except Exception as exc:  # a buggy check must never abort the scan
                findings.append(
                    Finding(
                        check_id=check.id,
                        severity=Severity.INFO,
                        title="Check raised an error",
                        message=f"{check.id} failed on this resource: {exc}",
                        resource=resource,
                    )
                )

    findings.sort(key=lambda f: (-int(f.severity), f.check_id, str(f.resource.path)))
    return findings


def filter_by_threshold(findings: List[Finding], threshold: Severity) -> List[Finding]:
    """Return only findings at or above *threshold* severity."""
    return [f for f in findings if f.severity >= threshold]
