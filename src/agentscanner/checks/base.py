"""Check abstract base class + registry.

Each check declares the artifact types it applies to and yields Findings. The
engine instantiates every registered check once and dispatches resources to it.
"""
from __future__ import annotations

from typing import Dict, Iterable, List, Set, Type

from ..models import ArtifactType, Finding, Resource, Severity

CHECK_REGISTRY: Dict[str, "Check"] = {}


class Check:
    """Abstract base class for all agentscanner checks.

    Subclass this, declare the class attributes, implement :meth:`analyze`,
    and decorate with :func:`register` to add a check to the scanner.

    Attributes:
        id: Unique check identifier (e.g. ``AS-HOOK-001``).
        severity: Default severity for findings emitted by this check.
        title: Short human-readable name shown in the CLI table.
        applies_to: Artifact types this check runs against.
        remediation: Actionable fix guidance included in every finding.
        framework: Comma-separated OWASP/NIST framework references.
    """

    id: str = ""
    severity: Severity = Severity.MEDIUM
    title: str = ""
    applies_to: Set[ArtifactType] = set()
    remediation: str = ""
    framework: str = ""

    def analyze(self, resource: Resource) -> Iterable[Finding]:  # pragma: no cover
        """Inspect *resource* and yield zero or more :class:`~agentscanner.models.Finding` objects."""
        raise NotImplementedError

    def finding(self, resource: Resource, message: str, line: int = 1) -> Finding:
        """Build a :class:`~agentscanner.models.Finding` pre-populated with this check's metadata."""
        return Finding(
            check_id=self.id,
            severity=self.severity,
            title=self.title,
            message=message,
            resource=resource,
            line=line,
            remediation=self.remediation,
            framework=self.framework,
        )


def register(cls: Type[Check]) -> Type[Check]:
    """Class decorator that instantiates and registers a :class:`Check` subclass.

    Raises ``ValueError`` if the check has no ``id`` or its ID is already taken.
    """
    inst = cls()
    if not inst.id:
        raise ValueError(f"{cls.__name__} missing id")
    if inst.id in CHECK_REGISTRY:
        raise ValueError(f"duplicate check id {inst.id}")
    CHECK_REGISTRY[inst.id] = inst
    return cls


def get_checks(
    only: Iterable[str] = (),
    skip: Iterable[str] = (),
) -> List[Check]:
    """Return registered checks filtered by *only* / *skip* ID sets, sorted by ID."""
    only_set = {c.strip() for c in only if c.strip()}
    skip_set = {c.strip() for c in skip if c.strip()}
    checks = []
    for cid, chk in sorted(CHECK_REGISTRY.items()):
        if only_set and cid not in only_set:
            continue
        if cid in skip_set:
            continue
        checks.append(chk)
    return checks
