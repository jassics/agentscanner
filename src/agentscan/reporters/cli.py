"""Human-readable CLI reporter (rich)."""
from __future__ import annotations

import os
from collections import Counter
from typing import List

from rich.console import Console
from rich.table import Table

from ..models import Finding, Severity

_COLOR = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def _rel(path: str) -> str:
    try:
        rel = os.path.relpath(path, os.getcwd())
        return rel if len(rel) < len(path) else path
    except ValueError:
        return path


def render(findings: List[Finding], scanned: int) -> str:
    console = Console(record=True, width=140)

    if not findings:
        console.print(
            f"[green]✓ No findings.[/green] Scanned {scanned} Claude Code "
            f"artifact(s)."
        )
        return console.export_text()

    table = Table(show_lines=True, expand=True, pad_edge=False)
    table.add_column("Sev", no_wrap=True, width=8)
    table.add_column("Check", no_wrap=True, width=13)
    table.add_column("Location", overflow="fold", ratio=2)
    table.add_column("Message", overflow="fold", ratio=3)

    for f in findings:
        color = _COLOR.get(f.severity, "white")
        table.add_row(
            f"[{color}]{f.severity.name}[/{color}]",
            f.check_id,
            f"{_rel(str(f.resource.path))}:{f.line}",
            f.message,
        )

    console.print(table)

    by_sev = Counter(f.severity.name for f in findings)
    parts = [
        f"[{_COLOR[s]}]{by_sev[s.name]} {s.name}[/{_COLOR[s]}]"
        for s in sorted(Severity, reverse=True)
        if by_sev.get(s.name)
    ]
    console.print(
        f"\nScanned {scanned} artifact(s) — {len(findings)} finding(s): "
        + ", ".join(parts)
    )
    return console.export_text()
