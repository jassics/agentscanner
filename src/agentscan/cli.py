"""agentscan command-line interface."""
from __future__ import annotations

from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.table import Table

from . import __version__
from .checks import get_checks
from .discovery import discover
from .engine import filter_by_threshold, run_checks
from .models import Severity
from .reporters import render

app = typer.Typer(
    add_completion=False,
    help="Static security scanner for Claude Code configuration "
    "(settings, hooks, MCP, agents, skills, CLAUDE.md).",
    no_args_is_help=True,
)
_err = Console(stderr=True)


def _split(values: Optional[List[str]]) -> List[str]:
    out: List[str] = []
    for v in values or []:
        out.extend(part for part in v.split(",") if part.strip())
    return out


@app.command()
def scan(
    path: Path = typer.Argument(Path("."), help="Repo root to scan."),
    include_user: bool = typer.Option(
        False, "--include-user", help="Also scan ~/.claude (user scope)."
    ),
    check: Optional[List[str]] = typer.Option(
        None, "--check", help="Only run these check IDs (comma-separated)."
    ),
    skip_check: Optional[List[str]] = typer.Option(
        None, "--skip-check", help="Skip these check IDs (comma-separated)."
    ),
    severity_threshold: str = typer.Option(
        "INFO", "--severity-threshold", help="Only report findings >= this severity."
    ),
    output: str = typer.Option("cli", "--output", help="cli | json | sarif."),
    output_file: Optional[Path] = typer.Option(
        None, "--output-file", help="Write report to a file instead of stdout."
    ),
    fail_on: Optional[str] = typer.Option(
        None, "--fail-on", help="Exit nonzero if any finding >= this severity."
    ),
    soft_fail: bool = typer.Option(
        False, "--soft-fail", help="Always exit 0 regardless of findings."
    ),
) -> None:
    """Scan a repository (and optionally ~/.claude) for insecure Claude Code config."""
    try:
        threshold = Severity.parse(severity_threshold)
    except KeyError:
        _err.print(f"[red]Invalid severity: {severity_threshold}[/red]")
        raise typer.Exit(2)

    resources = discover(repo_root=path, include_user=include_user)
    findings = run_checks(
        resources, only=_split(check), skip=_split(skip_check)
    )
    findings = filter_by_threshold(findings, threshold)

    report = render(output, findings, scanned=len(resources))
    if output_file:
        output_file.write_text(report, encoding="utf-8")
        _err.print(f"[green]Report written to {output_file}[/green]")
    else:
        print(report)

    if soft_fail:
        raise typer.Exit(0)
    if fail_on:
        try:
            gate = Severity.parse(fail_on)
        except KeyError:
            _err.print(f"[red]Invalid --fail-on: {fail_on}[/red]")
            raise typer.Exit(2)
        if any(f.severity >= gate for f in findings):
            raise typer.Exit(1)
    elif findings:
        raise typer.Exit(1)
    raise typer.Exit(0)


@app.command("list-checks")
def list_checks() -> None:
    """List the built-in check catalog."""
    console = Console()
    table = Table(title="agentscan checks")
    table.add_column("ID", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Title")
    for chk in get_checks():
        table.add_row(chk.id, chk.severity.name, chk.title)
    console.print(table)


@app.command()
def version() -> None:
    """Print the agentscan version."""
    print(f"agentscan {__version__}")


if __name__ == "__main__":  # pragma: no cover
    app()
