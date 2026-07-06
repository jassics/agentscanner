"""agentscanner command-line interface."""
from __future__ import annotations

import os
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.table import Table

from . import __version__, aivss
from .checks import get_checks
from .discovery import discover
from .engine import apply_model_tier, filter_by_threshold, run_checks
from .models import Severity
from .probe import probe_resource
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
    offline: bool = typer.Option(
        False,
        "--offline",
        help="Skip live OSV.dev dependency-CVE lookups (AS-DEP-001, AS-MCP-005).",
    ),
    model_tier: str = typer.Option(
        "high",
        "--model-tier",
        help=(
            "high | low. 'low' bumps severity of model_sensitive findings "
            "(prompt injection, social engineering, obfuscated payloads) by "
            "one level, reflecting that smaller/less-aligned models are more "
            "likely to comply with embedded instructions than a frontier model."
        ),
    ),
    aivss_score: bool = typer.Option(
        False,
        "--aivss",
        help="Include an AIVSS-Agentic score (OWASP AIVSS v0.5) per finding.",
    ),
    aivss_thm: float = typer.Option(
        aivss.DEFAULT_THM,
        "--aivss-thm",
        help="AIVSS Threat Multiplier override (0.0-1.0; default 0.97 per the OWASP spec).",
    ),
) -> None:
    """Scan a repository (and optionally ~/.claude) for insecure Claude Code config."""
    if offline:
        os.environ["AGENTSCANNER_OFFLINE"] = "1"
    if model_tier not in ("high", "low"):
        _err.print(f"[red]Invalid --model-tier: {model_tier!r} (must be 'high' or 'low')[/red]")
        raise typer.Exit(2)
    try:
        threshold = Severity.parse(severity_threshold)
    except KeyError:
        _err.print(f"[red]Invalid severity: {severity_threshold}[/red]")
        raise typer.Exit(2)

    resources = discover(repo_root=path, include_user=include_user)
    findings = run_checks(
        resources, only=_split(check), skip=_split(skip_check)
    )
    findings = apply_model_tier(findings, model_tier)
    findings = filter_by_threshold(findings, threshold)

    report = render(
        output, findings, scanned=len(resources), show_aivss=aivss_score, thm=aivss_thm
    )
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


@app.command()
def probe(
    path: Path = typer.Argument(Path("."), help="Repo root to scan for model-sensitive findings."),
    model: List[str] = typer.Option(
        ..., "--model", help="Target model ID to probe (repeatable), e.g. claude-haiku-4-5."
    ),
    judge_model: Optional[str] = typer.Option(
        None, "--judge-model", help="Model used to judge compliance (default: same as --model)."
    ),
    api_key_env: str = typer.Option(
        "ANTHROPIC_API_KEY", "--api-key-env", help="Env var holding your Anthropic API key."
    ),
) -> None:
    """Dynamically test whether specific models comply with flagged content.

    Optional and separate from `scan`: this makes real API calls using your
    own key, spends tokens, and is non-deterministic — treat results as a
    signal, not a verdict. Only runs against findings from model_sensitive
    checks (prompt injection, social engineering, obfuscated payloads).
    """
    api_key = os.environ.get(api_key_env)
    if not api_key:
        _err.print(f"[red]{api_key_env} is not set — probe needs your own Anthropic API key.[/red]")
        raise typer.Exit(2)

    resources = discover(repo_root=path)
    findings = run_checks(resources)
    sensitive_ids = {c.id for c in get_checks() if getattr(c, "model_sensitive", False)}
    targets = [f for f in findings if f.check_id in sensitive_ids]

    console = Console()
    if not targets:
        console.print("[green]No model-sensitive findings to probe.[/green]")
        raise typer.Exit(0)

    colors = {"VULNERABLE": "red", "RESISTANT": "green", "INCONCLUSIVE": "yellow"}
    any_vulnerable = False
    for f in targets:
        for m in model:
            result = probe_resource(f.resource, m, api_key, check_id=f.check_id, judge_model=judge_model)
            if result is None:
                console.print(
                    f"[yellow]INCONCLUSIVE[/yellow] {f.check_id} {f.resource.path} vs {m} "
                    "(probe call failed — check network/API key)"
                )
                continue
            console.print(
                f"[{colors[result.verdict]}]{result.verdict}[/{colors[result.verdict]}] "
                f"{f.check_id} {f.resource.path} vs {m}"
            )
            if result.verdict == "VULNERABLE":
                any_vulnerable = True

    raise typer.Exit(1 if any_vulnerable else 0)


@app.command("list-checks")
def list_checks() -> None:
    """List the built-in check catalog."""
    console = Console()
    table = Table(title="agentscanner checks")
    table.add_column("ID", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Title")
    for chk in get_checks():
        table.add_row(chk.id, chk.severity.name, chk.title)
    console.print(table)


@app.command()
def version() -> None:
    """Print the agentscanner version."""
    print(f"agentscanner {__version__}")


if __name__ == "__main__":  # pragma: no cover
    app()
