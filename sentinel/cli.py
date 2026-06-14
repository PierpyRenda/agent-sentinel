"""agent-sentinel — unified security CLI for AI agents & MCP ecosystems."""

from __future__ import annotations
import json
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table
from rich import print as rprint

app = typer.Typer(
    name="sentinel",
    help="Security toolkit for Claude Code agents, skills, and MCP servers.",
    add_completion=False,
    pretty_exceptions_show_locals=False,
)
keys_app = typer.Typer(help="API key scanner — detect compromised/leaked keys.")
skill_app = typer.Typer(help="Skill & MCP scanner — detect prompt injection, malicious code, integrity issues.")
app.add_typer(keys_app, name="keys")
app.add_typer(skill_app, name="skill")

console = Console()
err_console = Console(stderr=True)

SEVERITY_COLOR = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
}
SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def _max_severity(findings: list) -> str:
    if not findings:
        return "CLEAN"
    return max((f.severity if hasattr(f, "severity") else f.get("severity", "LOW") for f in findings),
               key=lambda s: SEVERITY_RANK.get(s, 0))


def _exit_code(severity: str) -> int:
    return 2 if severity == "CRITICAL" else 1 if severity == "HIGH" else 0


# ─────────────────────────────── keys commands ────────────────────────────────

@keys_app.command("scan")
def keys_scan(
    key: str | None = typer.Option(None, "--key", "-k", help="Single API key to check."),
    env_file: Path | None = typer.Option(None, "--env", "-e", help=".env file to scan for keys."),
    github: bool = typer.Option(False, "--github", help="Also scan GitHub for leaked keys."),
    json_out: bool = typer.Option(False, "--json", help="Output JSON."),
):
    """Check if API keys are compromised or leaked."""
    from sentinel.keys.validator import KeyValidator
    from sentinel.keys.reporter import KeyReporter

    results = []
    if key:
        validator = KeyValidator()
        result = validator.validate(key, scan_github=github)
        results.append(result)
    elif env_file:
        from sentinel.keys.scanners.github import scan_env_file
        results = scan_env_file(str(env_file), scan_github=github)
    else:
        err_console.print("[yellow]Provide --key or --env[/yellow]")
        raise typer.Exit(1)

    if json_out:
        print(json.dumps([r if isinstance(r, dict) else r.dict() for r in results], indent=2))
        return

    reporter = KeyReporter(console)
    reporter.display(results)

    worst = max((r.get("status", "unknown") if isinstance(r, dict) else getattr(r, "status", "unknown")
                 for r in results), key=lambda s: {"compromised": 3, "leaked": 2, "valid": 1}.get(s, 0), default="unknown")
    raise typer.Exit(0 if worst not in ("compromised", "leaked") else 2)


@keys_app.command("revoke")
def keys_revoke(
    provider: str = typer.Argument(..., help="Provider name (openai, anthropic, stripe, …)"),
    key: str = typer.Argument(..., help="Key to revoke."),
):
    """Attempt to revoke a compromised key via the provider's API."""
    from sentinel.keys.revoker import KeyRevoker
    revoker = KeyRevoker()
    result = revoker.revoke(provider, key)
    if result.get("success"):
        rprint(f"[green]✓[/green] Key revoked: {result.get('message', 'done')}")
    else:
        rprint(f"[red]✗[/red] Revoke failed: {result.get('error', 'unknown error')}")
        raise typer.Exit(1)


# ─────────────────────────────── skill commands ───────────────────────────────

@skill_app.command("scan")
def skill_scan(
    target: Path = typer.Argument(..., help="Skill .md file, MCP directory, or any path to scan."),
    json_out: bool = typer.Option(False, "--json", help="Output JSON."),
    min_severity: str = typer.Option("LOW", "--min-severity", help="Minimum severity to show (LOW/MEDIUM/HIGH/CRITICAL)."),
):
    """Scan a skill (.md) or MCP server directory for security issues."""
    from sentinel.skills.analyzer import analyze_skill, analyze_mcp

    target = target.resolve()
    if not target.exists():
        err_console.print(f"[red]Path not found:[/red] {target}")
        raise typer.Exit(1)

    findings = []
    if target.suffix == ".md" or (target.is_dir() and any(target.glob("*.md"))):
        md_files = [target] if target.is_file() else list(target.glob("*.md"))
        for f in md_files:
            findings.extend(analyze_skill(f))
    if target.is_dir():
        findings.extend(analyze_mcp(target))

    min_rank = SEVERITY_RANK.get(min_severity.upper(), 1)
    findings = [f for f in findings if SEVERITY_RANK.get(f.severity, 1) >= min_rank]

    if json_out:
        print(json.dumps([f._asdict() for f in findings], indent=2))
        raise typer.Exit(_exit_code(_max_severity(findings)))

    _render_findings(findings, str(target))
    raise typer.Exit(_exit_code(_max_severity(findings)))


@skill_app.command("verify-all")
def skill_verify_all(
    json_out: bool = typer.Option(False, "--json"),
    update: bool = typer.Option(False, "--update", help="Update lock file with current hashes."),
):
    """Verify integrity of all installed skills across .claude, .kiro, .agents."""
    from sentinel.skills.integrity import verify_all, update_lock

    if update:
        n = update_lock()
        rprint(f"[green]✓[/green] Lock updated — {n} skill(s) hashed.")
        return

    results = verify_all()
    if json_out:
        print(json.dumps(results, indent=2))
        return

    table = Table(title="Skill Integrity", show_header=True)
    table.add_column("Skill", style="bold")
    table.add_column("Location")
    table.add_column("Status")
    table.add_column("Source")

    exit_code = 0
    for r in results:
        status = r["status"]
        color = "green" if status == "match" else "yellow" if status == "not_tracked" else "red"
        if status == "mismatch":
            exit_code = 2
        table.add_row(r["name"], Path(r["dir"]).name, f"[{color}]{status}[/{color}]", r.get("source") or "—")

    console.print(table)
    if not results:
        rprint("[yellow]No skills found in ~/.claude/skills, ~/.kiro/skills, ~/.agents/skills[/yellow]")
    raise typer.Exit(exit_code)


@skill_app.command("scan-configs")
def skill_scan_configs(
    json_out: bool = typer.Option(False, "--json"),
):
    """Scan active MCP config files (~/.mcp.json, ~/Orchestrator/.mcp.json) for suspicious entries."""
    from sentinel.skills.config_scanner import scan_configs

    results = scan_configs()
    if json_out:
        print(json.dumps(results, indent=2))
        return

    total_issues = 0
    for cfg in results:
        if cfg.get("status") == "not_found":
            console.print(f"[dim]skip[/dim] {cfg['path']} (not found)")
            continue
        if cfg.get("status") == "invalid_json":
            console.print(f"[red]ERROR[/red] {cfg['path']}: {cfg.get('error')}")
            continue

        has_issues = any(s["issues"] for s in cfg.get("servers", []))
        status_str = "[red]ISSUES[/red]" if has_issues else "[green]OK[/green]"
        console.print(f"\n{status_str} {cfg['path']}")
        for srv in cfg.get("servers", []):
            for issue in srv["issues"]:
                console.print(f"  [yellow]⚠[/yellow]  {srv['name']}: {issue}")
                total_issues += 1

    if total_issues == 0:
        rprint("[green]✓[/green] No issues found in MCP configs.")
    raise typer.Exit(0 if total_issues == 0 else 1)


@skill_app.command("scan-env")
def skill_scan_env(
    json_out: bool = typer.Option(False, "--json"),
):
    """Scan .env files in ~/Orchestrator for exposed secrets."""
    from sentinel.skills.config_scanner import scan_env_files

    results = scan_env_files()
    if json_out:
        print(json.dumps(results, indent=2))
        return

    # gitignore check
    gitignore_ok = next((r.get("gitignore_check") for r in results if "gitignore_check" in r), None)
    env_results = [r for r in results if "path" in r]

    if gitignore_ok is False:
        rprint("[red]⚠[/red]  .gitignore does NOT include .env — secrets may leak to git!")
    elif gitignore_ok:
        rprint("[green]✓[/green] .gitignore includes .env")

    total_issues = 0
    for r in env_results:
        findings = r.get("findings", [])
        high = [f for f in findings if f["severity"] in ("CRITICAL", "HIGH")]
        if not findings:
            console.print(f"[dim]{r['path']}[/dim] — clean")
            continue
        console.print(f"\n[{'red' if high else 'yellow'}]{r['path']}[/{'red' if high else 'yellow'}]")
        for f in findings:
            color = SEVERITY_COLOR.get(f["severity"], "white")
            console.print(f"  [{color}]{f['id']} {f['severity']}[/{color}] {f['label']}")
            for m in f["matches"][:3]:
                console.print(f"    [dim]{m}[/dim]")
            total_issues += len(f["matches"])

    raise typer.Exit(0 if total_issues == 0 else 1)


# ─────────────────────────────── top-level ────────────────────────────────────

@app.command("version")
def version():
    """Print version."""
    from sentinel import __version__
    rprint(f"agent-sentinel [bold]{__version__}[/bold]")


def _render_findings(findings: list, target: str) -> None:
    if not findings:
        rprint(f"[green]✓ CLEAN[/green]  No issues found in [dim]{target}[/dim]")
        return

    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    worst = _max_severity(findings)
    color = SEVERITY_COLOR.get(worst, "white")
    summary = " · ".join(f"[{SEVERITY_COLOR[s]}]{c} {s}[/{SEVERITY_COLOR[s]}]"
                          for s, c in sorted(counts.items(), key=lambda x: -SEVERITY_RANK[x[0]]))
    console.print(f"\n[{color}]● {worst}[/{color}]  {summary}  in [dim]{target}[/dim]\n")

    for f in sorted(findings, key=lambda x: -SEVERITY_RANK.get(x.severity, 0)):
        color = SEVERITY_COLOR.get(f.severity, "white")
        file_tag = f"  [dim]{f.file}[/dim]" if f.file else ""
        console.print(f"  [{color}]{f.id}[/{color}]  {f.label}{file_tag}")
        for m in f.matches[:2]:
            console.print(f"       [dim]{m[:100]}[/dim]")
    console.print()


def main() -> None:
    app()


if __name__ == "__main__":
    main()
