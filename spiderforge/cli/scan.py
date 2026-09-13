from __future__ import annotations

import asyncio
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from spiderforge.core.engine import run_full_security_assessment

app = typer.Typer(name="scan", help="SpiderForge Security Engine Scanner", invoke_without_command=True)
console = Console()

SEVERITY_COLORS = {
    "Critical": "bold red",
    "High": "red",
    "Medium": "yellow",
    "Low": "cyan",
    "Info": "dim",
}

def render_results(results: dict) -> None:
    console.print(
        Panel.fit(
            f"[bold cyan]SPIDERFORGE SCAN REPORT[/bold cyan]\n"
            f"[white]Target:[/white] {results['target']}\n"
            f"[white]Total Findings:[/white] {results['total_findings']}",
            border_style="cyan"
        )
    )

    findings = results.get("findings", [])
    if not findings:
        console.print("[green][+] No vulnerabilities detected with provided payloads.[/green]")
        return

    table = Table(title="Vulnerabilities & Checks", show_lines=True)
    table.add_column("Type", style="bold white")
    table.add_column("Severity", justify="center")
    table.add_column("Parameter / Target", style="magenta")
    table.add_column("Payload", style="dim")
    table.add_column("Evidence", style="cyan")

    for f in findings:
        sev = f.get("severity", "Info")
        color = SEVERITY_COLORS.get(sev, "white")
        table.add_row(
            f.get("type", "N/A"),
            f"[{color}]{sev.upper()}[/{color}]",
            str(f.get("param", "N/A")),
            str(f.get("payload", "N/A")),
            str(f.get("evidence", "N/A"))
        )
    console.print(table)

@app.command("run")
def run_command(target: str = typer.Argument(..., help="Target URL to assess")):
    """Run security assessment on the target."""
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"
    console.print(f"[bold yellow][*] Running scan on {target}...[/bold yellow]")
    results = asyncio.run(run_full_security_assessment(target))
    render_results(results)

@app.callback()
def main_callback(ctx: typer.Context, target: str = typer.Argument(None, help="Target URL")):
    """Allow direct scanning with or without 'run' keyword."""
    if ctx.invoked_subcommand is None:
        if not target:
            console.print("[red]Error: Target URL required.[/red]")
            raise typer.Exit(code=1)
        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"
        console.print(f"[bold yellow][*] Running scan on {target}...[/bold yellow]")
        results = asyncio.run(run_full_security_assessment(target))
        render_results(results)

if __name__ == "__main__":
    app()