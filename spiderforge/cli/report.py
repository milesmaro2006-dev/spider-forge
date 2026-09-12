from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console

from spiderforge.findings.models import Finding
from spiderforge.reporting import html_report, json_report, markdown_report, pdf_report
from spiderforge.reporting.models import ReportContext, ReportMeta
from spiderforge.utils.logging import setup_logging
from spiderforge.utils.timestamps import isoformat

app = typer.Typer(name="report", help="Generate reports from a scan workspace.")
console = Console()


def _load_workspace(workspace: Path) -> ReportContext:
    if not workspace.exists():
        raise typer.BadParameter(f"workspace not found: {workspace}")

    scan_json = workspace / "scan.json"
    findings_json = workspace / "findings.json"
    if not scan_json.exists():
        raise typer.BadParameter(f"scan.json not found in {workspace}")

    data = json.loads(scan_json.read_text(encoding="utf-8"))
    findings_data: list[dict] = []
    if findings_json.exists():
        findings_data = json.loads(findings_json.read_text(encoding="utf-8"))
    else:
        findings_data = data.get("findings", [])

    findings = [Finding.model_validate(f) for f in findings_data]

    scope = data.get("scope") or {}
    meta = ReportMeta(
        project_name=data.get("project") or workspace.parent.name,
        scan_id=data.get("scan_id", workspace.name),
        target=data.get("target", "—"),
        started_at=data.get("started_at", "—"),
        finished_at=data.get("finished_at") or isoformat(),
    )

    return ReportContext(
        meta=meta,
        scope_include=scope.get("include", []),
        scope_exclude=scope.get("exclude", []),
        findings=findings,
        recon=data.get("recon") or {},
        discovery=data.get("discovery_stats") or data.get("discovery") or {},
        stats=data.get("analysis") or data.get("stats") or {},
        module_errors=data.get("module_errors") or {},
    )


@app.command("generate", help="Generate reports for a workspace.")
def generate(
    workspace: Path = typer.Argument(..., exists=True, file_okay=False, help="Scan workspace directory."),
    formats: str = typer.Option(
        "json,md,html",
        "--format",
        "-f",
        help="Comma-separated: json, md, html, pdf (pdf requires WeasyPrint).",
    ),
    output_dir: Path | None = typer.Option(
        None, "--out", help="Directory to write reports. Defaults to <workspace>/reports."
    ),
) -> None:
    setup_logging()
    ctx = _load_workspace(workspace)
    target_dir = output_dir or (workspace / "reports")
    target_dir.mkdir(parents=True, exist_ok=True)

    wanted = {f.strip().lower() for f in formats.split(",") if f.strip()}
    written: list[Path] = []

    if "json" in wanted:
        written.append(json_report.render(ctx, target_dir / "report.json"))
    if "md" in wanted or "markdown" in wanted:
        written.append(markdown_report.render(ctx, target_dir / "report.md"))
    if "html" in wanted:
        written.append(html_report.render(ctx, target_dir / "report.html"))
    if "pdf" in wanted:
        try:
            written.append(pdf_report.render(ctx, target_dir / "report.pdf"))
        except RuntimeError as exc:
            console.print(f"[yellow]pdf skipped:[/yellow] {exc}")

    for p in written:
        console.print(f"[green]wrote[/green] {p}")