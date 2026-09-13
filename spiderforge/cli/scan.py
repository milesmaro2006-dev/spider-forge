from __future__ import annotations

import asyncio
import json
from pathlib import Path
from urllib.parse import urlsplit

import httpx
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from spiderforge.analysis.loader import load_builtin_modules
from spiderforge.analysis.registry import registry
from spiderforge.analysis.runner import make_context, run_modules
from spiderforge.config.defaults import DEFAULT_DATA_DIR
from spiderforge.config.loader import load_config
from spiderforge.core.events import Event, EventBus, EventType
from spiderforge.crawler.engine import crawl
from spiderforge.database.engine import init_db, session_scope
from spiderforge.database.models import FindingRow
from spiderforge.database.repositories import (
    FindingRepository,
    ProjectRepository,
    ScanRepository,
)
from spiderforge.discovery.runner import run as run_discovery
from spiderforge.evidence.collector import EvidenceCollector
from spiderforge.findings.cvss import score_for
from spiderforge.findings.models import Finding
from spiderforge.recon.runner import run as run_recon
from spiderforge.scope.parser import default_scope_for, load_scope
from spiderforge.scope.validator import ScopeValidator
from spiderforge.utils.logging import get_logger, setup_logging
from spiderforge.utils.timestamps import isoformat, scan_id

app = typer.Typer(name="scan", help="Full end-to-end assessment.")
console = Console()
log = get_logger("cli.scan")

SEVERITY_COLORS = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}


def _print_findings(findings: list[Finding]) -> None:
    if not findings:
        console.print("[dim]no findings[/dim]")
        return
    t = Table(title="Findings", show_lines=False)
    t.add_column("ID", style="cyan", no_wrap=True)
    t.add_column("Sev", no_wrap=True)
    t.add_column("Conf", justify="right", no_wrap=True)
    t.add_column("Category", style="dim", no_wrap=True)
    t.add_column("Title")
    t.add_column("URL", style="dim")
    for f in findings:
        color = SEVERITY_COLORS.get(f.severity.value, "white")
        t.add_row(
            f.id,
            f"[{color}]{f.severity.value.upper()}[/{color}]",
            f"{f.confidence:.2f}",
            f.category,
            f.title,
            (f.url or "")[-70:],
        )
    console.print(t)


@app.command("run", help="Run a full assessment: recon → crawl → discover → analyze.")
def scan_run(
    target: str = typer.Argument(..., help="Target URL."),
    scope_file: Path | None = typer.Option(None, "--scope", help="Scope YAML."),
    profile: str = typer.Option("balanced", "--profile"),
    depth: int | None = typer.Option(None, "--depth"),
    concurrency: int | None = typer.Option(None, "--concurrency"),
    timeout: float | None = typer.Option(None, "--timeout"),
    rate_limit: float | None = typer.Option(None, "--rate-limit"),
    user_agent: str | None = typer.Option(None, "--user-agent"),
    verify_tls: bool = typer.Option(True, "--verify-tls/--no-verify-tls"),
    modules: str | None = typer.Option(
        None, "--modules", help="Comma-separated module names to include."
    ),
    exclude_modules: str | None = typer.Option(
        None, "--exclude-modules", help="Comma-separated module names to skip."
    ),
    no_recon: bool = typer.Option(False, "--no-recon"),
    no_crawl: bool = typer.Option(False, "--no-crawl"),
    no_discovery: bool = typer.Option(False, "--no-discovery"),
    output: Path | None = typer.Option(None, "--output", help="Workspace directory."),
    json_out: Path | None = typer.Option(None, "--json", help="Write full result JSON."),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
    debug: bool = typer.Option(False, "--debug"),
) -> None:
    """Run everything in one command."""
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"

    setup_logging(level="DEBUG" if debug else "INFO", quiet=quiet)
    cfg = load_config(profile=profile)

    # --- Scope ----------------------------------------------------------
    if scope_file:
        scope_cfg = load_scope(scope_file)
    else:
        host = target.split("://")[-1].split("/")[0].split(":")[0]
        scope_cfg = default_scope_for(host)
        if not quiet:
            console.print(
                f"[yellow]note[/yellow] no --scope provided; auto-scope for [bold]{host}[/bold]"
            )
    scope = ScopeValidator(scope_cfg)

    # --- Effective options ---------------------------------------------
    eff_depth = depth if depth is not None else cfg.scanner.max_depth
    eff_conc = concurrency if concurrency is not None else cfg.scanner.concurrency
    eff_timeout = timeout if timeout is not None else cfg.scanner.timeout
    eff_rate = rate_limit if rate_limit is not None else cfg.scanner.rate_limit
    eff_ua = user_agent or cfg.scanner.user_agent

    # --- Modules selection ---------------------------------------------
    load_builtin_modules()
    include = [m.strip() for m in modules.split(",")] if modules else None
    exclude = [m.strip() for m in exclude_modules.split(",")] if exclude_modules else None
    selected_modules = registry.select(include=include, exclude=exclude)

    # --- Banner --------------------------------------------------------
    if not quiet:
        console.print(
            Panel.fit(
                f"[bold cyan]SPIDERFORGE[/bold cyan]\n"
                f"[white]Full assessment[/white]\n\n"
                f"Target:   {target}\n"
                f"Project:  {scope_cfg.project.name}\n"
                f"Profile:  {profile}\n"
                f"Modules:  {len(selected_modules)} selected",
                border_style="cyan",
            )
        )

    # --- Workspace -----------------------------------------------------
    sid = scan_id()
    workspace = output or (DEFAULT_DATA_DIR / "workspaces" / scope_cfg.project.name / "scans" / sid)
    workspace.mkdir(parents=True, exist_ok=True)

    # --- DB ------------------------------------------------------------
    init_db()
    with session_scope() as session:
        proj_repo = ProjectRepository(session)
        scan_repo = ScanRepository(session)
        find_repo = FindingRepository(session)
        project = proj_repo.get_or_create(scope_cfg.project.name)
        scan_record = scan_repo.create(
            scan_uid=sid,
            project_id=project.id,
            target=target,
            profile=profile,
            workspace_path=str(workspace),
        )
        session.flush()
        scan_db_id = scan_record.id

    # --- Event bus -----------------------------------------------------
    bus = EventBus()
    if not quiet:
        def _on_event(ev: Event) -> None:
            if ev.type == EventType.SCAN_STARTED and ev.data.get("phase") == "analysis":
                console.print(f"[cyan]→[/cyan] {ev.message}")
            elif ev.type == EventType.SCAN_STARTED and ev.data.get("phase") != "analysis":
                console.print(f"[cyan]→[/cyan] {ev.message}")
            elif ev.type == EventType.SCAN_FINISHED and ev.data.get("phase") == "analysis":
                n = ev.data.get("findings", 0)
                console.print(f"  [dim]{ev.message}: {n} finding(s)[/dim]")
            elif ev.type == EventType.OUT_OF_SCOPE:
                pass  # quiet during scan
            elif ev.type == EventType.ERROR:
                console.print(f"[red]ERROR[/red] {ev.message}")
        bus.subscribe(_on_event)

    async def _run() -> dict:
        result_payload: dict = {
            "scan_id": sid,
            "target": target,
            "started_at": isoformat(),
        }

        recon_result = None
        crawl_result = None
        discovery_result = None

        if not no_recon:
            if not quiet:
                console.print("[bold]Recon[/bold]")
            recon_result = await run_recon(
                target,
                scope=scope,
                bus=bus,
                timeout=eff_timeout,
                user_agent=eff_ua,
                verify_tls=verify_tls,
            )
            result_payload["recon"] = {
                "http": recon_result.http,
                "technologies": recon_result.technologies,
                "dns_records": (recon_result.dns or {}).get("records", []),
            }

        if not no_crawl:
            if not quiet:
                console.print("[bold]Crawl[/bold]")
            crawl_result = await crawl(
                target,
                scope=scope,
                bus=bus,
                concurrency=max(5, eff_conc // 2),
                max_depth=eff_depth,
                timeout=eff_timeout,
                rate_limit=eff_rate,
                user_agent=eff_ua,
                verify_tls=verify_tls,
            )
            result_payload["crawl_stats"] = crawl_result.stats

        if not no_discovery:
            if not quiet:
                console.print("[bold]Discovery[/bold]")
            discovery_result = await run_discovery(
                target,
                scope=scope,
                bus=bus,
                crawl_result=crawl_result,
                concurrency=eff_conc,
                timeout=eff_timeout,
                rate_limit=eff_rate,
                user_agent=eff_ua,
                verify_tls=verify_tls,
            )
            result_payload["discovery_stats"] = discovery_result.stats

        # --- Analysis --------------------------------------------------
        if not quiet:
            console.print("[bold]Analysis[/bold]")

        async with httpx.AsyncClient(
            follow_redirects=False,
            timeout=eff_timeout,
            headers={"User-Agent": eff_ua},
            verify=verify_tls,
        ) as client:
            ctx = make_context(
                target=target,
                scope=scope,
                client=client,
                config=cfg,
                crawl_result=crawl_result,
                discovery_result=discovery_result,
                recon_result=recon_result,
                bus=bus,
            )
            analysis = await run_modules(selected_modules, ctx=ctx, bus=bus)

        # --- Enrich with CVSS + persist evidence (before DB write) ------------- #
        collector = EvidenceCollector(workspace)
        for f in analysis.findings:
            if f.cvss_score is None:
                scored = score_for(f.category)
                if scored is not None:
                    f.cvss_score, f.cvss_vector = scored
            # Persist whatever evidence we already have as an artifact
            if f.evidence.request or f.evidence.response:
                collector.capture_text(
                    f,
                    name="raw_evidence.txt",
                    content=f"# {f.id} — {f.title}\n\n"
                            f"## Request\n{f.evidence.request or '(none)'}\n\n"
                            f"## Response\n{f.evidence.response or '(none)'}\n\n"
                            f"## Payload\n{f.evidence.payload or '(none)'}\n",
                    kind="note",
                )
        collector.export_findings(analysis.findings)

        result_payload["analysis"] = analysis.stats
        result_payload["module_errors"] = analysis.module_errors
        result_payload["findings"] = [f.model_dump(mode="json") for f in analysis.findings]
        result_payload["finished_at"] = isoformat()
        result_payload["scope"] = {
            "include": list(scope_cfg.include),
            "exclude": list(scope_cfg.exclude),
        }
        result_payload["project"] = scope_cfg.project.name

        # --- Persist findings -----------------------------------------
        with session_scope() as session:
            find_repo = FindingRepository(session)
            for f in analysis.findings:
                row = FindingRow(
                    scan_id=scan_db_id,
                    finding_uid=f.id,
                    fingerprint=f.fingerprint,
                    title=f.title,
                    category=f.category,
                    severity=f.severity.value,
                    confidence=f.confidence,
                    cvss_score=f.cvss_score,
                    cvss_vector=f.cvss_vector,
                    url=f.url,
                    method=f.method,
                    parameter=f.parameter,
                    description=f.description,
                    impact=f.impact,
                    evidence=json.dumps(f.evidence.model_dump()),
                    remediation=f.remediation,
                    status=f.status.value,
                )
                find_repo.add(row)
            scan_repo.finish(scan_db_id, status="completed")

        return result_payload

    try:
        payload = asyncio.run(_run())
    except KeyboardInterrupt:
        console.print("[red]aborted[/red]")
        with session_scope() as session:
            ScanRepository(session).finish(scan_db_id, status="aborted")
        raise typer.Exit(code=130) from None
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]fatal:[/red] {exc}")
        with session_scope() as session:
            ScanRepository(session).finish(scan_db_id, status="failed")
        raise typer.Exit(code=1) from None

    # --- Print --------------------------------------------------------
    findings_list = [
        Finding.model_validate(f) for f in payload.get("findings", [])
    ]
    _print_findings(findings_list)

    # Severity summary
    counts: dict[str, int] = {}
    for f in findings_list:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    console.rule("[bold]Severity distribution")
    for sev in ("critical", "high", "medium", "low", "info"):
        color = SEVERITY_COLORS.get(sev, "white")
        console.print(f"  [{color}]{sev.upper():<10}[/{color}] {counts.get(sev, 0)}")

    # Save payload
    workspace_json = workspace / "scan.json"
    workspace_json.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    console.print(f"\n[green]workspace:[/green] {workspace}")

    if json_out:
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        console.print(f"[green]json:[/green] {json_out}")

    if payload.get("module_errors"):
        console.rule("[bold red]Module errors")
        for name, err in payload["module_errors"].items():
            console.print(f"  [red]{name}[/red]: {err}")