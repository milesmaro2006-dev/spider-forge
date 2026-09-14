# spiderforge/cli/main.py
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import webbrowser
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from spiderforge.cli import doctor, recon, report, scan

app = typer.Typer(
    name="spiderforge",
    help="Advanced Web Reconnaissance & Security Assessment Framework",
    add_completion=False,
)

app.add_typer(recon.app, name="recon")
app.add_typer(scan.app, name="scan")
app.add_typer(report.app, name="report")

console = Console()

BANNER = """
[bold red]    ███████╗██████╗ ██╗██████╗ ███████╗██████╗ ███████╗██████╗ ██████╗  ██████╗ ███████╗
    ██╔════╝██╔══██╗██║██╔══██╗██╔════╝██╔══██╗██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
    ███████╗██████╔╝██║██║  ██║█████╗  ██████╔╝█████╗  ██║   ██║██████╔╝██║  ███╗█████╗  
    ╚════██║██╔═══╝ ██║██║  ██║██╔══╝  ██╔══██╗██╔══╝  ██║   ██║██╔══██║██║   ██║██╔══╝  
    ███████║██║     ██║██████╔╝███████╗██║  ██║██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
    ╚══════╝╚═╝     ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝     ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝[/bold red]
[dim white]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/dim white]
[bold cyan]  [+] Framework:[/bold cyan] SpiderForge v2.0.0    [bold cyan]• Author:[/bold cyan] Spidey (@redteam)
[bold cyan]  [+] Core Engine:[/bold cyan] Async / Modular       [bold cyan]• Web Platform:[/bold cyan] http://127.0.0.1:8000
[dim white]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/dim white]
"""


# ─────────────────────────── Helpers ───────────────────────────

def _normalize_target(target: str) -> str:
    target = (target or "").strip()
    if target and not target.startswith(("http://", "https://")):
        target = f"http://{target}"
    return target


def _safe_call(fn, **kwargs) -> None:
    """استدعاء دالة CLI بأمان مع التقاط typer.Exit حتى لا يخرج الـ REPL."""
    try:
        fn(**kwargs)
    except (typer.Exit, SystemExit):
        pass
    except KeyboardInterrupt:
        console.print("\n[yellow][!] Interrupted by user.[/yellow]")
    except Exception as exc:  # noqa: BLE001
        console.print(f"[bold red][!] {type(exc).__name__}: {exc}[/bold red]")


def _human_age(mtime: float) -> str:
    delta = max(0.0, time.time() - mtime)
    if delta < 60:
        return f"{int(delta)}s ago"
    if delta < 3600:
        return f"{int(delta / 60)}m ago"
    if delta < 86400:
        return f"{int(delta / 3600)}h ago"
    return f"{int(delta / 86400)}d ago"


def _iter_scan_workspaces(root: Path, max_depth: int = 3):
    """يمر على المجلدات التي تحتوي scan.json داخل root حتى عمق max_depth."""
    try:
        if not root.exists() or not root.is_dir():
            return
        root = root.resolve()
    except OSError:
        return

    root_depth = len(root.parts)
    try:
        for scan_json in root.rglob("scan.json"):
            try:
                if len(scan_json.parts) - root_depth > max_depth:
                    continue
                if not scan_json.is_file():
                    continue
                # تجاهل أي شيء داخل مجلدات التقارير أو الحزم
                if any(p in {"reports", "node_modules", ".venv", "__pycache__", ".git"}
                       for p in scan_json.parts):
                    continue
                yield scan_json.parent
            except OSError:
                continue
    except OSError:
        return


def _discover_workspaces(limit: int = 5) -> list[Path]:
    """يبحث في المسارات المحتملة، يرتّب النتائج حسب mtime، ويعيد آخر limit."""
    here = Path(__file__).resolve()
    project_root = here.parent.parent.parent  # spiderforge/cli/main.py → project root

    roots: list[Path] = [
        Path.cwd(),
        project_root,
        Path.cwd() / "scans",
        Path.cwd() / "workspaces",
        Path.home() / ".spiderforge" / "scans",
    ]

    seen: set[Path] = set()
    candidates: list[Path] = []

    for root in roots:
        for ws in _iter_scan_workspaces(root):
            try:
                rp = ws.resolve()
            except OSError:
                continue
            if rp in seen:
                continue
            seen.add(rp)
            candidates.append(rp)

    def _mtime(p: Path) -> float:
        try:
            return (p / "scan.json").stat().st_mtime
        except OSError:
            return 0.0

    candidates.sort(key=_mtime, reverse=True)
    return candidates[:limit]


def _peek_target(ws: Path) -> str | None:
    try:
        data = json.loads((ws / "scan.json").read_text(encoding="utf-8"))
    except Exception:
        return None
    tgt = data.get("target") or data.get("final_url")
    return str(tgt) if tgt else None


def _pick_workspace() -> Path | None:
    """يعرض قائمة الفحوصات المكتشفة ويطلب من المستخدم اختياراً، أو مساراً يدوياً."""
    workspaces = _discover_workspaces(limit=5)

    if workspaces:
        table = Table(
            title="Recent Scan Workspaces",
            title_style="bold cyan",
            header_style="bold cyan",
            show_lines=False,
            expand=False,
        )
        table.add_column("#", justify="right", style="bold yellow", no_wrap=True)
        table.add_column("Target / Folder", style="white", overflow="fold")
        table.add_column("Last Modified", style="dim", no_wrap=True)
        table.add_column("Path", style="dim", overflow="fold")

        for i, ws in enumerate(workspaces, start=1):
            try:
                mtime = (ws / "scan.json").stat().st_mtime
            except OSError:
                mtime = 0.0
            when = time.strftime("%Y-%m-%d %H:%M", time.localtime(mtime))
            age = _human_age(mtime)
            label = ws.name
            tgt = _peek_target(ws)
            if tgt:
                label = f"{ws.name}  →  {tgt}"
            table.add_row(str(i), label, f"{when}  ({age})", str(ws))

        console.print(table)
    else:
        console.print("[yellow]No previous scan workspaces were found automatically.[/yellow]")

    if workspaces:
        console.print(
            f"[bold cyan]Select a scan number [1-{len(workspaces)}], "
            "[M] for manual path, or [Q] to cancel:[/bold cyan]"
        )
        default_choice = "1"
    else:
        console.print("[bold cyan][M] for manual path, or [Q] to cancel:[/bold cyan]")
        default_choice = "M"

    answer = Prompt.ask("Choice", default=default_choice).strip()

    if answer.lower() in {"q", "quit", "cancel"}:
        return None
    if answer == "" and not workspaces:
        return None

    if answer.lower() in {"m", "manual"}:
        raw = Prompt.ask("[bold cyan]Enter workspace path[/bold cyan]").strip()
        if not raw:
            console.print("[yellow][!] No path provided.[/yellow]")
            return None
        ws = Path(raw).expanduser()
        try:
            ws = ws.resolve()
        except OSError:
            pass
        if not ws.exists() or not ws.is_dir():
            console.print(f"[bold red][!] Directory not found: {ws}[/bold red]")
            return None
        if not (ws / "scan.json").is_file():
            console.print(f"[bold red][!] scan.json not found in: {ws}[/bold red]")
            return None
        return ws

    if answer.isdigit() and workspaces:
        idx = int(answer)
        if 1 <= idx <= len(workspaces):
            return workspaces[idx - 1]
        console.print(f"[bold red][!] Invalid selection: {answer}[/bold red]")
        return None

    console.print(f"[bold red][!] Unrecognized choice: {answer}[/bold red]")
    return None


def _open_in_browser(target_file: Path) -> None:
    """يفتح ملفاً محلياً في المتصفح الافتراضي، مع رسائل مساعدة."""
    try:
        uri = target_file.as_uri()
    except ValueError:
        console.print(f"[yellow][!] Cannot build URI for: {target_file}[/yellow]")
        return

    try:
        opened = webbrowser.open(uri, new=2)
        if not opened:
            console.print(f"[yellow][!] No browser accepted the request.[/yellow]")
            console.print(f"[dim]افتح يدوياً: {target_file}[/dim]")
            return
        console.print(f"[green][✓] Opened:[/green] {target_file}")
        if target_file.suffix.lower() == ".pdf":
            console.print(
                "[dim]→ المتصفح سيعرض الـ PDF داخلياً، وفيه زر التحميل والطباعة.[/dim]"
            )
    except Exception as exc:  # noqa: BLE001
        console.print(f"[yellow][!] Could not open browser: {exc}[/yellow]")
        console.print(f"[dim]افتح يدوياً: {target_file}[/dim]")


def _offer_open_report(ws_path: Path) -> None:
    """يعرض قائمة خيارات الفتح (PDF / HTML / كلاهما / لا) ويفتح الاختيار."""
    reports_dir = ws_path / "reports"
    pdf_file = reports_dir / "report.pdf"
    html_file = reports_dir / "report.html"

    available: list[tuple[str, str, Path]] = []
    if pdf_file.is_file():
        available.append(("p", "PDF  (يُعرض inline في المتصفح + زر تحميل)", pdf_file))
    if html_file.is_file():
        available.append(("h", "HTML (تفاعلي، سهل النسخ والتعديل)", html_file))

    if not available:
        console.print("[dim]No report files found to open.[/dim]")
        return

    console.print("\n[bold cyan]Open report in browser?[/bold cyan]")
    for key, label, _ in available:
        console.print(f"  [{key.upper()}] {label}")
    if len(available) > 1:
        console.print("  [B] Both (PDF + HTML)")
    console.print("  [N] Skip")

    valid_keys = [k for k, _, _ in available] + ["n"]
    if len(available) > 1:
        valid_keys.append("b")

    default_key = available[0][0]
    picked = Prompt.ask(
        "Choice", choices=valid_keys, default=default_key
    ).lower()

    if picked == "n":
        return

    if picked == "b" and len(available) > 1:
        for _, _, f in available:
            _open_in_browser(f)
        return

    chosen = next((f for k, _, f in available if k == picked), None)
    if chosen:
        _open_in_browser(chosen)


# ─────────────────────── Web server launcher ───────────────────────

def launch_web_server():
    """تشغيل خادم الويب في الخلفية والتأكد من إقلاعه قبل فتح المتصفح."""
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

    try:
        import httpx
        r = httpx.get("http://127.0.0.1:8000/", timeout=1.0)
        if r.status_code == 200:
            console.print("[green][✓] Web console is already active at http://127.0.0.1:8000[/green]")
            webbrowser.open("http://127.0.0.1:8000")
            return
    except Exception:
        pass

    venv_py = os.path.join(root_dir, ".venv", "bin", "python3")
    py_bin = venv_py if os.path.isfile(venv_py) else sys.executable

    log_path = os.path.join(root_dir, "server.log")
    log_file = open(log_path, "a")

    subprocess.Popen(
        [
            py_bin, "-m", "uvicorn", "backend.main:app",
            "--host", "127.0.0.1", "--port", "8000",
        ],
        cwd=root_dir,
        stdout=log_file,
        stderr=log_file,
        start_new_session=True,
    )

    console.print("[bold yellow][*] Starting SpiderForge Web Engine...[/bold yellow]")

    import httpx
    started = False
    for _ in range(12):
        time.sleep(0.5)
        try:
            r = httpx.get("http://127.0.0.1:8000/", timeout=0.5)
            if r.status_code == 200:
                started = True
                break
        except Exception:
            continue

    if started:
        console.print("[bold green][✓] Web platform running at http://127.0.0.1:8000[/bold green]")
        webbrowser.open("http://127.0.0.1:8000")
    else:
        console.print("[bold red][!] Server initialization timed out. Check server.log for details.[/bold red]")


# ─────────────────────── Interactive menu ───────────────────────

@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    if ctx.invoked_subcommand is not None:
        return

    while True:
        console.clear()
        console.print(BANNER)
        console.print(
            Panel(
                "[bold green]Welcome to SpiderForge Interactive Control Center[/bold green]\n"
                "Select an operation to run CLI modules or dispatch the GUI console:",
                title="[b]Interactive Mode[/b]",
                border_style="red",
            )
        )

        console.print("[1] 🎯 Run Full Assessment (Scan)")
        console.print("[2] 🌐 Launch Web Dashboard (GUI - Persistent)")
        console.print("[3] 🔍 Run Reconnaissance Only")
        console.print("[4] 📊 Generate Reports")
        console.print("[5] 🩺 Run System Diagnostics (Doctor)")
        console.print("[6] 🚪 Exit")

        choice = Prompt.ask(
            "\n[bold yellow]Select an option[/bold yellow]",
            choices=["1", "2", "3", "4", "5", "6"],
            default="1",
        )

        # ── 1) Full Assessment ──
        if choice == "1":
            target = Prompt.ask("[bold cyan]Enter target URL (e.g., http://example.com)[/bold cyan]")
            target = _normalize_target(target)
            if target:
                console.print(f"[bold green][*] Launching full assessment on {target}...[/bold green]")
                _safe_call(scan.run_command, target=target)
            Prompt.ask("\n[dim]Press Enter to return to menu...[/dim]")

        # ── 2) Web Dashboard ──
        elif choice == "2":
            launch_web_server()
            Prompt.ask("\n[dim]Press Enter to return to menu...[/dim]")

        # ── 3) Recon ──
        elif choice == "3":
            target = Prompt.ask("[bold cyan]Enter target URL for recon[/bold cyan]")
            target = _normalize_target(target)
            if target:
                console.print(f"[bold green][*] Running reconnaissance on {target}...[/bold green]")
                _safe_call(
                    recon.recon_run,
                    target=target,
                    profile="balanced",
                    scope_file=None,
                    timeout=20.0,
                    user_agent=None,
                    verify_tls=True,
                    no_sitemaps=False,
                    json_out=None,
                    quiet=False,
                    debug=False,
                )
            Prompt.ask("\n[dim]Press Enter to return to menu...[/dim]")

        # ── 4) Reports — Interactive Workspace Selector ──
        elif choice == "4":
            console.rule("[bold cyan]Report Generator[/bold cyan]")
            ws_path = _pick_workspace()

            if ws_path is None:
                console.print("[yellow][!] No workspace selected — returning to menu.[/yellow]")
                Prompt.ask("\n[dim]Press Enter to return to menu...[/dim]")
                continue

            console.print(f"[bold green][*] Generating reports for:[/bold green] {ws_path}")
            _safe_call(
                report.generate,
                workspace=ws_path,
                formats="json,md,html,pdf",
                output_dir=None,
            )

            _offer_open_report(ws_path)
            Prompt.ask("\n[dim]Press Enter to return to menu...[/dim]")

                # ── 5) Doctor ──
        elif choice == "5":
            console.rule("[bold cyan]System Health Check[/bold cyan]")
            try:
                # doctor_run يُرجع: 0=Ready, 1=Degraded, 2=Action Required
                code = doctor.doctor_run()
                if code == 0:
                    console.print("[bold green][✓] System is ready for scanning.[/bold green]")
                elif code == 1:
                    console.print(
                        "[bold yellow][!] System is functional but degraded — "
                        "review warnings above.[/bold yellow]"
                    )
                else:
                    console.print(
                        "[bold red][!] Action required — fix FAIL items before scanning.[/bold red]"
                    )
            except Exception as exc:  # noqa: BLE001
                console.print(f"[bold red][!] Doctor crashed: {type(exc).__name__}: {exc}[/bold red]")
            Prompt.ask("\n[dim]Press Enter to return to menu...[/dim]")

        # ── 6) Exit ──
        elif choice == "6":
            console.print(
                "[bold red][!] Exiting SpiderForge CLI. "
                "(Web server stays active if running)[/bold red]"
            )
            raise typer.Exit()


if __name__ == "__main__":
    app()
