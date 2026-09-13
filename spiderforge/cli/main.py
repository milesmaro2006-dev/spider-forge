import os
import subprocess
import sys
import webbrowser
import typer
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt

from spiderforge.cli import recon, scan, report, doctor

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


def launch_web_server():
    """تشغيل خادم الويب في الخلفية بشكل دائم دون إيقاف التيرمنال"""
    try:
        import httpx
        r = httpx.get("http://127.0.0.1:8000/", timeout=1.0)
        if r.status_code == 200:
            console.print("[green][✓] Web console is already active at http://127.0.0.1:8000[/green]")
            webbrowser.open("http://127.0.0.1:8000")
            return
    except Exception:
        pass

    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    log_file = open(os.path.join(root_dir, "server.log"), "a")

    subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"],
        cwd=root_dir,
        stdout=log_file,
        stderr=log_file,
        start_new_session=True,
    )
    console.print("[bold green][✓] Web platform running permanently at http://127.0.0.1:8000[/bold green]")
    webbrowser.open("http://127.0.0.1:8000")


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

        if choice == "1":
            target = Prompt.ask("[bold cyan]Enter target URL (e.g., http://example.com)[/bold cyan]")
            if target:
                if not target.startswith(("http://", "https://")):
                    target = f"http://{target}"
                console.print(f"[bold green][*] Launching full assessment on {target}...[/bold green]")
                ctx.invoke(scan.scan_run, target=target)
            Prompt.ask("\n[dim]Press Enter to return to menu...[/dim]")

        elif choice == "2":
            launch_web_server()
            Prompt.ask("\n[dim]Press Enter to return to menu...[/dim]")

        elif choice == "3":
            target = Prompt.ask("[bold cyan]Enter target URL for recon[/bold cyan]")
            if target:
                console.print(f"[bold green][*] Running reconnaissance on {target}...[/bold green]")
                ctx.invoke(recon.recon_run, target=target)
            Prompt.ask("\n[dim]Press Enter to return to menu...[/dim]")

        elif choice == "4":
            workspace = Prompt.ask("[bold cyan]Enter workspace/scan path[/bold cyan]")
            if workspace:
                console.print(f"[bold green][*] Generating reports for {workspace}...[/bold green]")
                ctx.invoke(report.report_generate, scan_dir=workspace, format="json,md,html")
            Prompt.ask("\n[dim]Press Enter to return to menu...[/dim]")

        elif choice == "5":
            console.print("[bold green][*] Running system health check...[/bold green]")
            if hasattr(doctor, "doctor_run"):
                doctor.doctor_run()
            elif hasattr(doctor, "main"):
                doctor.main()
            Prompt.ask("\n[dim]Press Enter to return to menu...[/dim]")

        elif choice == "6":
            console.print("[bold red][!] Exiting SpiderForge CLI. (Web server stays active if running)[/bold red]")
            raise typer.Exit()


if __name__ == "__main__":
    app()