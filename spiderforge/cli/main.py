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

# تسجيل الأوامر الرئيسية المتاحة
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
[bold cyan]  [+] Framework:[/bold cyan] SpiderForge v1.0.0    [bold cyan]• Author:[/bold cyan] Spidey (@redteam)
[bold cyan]  [+] Core Engine:[/bold cyan] Async / Modular       [bold cyan]• Security Modules:[/bold cyan] 12 Active
[dim white]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/dim white]
"""

@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    """
    SpiderForge CLI Framework. If no command is provided, an interactive menu will launch.
    """
    if ctx.invoked_subcommand is not None:
        return

    # عرض الواجهة التفاعلية بالبانر الجديد
    console.clear()
    console.print(BANNER)
    console.print(Panel("[bold green]Welcome to SpiderForge Interactive Control Center[/bold green]\nPlease select an option below to get started:", title="[b]Interactive Mode[/b]", border_style="red"))

    while True:
        console.print("\n[1] 🎯 Run Full Assessment (Scan)")
        console.print("[2] 🔍 Run Reconnaissance Only")
        console.print("[3] 📊 Generate Reports")
        console.print("[4] 🩺 Run System Diagnostics (Doctor)")
        console.print("[5] 🚪 Exit")

        choice = Prompt.ask("\n[bold yellow]Select an option[/bold yellow]", choices=["1", "2", "3", "4", "5"], default="1")

        if choice == "1":
            target = Prompt.ask("[bold cyan]Enter target URL (e.g., http://example.com)[/bold cyan]")
            if target:
                console.print(f"[bold green][*] Launching full assessment on {target}...[/bold green]")
                ctx.invoke(scan.scan_run, target=target)
            break
        elif choice == "2":
            target = Prompt.ask("[bold cyan]Enter target URL for recon[/bold cyan]")
            if target:
                console.print(f"[bold green][*] Running reconnaissance on {target}...[/bold green]")
                ctx.invoke(recon.recon_run, target=target)
            break
        elif choice == "3":
            workspace = Prompt.ask("[bold cyan]Enter workspace/scan path[/bold cyan]")
            if workspace:
                console.print(f"[bold green][*] Generating reports for {workspace}...[/bold green]")
                ctx.invoke(report.report_generate, scan_dir=workspace, format="json,md,html")
            break
        elif choice == "4":
            console.print("[bold green][*] Running system health check...[/bold green]")
            if hasattr(doctor, "doctor_run"):
                doctor.doctor_run()
            elif hasattr(doctor, "main"):
                doctor.main()
            break
        elif choice == "5":
            console.print("[bold red][!] Exiting SpiderForge. Stay safe![/bold red]")
            raise typer.Exit()

if __name__ == "__main__":
    app()
