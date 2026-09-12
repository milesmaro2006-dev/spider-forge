from __future__ import annotations

import typer
from rich.console import Console
from rich.panel import Panel

from spiderforge import __version__
from spiderforge.cli import browser as browser_module
from spiderforge.cli import config as config_module
from spiderforge.cli import crawl as crawl_module
from spiderforge.cli import discover as discover_module
from spiderforge.cli import doctor as doctor_module
from spiderforge.cli import findings as findings_module
from spiderforge.cli import history as history_module
from spiderforge.cli import integrations as integrations_module
from spiderforge.cli import modules as modules_module
from spiderforge.cli import recon as recon_module
from spiderforge.cli import report as report_module
from spiderforge.cli import scan as scan_module
from spiderforge.cli import scope as scope_module
from spiderforge.cli import update as update_module
from spiderforge.utils.logging import setup_logging

app = typer.Typer(
    name="spiderforge",
    help="SpiderForge — Personal Web Security Assessment Platform.",
    no_args_is_help=False,
    add_completion=False,
    rich_markup_mode="rich",
)
console = Console()


@app.callback(invoke_without_command=True)
def _root(
    ctx: typer.Context,
    version: bool = typer.Option(
        False, "--version", "-V", help="Show version and exit.", is_eager=True
    ),
) -> None:
    if version:
        console.print(f"SpiderForge {__version__}")
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        _banner()


def _banner() -> None:
    console.print(
        Panel.fit(
            f"[bold cyan]SPIDERFORGE[/bold cyan]\n"
            f"[white]Web Security Assessment Engine[/white]\n\n"
            f"Version: [bold]{__version__}[/bold]\n\n"
            f"[bold]Commands:[/bold]\n"
            f"  scan         Full assessment (recon → crawl → discover → analyze)\n"
            f"  recon        DNS, HTTP probe, tech detection, robots, sitemap\n"
            f"  crawl        Async crawler\n"
            f"  discover     Endpoints, params, APIs, JS, Swagger, GraphQL\n"
            f"  modules      List / inspect security modules\n"
            f"  findings     List / show / confirm / false-positive / retest\n"
            f"  report       Generate JSON/MD/HTML/PDF reports\n"
            f"  history      Scan history and diffs\n"
            f"  scope        Parse and validate scope files\n"
            f"  config       Inspect effective configuration\n"
            f"  browser      Playwright / Chromium management\n"
            f"  integrations Check external tool availability\n"
            f"  doctor       System readiness\n"
            f"  update       Check for updates",
            title="SpiderForge",
            border_style="cyan",
        )
    )


app.command(name="doctor", help="Check system readiness.")(doctor_module.doctor)


@app.command(name="version", help="Print version and exit.")
def version_cmd() -> None:
    console.print(f"SpiderForge {__version__}")


app.add_typer(scope_module.app, name="scope")
app.add_typer(config_module.app, name="config")
app.add_typer(recon_module.app, name="recon")
app.add_typer(crawl_module.app, name="crawl")
app.add_typer(discover_module.app, name="discover")
app.add_typer(scan_module.app, name="scan")
app.add_typer(modules_module.app, name="modules")
app.add_typer(findings_module.app, name="findings")
app.add_typer(report_module.app, name="report")
app.add_typer(history_module.app, name="history")
app.add_typer(browser_module.app, name="browser")
app.add_typer(integrations_module.app, name="integrations")
app.add_typer(update_module.app, name="update")


def main() -> None:  # pragma: no cover
    setup_logging()
    app()


if __name__ == "__main__":
    main()