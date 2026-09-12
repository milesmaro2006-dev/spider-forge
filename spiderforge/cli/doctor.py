from __future__ import annotations

import importlib.util
import shutil
import sys

from rich.console import Console
from rich.table import Table

from spiderforge import __version__
from spiderforge.config.defaults import (
    DEFAULT_CONFIG_FILE,
    DEFAULT_DATA_DIR,
    DEFAULT_DB_PATH,
)
from spiderforge.database.engine import init_db

console = Console()


def _row(label: str, ok: bool, detail: str = "") -> tuple[str, str, str]:
    mark = "[green]✓[/green]" if ok else "[red]✗[/red]"
    return label, mark, detail


def doctor() -> None:
    """Diagnostic report of the SpiderForge installation."""
    table = Table(title=f"SpiderForge {__version__} — Doctor", show_lines=False)
    table.add_column("Component", style="cyan", no_wrap=True)
    table.add_column("Status", justify="center")
    table.add_column("Detail", style="dim")

    table.add_row(*_row("Python", sys.version_info >= (3, 10), sys.version.split()[0]))

    try:
        init_db()
        table.add_row(*_row("Database", True, str(DEFAULT_DB_PATH)))
    except Exception as exc:  # noqa: BLE001
        table.add_row(*_row("Database", False, str(exc)))

    for mod, name in [
        ("playwright", "Playwright"),
        ("weasyprint", "WeasyPrint (PDF)"),
        ("yaml", "PyYAML"),
        ("httpx", "httpx"),
        ("bs4", "BeautifulSoup4"),
    ]:
        ok = importlib.util.find_spec(mod) is not None
        table.add_row(*_row(name, ok, "installed" if ok else "not installed"))

    for tool in ["nmap", "httpx", "nuclei", "ffuf"]:
        path = shutil.which(tool)
        table.add_row(*_row(tool, path is not None, path or "not found in PATH"))

    try:
        DEFAULT_DATA_DIR.mkdir(parents=True, exist_ok=True)
        table.add_row(*_row("Workspace dir", DEFAULT_DATA_DIR.is_dir(), str(DEFAULT_DATA_DIR)))
    except Exception as exc:  # noqa: BLE001
        table.add_row(*_row("Workspace dir", False, str(exc)))

    cfg_ok = DEFAULT_CONFIG_FILE.exists()
    table.add_row(
        *_row(
            "Config file",
            cfg_ok,
            str(DEFAULT_CONFIG_FILE) if cfg_ok else "not present (defaults will be used)",
        )
    )

    console.print(table)