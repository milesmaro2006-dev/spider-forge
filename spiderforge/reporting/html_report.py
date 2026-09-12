from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from spiderforge.reporting.models import ReportContext

_TEMPLATES_DIR = Path(__file__).parent / "templates"
_ASSETS_DIR = Path(__file__).parent / "assets"


def _env() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def render_html(ctx: ReportContext) -> str:
    env = _env()
    tmpl = env.get_template("report.html.j2")
    css = (_ASSETS_DIR / "report.css").read_text(encoding="utf-8")
    return tmpl.render(
        meta=ctx.meta,
        scope_include=ctx.scope_include,
        scope_exclude=ctx.scope_exclude,
        findings=ctx.findings,
        counts=ctx.severity_counts(),
        total_findings=len(ctx.findings),
        module_count=ctx.stats.get("modules_run", "N/A"),
        discovery=ctx.discovery,
        module_errors=ctx.module_errors,
        css=css,
    )


def render(ctx: ReportContext, out_path: Path) -> Path:
    html = render_html(ctx)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html, encoding="utf-8")
    return out_path