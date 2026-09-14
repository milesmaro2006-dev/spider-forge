# spiderforge/cli/report.py
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from spiderforge.findings.models import Finding
from spiderforge.reporting import html_report, json_report, markdown_report, pdf_report
from spiderforge.reporting.models import ReportContext, ReportMeta
from spiderforge.utils.logging import setup_logging
from spiderforge.utils.timestamps import isoformat

app = typer.Typer(name="report", help="Generate reports from a scan workspace.")
console = Console()

VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}


# ─────────────────── Normalization helpers ───────────────────

def _infer_category(title: str) -> str:
    t = (title or "").lower()
    if "sql" in t:
        return "injection"
    if "xss" in t or "cross-site" in t:
        return "xss"
    if "header" in t:
        return "headers"
    if "csrf" in t:
        return "csrf"
    if "redirect" in t:
        return "redirect"
    if "disclosure" in t or "exposure" in t or "leak" in t:
        return "disclosure"
    if "clickjack" in t or "frame" in t:
        return "clickjacking"
    return "general"


def _coerce_severity(value: Any) -> str:
    s = str(value or "info").strip().lower()
    if s in VALID_SEVERITIES:
        return s
    # مرادفات شائعة
    aliases = {
        "moderate": "medium",
        "informational": "info",
        "none": "info",
        "critical ": "critical",
    }
    return aliases.get(s, "info")


def _coerce_evidence(value: Any, payload: str = "") -> dict:
    """يضمن أن evidence dict صالح (وليس نصاً أو None)."""
    if isinstance(value, dict):
        ev = dict(value)
    else:
        text = "" if value is None else str(value)
        ev = {"summary": text}

    # املأ الحقول الشائعة بشكل غير مؤذٍ (Pydantic يتجاهل الحقول غير المعروفة افتراضياً)
    ev.setdefault("summary", "")
    ev.setdefault("payload", payload or "")
    ev.setdefault("request", "")
    ev.setdefault("response", "")
    return ev


def _make_fingerprint(title: str, param: str, url: str) -> str:
    raw = f"{title}|{param}|{url}".encode("utf-8", errors="ignore")
    return hashlib.sha1(raw).hexdigest()[:16]


def _normalize_finding(raw: dict, index: int, default_url: str) -> dict:
    """
    يحوّل أي صيغة Finding إلى الصيغة التي يتوقعها `Finding.model_validate`:
    - إن كانت الصيغة الأساسية موجودة → نُمرِّرها بعد تصحيح severity/evidence.
    - وإن كانت صيغة الـ scanner (title/severity/param/evidence) → نبني الصيغة الكاملة.
    """
    if not isinstance(raw, dict):
        raw = {"title": str(raw), "severity": "info"}

    required = {"id", "fingerprint", "category", "severity", "url", "evidence"}
    has_canonical = required.issubset(raw.keys())

    if has_canonical:
        out = dict(raw)
        out["severity"] = _coerce_severity(out.get("severity"))
        out["evidence"] = _coerce_evidence(out.get("evidence"), out.get("payload", ""))
        return out

    # ── صيغة الـ scanner → نحوّلها ──
    title = raw.get("title") or raw.get("type") or raw.get("name") or f"Finding #{index + 1}"
    param = str(raw.get("param") or raw.get("parameter") or "")
    url = str(raw.get("url") or raw.get("target") or default_url or "")
    payload = str(raw.get("payload") or "")
    severity = _coerce_severity(raw.get("severity"))

    return {
        "id": raw.get("id") or f"F-{index + 1:04d}",
        "fingerprint": raw.get("fingerprint") or _make_fingerprint(title, param, url),
        "category": raw.get("category") or _infer_category(title),
        "severity": severity,
        "url": url,
        "title": title,
        "description": raw.get("description") or raw.get("desc") or "",
        "param": param,
        "payload": payload,
        "evidence": _coerce_evidence(raw.get("evidence"), payload),
        # حقول إضافية اختيارية — يتجاهلها Pydantic إن لم تُعرَّف
        "remediation": raw.get("remediation") or "",
        "cwe": raw.get("cwe") or "",
        "owasp": raw.get("owasp") or "",
        "tags": raw.get("tags") or [],
    }


# ─────────────────── Workspace loader ───────────────────

def _load_workspace(workspace: Path) -> ReportContext:
    if not workspace.exists():
        raise typer.BadParameter(f"workspace not found: {workspace}")

    scan_json = workspace / "scan.json"
    findings_json = workspace / "findings.json"
    if not scan_json.exists():
        raise typer.BadParameter(f"scan.json not found in {workspace}")

    try:
        data = json.loads(scan_json.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise typer.BadParameter(f"scan.json is not valid JSON: {exc}") from exc

    findings_data: list[dict] = []
    if findings_json.exists():
        try:
            findings_data = json.loads(findings_json.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            findings_data = []
    else:
        findings_data = data.get("findings", []) or []

    default_url = str(data.get("target") or data.get("final_url") or "")

    findings: list[Finding] = []
    skipped: list[str] = []
    for i, raw in enumerate(findings_data):
        normalized = _normalize_finding(raw, i, default_url)
        try:
            findings.append(Finding.model_validate(normalized))
        except Exception as exc:  # noqa: BLE001
            skipped.append(f"#{i + 1} ({normalized.get('title', '?')}): {exc}")

    if skipped:
        console.print(
            f"[yellow][!] Skipped {len(skipped)} malformed finding(s):[/yellow]"
        )
        for line in skipped[:5]:
            console.print(f"    [dim]{line}[/dim]")
        if len(skipped) > 5:
            console.print(f"    [dim]... {len(skipped) - 5} more[/dim]")

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


# ─────────────────── CLI command ───────────────────

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
        except Exception as exc:  # noqa: BLE001
            console.print(f"[yellow]pdf skipped:[/yellow] {type(exc).__name__}: {exc}")

    if not written:
        console.print("[yellow][!] No reports were generated (empty format list?).[/yellow]")
        return

    for p in written:
        console.print(f"[green]wrote[/green] {p}")
