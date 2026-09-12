from __future__ import annotations

import json
from pathlib import Path

from spiderforge.reporting.models import ReportContext


def render(ctx: ReportContext, out_path: Path) -> Path:
    payload = {
        "meta": {
            "project": ctx.meta.project_name,
            "scan_id": ctx.meta.scan_id,
            "target": ctx.meta.target,
            "started_at": ctx.meta.started_at,
            "finished_at": ctx.meta.finished_at,
            "author": ctx.meta.author,
        },
        "scope": {"include": ctx.scope_include, "exclude": ctx.scope_exclude},
        "stats": ctx.stats,
        "severity_counts": ctx.severity_counts(),
        "module_errors": ctx.module_errors,
        "recon": ctx.recon,
        "discovery": ctx.discovery,
        "findings": [f.model_dump(mode="json") for f in ctx.findings],
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    return out_path