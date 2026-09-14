# backend/main.py
from __future__ import annotations

import mimetypes
import os
from typing import Dict, Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from spiderforge.core.engine import run_full_security_assessment

app = FastAPI(
    title="SpiderForge Web Platform",
    description="Unified Web and CLI Security Assessment Platform",
    version="2.0.0",
)


class ScanRequest(BaseModel):
    target: str = Field(
        ...,
        description="Target URL, e.g. http://testphp.vulnweb.com/listproducts.php?cat=1",
    )
    params: Optional[Dict[str, str]] = None


# ---------- Paths ----------
PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)
frontend_path = os.path.join(PROJECT_ROOT, "frontend")
REPORTS_ROOT = PROJECT_ROOT  # كل workspaces تحت جذر المشروع


# ---------- Static / Frontend ----------
if os.path.exists(frontend_path):
    app.mount("/static", StaticFiles(directory=frontend_path), name="static")


@app.get("/")
def serve_index():
    index_file = os.path.join(frontend_path, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"status": "online", "message": "Frontend files not found, use the API."}


@app.get("/styles.css")
def serve_css():
    return FileResponse(os.path.join(frontend_path, "styles.css"))


@app.get("/app.js")
def serve_js():
    return FileResponse(os.path.join(frontend_path, "app.js"))


# ---------- Scan API ----------
@app.post("/api/scan")
async def run_web_scan(request: ScanRequest):
    target = (request.target or "").strip()
    if not target:
        raise HTTPException(status_code=400, detail="`target` is required.")

    try:
        results = await run_full_security_assessment(
            target=target,
            params=request.params,
        )
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(
            status_code=502,
            content={
                "status": "error",
                "target": target,
                "total_issues": 0,
                "findings": [],
                "detail": f"Scan failed: {type(exc).__name__}: {exc}",
            },
        )

    findings = results.get("findings", []) if isinstance(results, dict) else []
    resolved_target = (
        results.get("target", target) if isinstance(results, dict) else target
    )

    return {
        "status": "success",
        "target": resolved_target,
        "total_issues": len(findings),
        "findings": findings,
    }


# ---------- Reports API ----------

def _safe_join(base: str, *parts: str) -> str:
    """يمنع path traversal خارج base."""
    base = os.path.abspath(base)
    p = os.path.abspath(os.path.join(base, *parts))
    if not (p == base or p.startswith(base + os.sep)):
        raise HTTPException(status_code=400, detail="Invalid path.")
    return p


@app.get("/api/reports/{workspace}")
def list_workspace_reports(workspace: str):
    """يسرد ملفات التقارير المتاحة في workspace مع روابطها."""
    reports_dir = _safe_join(REPORTS_ROOT, workspace, "reports")
    if not os.path.isdir(reports_dir):
        raise HTTPException(status_code=404, detail="No reports directory.")

    files = []
    for name in sorted(os.listdir(reports_dir)):
        p = os.path.join(reports_dir, name)
        if not os.path.isfile(p):
            continue
        files.append({
            "name": name,
            "size": os.path.getsize(p),
            "inline_url": f"/reports/{workspace}/download/{name}",
            "download_url": f"/reports/{workspace}/download/{name}?as_attachment=true",
        })
    return {"workspace": workspace, "files": files}


@app.get("/reports/{workspace}/download/{filename}")
def download_report(
    workspace: str,
    filename: str,
    as_attachment: bool = False,
):
    """
    يخدم تقريراً من أي workspace داخل جذر المشروع.
    - افتراضياً: inline (يُعرض في المتصفح).
    - `?as_attachment=true`: يجبر التحميل مباشرة.
    """
    file_path = _safe_join(REPORTS_ROOT, workspace, "reports", filename)

    if not os.path.isfile(file_path):
        raise HTTPException(status_code=404, detail="Report not found.")

    media_type, _ = mimetypes.guess_type(file_path)
    media_type = media_type or "application/octet-stream"

    return FileResponse(
        file_path,
        media_type=media_type,
        filename=os.path.basename(file_path),
        content_disposition_type="attachment" if as_attachment else "inline",
    )


@app.get("/reports/{workspace}/view/{filename}")
def view_report(workspace: str, filename: str):
    """اختصار لفتح التقرير inline بدون الحاجة لكتابة download في المسار."""
    return download_report(workspace=workspace, filename=filename, as_attachment=False)
