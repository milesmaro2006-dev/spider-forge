import os
from typing import Dict, Optional
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from spiderforge.core.engine import run_full_security_assessment

app = FastAPI(
    title="SpiderForge Web Platform",
    description="Unified Web and CLI Security Assessment Platform",
    version="2.0.0"
)

class ScanRequest(BaseModel):
    target: str
    params: Optional[Dict[str, str]] = None

# تقديم مجلد الواجهة كـ Static Files
frontend_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend"))

if os.path.exists(frontend_path):
    app.mount("/static", StaticFiles(directory=frontend_path), name="static")

@app.get("/")
def serve_index():
    index_file = os.path.join(frontend_path, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"status": "online", "message": "Frontend files not found, run via API."}

@app.get("/styles.css")
def serve_css():
    return FileResponse(os.path.join(frontend_path, "styles.css"))

@app.get("/app.js")
def serve_js():
    return FileResponse(os.path.join(frontend_path, "app.js"))

@app.post("/api/scan")
async def run_web_scan(request: ScanRequest):
    results = await run_full_security_assessment(request.target, request.params)
    return {
        "status": "success",
        "data": results
    }