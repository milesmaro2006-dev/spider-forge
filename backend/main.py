from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional, Dict
from spiderforge.core.engine import run_full_security_assessment

app = FastAPI(
    title="SpiderForge Web Platform",
    description="Unified Web and CLI Security Assessment Platform",
    version="2.0.0"
)

class ScanRequest(BaseModel):
    target: str
    params: Optional[Dict[str, str]] = None

@app.get("/")
def read_root():
    return {"status": "online", "tool": "SpiderForge", "mode": "Web Platform"}

@app.post("/api/scan")
async def run_web_scan(request: ScanRequest):
    """
    تنفيذ نفس محرك الفحص الموحد وإرجاع النتائج بصيغة JSON للداشبورد
    """
    results = await run_full_security_assessment(request.target, request.params)
    return {
        "status": "success",
        "data": results
    }