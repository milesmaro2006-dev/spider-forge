from typing import Dict, Any, Optional
from spiderforge.scanners.xss import check_reflected_xss

async def run_full_security_assessment(target_url: str, params: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """
    المحرك الموحد الذي تستدعيه واجهة الـ CLI أو الـ Web API
    """
    if params is None:
        params = {"q": "test", "id": "1"}
        
    all_findings = []
    
    # 1. فحص XSS
    xss_results = await check_reflected_xss(target_url, params)
    if xss_results:
        all_findings.extend(xss_results)
        
    return {
        "target": target_url,
        "total_findings": len(all_findings),
        "findings": all_findings
    }