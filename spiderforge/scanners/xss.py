import httpx
from typing import List, Dict, Any

TEST_PAYLOADS = [
    "<script>alert('SpiderForge')</script>",
    "\"><script>alert('SpiderForge')</script>",
    "<img src=x onerror=alert('SpiderForge')>",
]

async def check_reflected_xss(url: str, params: Dict[str, str]) -> List[Dict[str, Any]]:
    """
    فحص مدخلات الرابط لاكتشاف Reflected XSS
    """
    findings = []
    
    async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
        for param_name in params.keys():
            for payload in TEST_PAYLOADS:
                test_params = params.copy()
                test_params[param_name] = payload
                
                try:
                    response = await client.get(url, params=test_params)
                    if payload in response.text:
                        findings.append({
                            "type": "Reflected XSS",
                            "severity": "High",
                            "param": param_name,
                            "payload": payload,
                            "evidence": f"Reflected in response for param: {param_name}"
                        })
                        break
                except httpx.RequestError:
                    continue
                    
    return findings