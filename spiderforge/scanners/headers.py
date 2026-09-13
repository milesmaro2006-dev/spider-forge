import httpx
from typing import List, Dict, Any

REQUIRED_HEADERS = {
    "Strict-Transport-Security": "Missing HSTS Header (Vulnerable to MITM)",
    "Content-Security-Policy": "Missing CSP Header (Vulnerable to XSS / Injection)",
    "X-Frame-Options": "Missing X-Frame-Options (Vulnerable to Clickjacking)",
    "X-Content-Type-Options": "Missing X-Content-Type-Options (MIME-sniffing risk)"
}

async def check_security_headers(url: str) -> List[Dict[str, Any]]:
    findings = []
    try:
        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            resp = await client.get(url)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            for h_name, desc in REQUIRED_HEADERS.items():
                if h_name.lower() not in headers:
                    findings.append({
                        "type": "Missing Security Header",
                        "severity": "Low",
                        "param": "Header",
                        "payload": h_name,
                        "evidence": desc
                    })
    except httpx.RequestError:
        pass
    return findings