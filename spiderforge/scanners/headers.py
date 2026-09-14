# spiderforge/scanners/headers.py
from __future__ import annotations

from typing import Any, Dict, List, Optional
import httpx


# الترويسات المطلوبة + معلومات كل ترويسة ناقصة
REQUIRED_HEADERS: Dict[str, Dict[str, str]] = {
    "Content-Security-Policy": {
        "title": "Missing Content-Security-Policy Header",
        "severity": "Low",
        "description": (
            "ترويسة CSP تحمي من XSS وحقن المحتوى. أضف سياسة مثل: "
            "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'."
        ),
    },
    "Strict-Transport-Security": {
        "title": "Missing Strict-Transport-Security (HSTS) Header",
        "severity": "Low",
        "description": (
            "HSTS تُجبر المتصفح على استخدام HTTPS وتمنع هجمات MITM/SSL-Strip. "
            "أضف: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload."
        ),
    },
    "X-Frame-Options": {
        "title": "Missing X-Frame-Options Header",
        "severity": "Low",
        "description": (
            "X-Frame-Options تحمي من Clickjacking عبر منع تضمين الصفحة داخل iframe. "
            "أضف: X-Frame-Options: DENY (أو SAMEORIGIN)."
        ),
    },
    "X-Content-Type-Options": {
        "title": "Missing X-Content-Type-Options Header",
        "severity": "Low",
        "description": (
            "تمنع MIME sniffing الذي قد يؤدي إلى تنفيذ محتوى ضار. "
            "أضف: X-Content-Type-Options: nosniff."
        ),
    },
    "Referrer-Policy": {
        "title": "Missing Referrer-Policy Header",
        "severity": "Info",
        "description": (
            "تتحكم في كمية معلومات الـ Referrer المُرسَلة للطرف الآخر. "
            "أضف: Referrer-Policy: strict-origin-when-cross-origin."
        ),
    },
}


async def check_security_headers(
    url: str,
    client: Optional[httpx.AsyncClient] = None,
) -> List[Dict[str, Any]]:
    """فحص وجود الترويسات الأمنية الأساسية (Passive Check)."""
    findings: List[Dict[str, Any]] = []

    own_client = False
    if client is None:
        client = httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=True)
        own_client = True

    try:
        resp = await client.get(url)
        present = {k.lower() for k in resp.headers.keys()}

        for header_name, meta in REQUIRED_HEADERS.items():
            if header_name.lower() not in present:
                findings.append({
                    "title": meta["title"],
                    "severity": meta["severity"],
                    "description": meta["description"],
                    "param": "HTTP-Header",
                    "evidence": (
                        f"Response header '{header_name}' is not present. "
                        f"Status: {resp.status_code} | URL: {resp.url}"
                    ),
                })
    except httpx.RequestError as exc:
        findings.append({
            "title": "Header check skipped (connection error)",
            "severity": "Info",
            "description": "تعذّر الاتصال بالهدف لفحص الترويسات الأمنية.",
            "param": "N/A",
            "evidence": f"{type(exc).__name__}: {exc}",
        })
    finally:
        if own_client:
            await client.aclose()

    return findings
