# spiderforge/scanners/xss.py
from __future__ import annotations

from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, parse_qs

import httpx


# Payloads مميزة لتقليل الـ False Positives
XSS_PAYLOADS: List[str] = [
    "<sf_probe_9f3a>",
    "'\"><sf_probe_9f3a>",
    "<script>sf_probe_9f3a</script>",
    "\"><img src=x onerror=sf_probe_9f3a>",
]


def _extract_params(url: str) -> Dict[str, str]:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    return {k: (v[0] if v else "") for k, v in qs.items()}


def _base_url(url: str) -> str:
    return url.split("?", 1)[0]


async def check_reflected_xss(
    url: str,
    client: Optional[httpx.AsyncClient] = None,
    params: Optional[Dict[str, str]] = None,
) -> List[Dict[str, Any]]:
    """
    فحص Reflected XSS:
    - يحقن Payload مميز.
    - يتحقق من انعكاسه في الـ Body دون HTML-encoding.
    """
    findings: List[Dict[str, Any]] = []

    target_params = params if params is not None else _extract_params(url)
    if not target_params:
        return findings

    base = _base_url(url)

    own_client = False
    if client is None:
        client = httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=True)
        own_client = True

    try:
        for param_name in target_params.keys():
            for payload in XSS_PAYLOADS:
                test_params = dict(target_params)
                test_params[param_name] = payload

                try:
                    resp = await client.get(base, params=test_params)
                except httpx.RequestError:
                    continue

                body = resp.text or ""

                # انعكاس حقيقي غير مُرمَّز
                if payload in body:
                    idx = body.find(payload)
                    start = max(0, idx - 80)
                    end = min(len(body), idx + len(payload) + 80)
                    snippet = body[start:end].replace("\n", " ").strip()

                    findings.append({
                        "title": f"Reflected XSS in parameter '{param_name}'",
                        "severity": "High",
                        "description": (
                            f"الباراميتر '{param_name}' يُنعكس في استجابة الخادم بدون HTML-encoding، "
                            "مما يسمح بتنفيذ JavaScript في متصفح الضحية (Reflected XSS)."
                        ),
                        "param": param_name,
                        "evidence": (
                            f"Payload reflected unencoded | Payload: {payload} | "
                            f"Status: {resp.status_code} | Context: ...{snippet}..."
                        ),
                    })
                    break  # أول انعكاس ناجح يكفي للباراميتر
    finally:
        if own_client:
            await client.aclose()

    return findings
