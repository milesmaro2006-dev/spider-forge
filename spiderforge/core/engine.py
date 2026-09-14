# spiderforge/core/engine.py
from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

from spiderforge.scanners.headers import check_security_headers
from spiderforge.scanners.sqli import check_sql_injection
from spiderforge.scanners.xss import check_reflected_xss


def _normalize_target(target: str) -> str:
    target = target.strip()
    if not target.startswith(("http://", "https://")):
        target = "http://" + target
    return target


def _merge_params(url: str, params: Optional[Dict[str, str]]) -> str:
    if not params:
        return url
    parsed = urlparse(url)
    existing = parse_qs(parsed.query, keep_blank_values=True)
    for k, v in params.items():
        existing[k] = [v]
    new_query = urlencode(existing, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


async def run_full_security_assessment(
    target: str,
    params: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """تشغيل الفحوصات الثلاثة بشكل متزامن على AsyncClient واحد."""

    target = _normalize_target(target)
    target = _merge_params(target, params)

    findings: List[Dict[str, Any]] = []

    async with httpx.AsyncClient(
        timeout=10.0,
        verify=False,
        follow_redirects=True,
        headers={"User-Agent": "SpiderForge/2.0 (+security-scanner)"},
    ) as client:
        # تشغيل الفحوصات الثلاثة بالتوازي
        headers_task = check_security_headers(target, client)
        sqli_task = check_sql_injection(target, client)
        xss_task = check_reflected_xss(target, client)

        headers_findings, sqli_findings, xss_findings = await asyncio.gather(
            headers_task, sqli_task, xss_task, return_exceptions=False
        )

        findings.extend(headers_findings)
        findings.extend(sqli_findings)
        findings.extend(xss_findings)

    return {
        "target": target,
        "total_issues": len(findings),
        "findings": findings,
    }
