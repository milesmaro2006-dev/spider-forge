# spiderforge/scanners/sqli.py
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, parse_qs

import httpx


# Payloads آمنة لفحص Error-based SQLi
SQLI_PAYLOADS: List[str] = [
    "'",
    "\"",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "') OR ('1'='1",
    "1' AND '1'='2",
    "1 AND 1=CONVERT(int, @@version)",  # MSSQL
]

# أنماط أخطاء قواعد البيانات الشائعة (MySQL / PostgreSQL / MSSQL / Oracle / SQLite)
SQL_ERROR_PATTERNS: List[tuple] = [
    (re.compile(r"you have an error in your sql syntax", re.I), "MySQL syntax error"),
    (re.compile(r"warning:\s*mysql_", re.I), "MySQL warning"),
    (re.compile(r"mysql_fetch_(array|assoc|row|object)", re.I), "MySQL fetch error"),
    (re.compile(r"supplied argument is not a valid mysql", re.I), "MySQL argument error"),
    (re.compile(r"unclosed quotation mark after the character string", re.I), "MSSQL unclosed quote"),
    (re.compile(r"microsoft ole db provider for sql server", re.I), "MSSQL OLE DB error"),
    (re.compile(r"microsoft sql native client error", re.I), "MSSQL Native Client error"),
    (re.compile(r"quoted string not properly terminated", re.I), "Oracle quoted string error"),
    (re.compile(r"\bORA-\d{4,5}\b", re.I), "Oracle ORA error"),
    (re.compile(r"pg_query\(\)", re.I), "PostgreSQL pg_query error"),
    (re.compile(r"postgresql.*error", re.I), "PostgreSQL error"),
    (re.compile(r"psql:.*error", re.I), "PostgreSQL psql error"),
    (re.compile(r"sqlite3\.operationalerror", re.I), "SQLite OperationalError"),
    (re.compile(r"sqlite error", re.I), "SQLite error"),
    (re.compile(r"sqlstate\[", re.I), "SQLSTATE error"),
    (re.compile(r"division by zero", re.I), "SQL division by zero"),
]


def _extract_params(url: str) -> Dict[str, str]:
    """استخراج Query Parameters من الرابط."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    return {k: (v[0] if v else "") for k, v in qs.items()}


def _base_url(url: str) -> str:
    return url.split("?", 1)[0]


def _extract_snippet(text: str, match: re.Match) -> str:
    start = max(0, match.start() - 80)
    end = min(len(text), match.end() + 80)
    return text[start:end].replace("\n", " ").replace("\r", " ").strip()


async def check_sql_injection(
    url: str,
    client: Optional[httpx.AsyncClient] = None,
    params: Optional[Dict[str, str]] = None,
) -> List[Dict[str, Any]]:
    """فحص Error-based SQL Injection على كل Query Parameter."""
    findings: List[Dict[str, Any]] = []

    target_params = params if params is not None else _extract_params(url)
    if not target_params:
        return findings  # لا يوجد مدخلات للفحص

    base = _base_url(url)

    own_client = False
    if client is None:
        client = httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=True)
        own_client = True

    try:
        for param_name in target_params.keys():
            for payload in SQLI_PAYLOADS:
                test_params = dict(target_params)
                test_params[param_name] = payload

                try:
                    resp = await client.get(base, params=test_params)
                except httpx.RequestError:
                    continue

                body = resp.text or ""
                matched: Optional[tuple] = None
                for pattern, err_name in SQL_ERROR_PATTERNS:
                    m = pattern.search(body)
                    if m:
                        matched = (err_name, m)
                        break

                if matched:
                    err_name, m = matched
                    snippet = _extract_snippet(body, m)
                    findings.append({
                        "title": f"SQL Injection (Error-Based) in parameter '{param_name}'",
                        "severity": "High",
                        "description": (
                            f"الباراميتر '{param_name}' قابل للحقن عبر Error-based SQL Injection. "
                            "الخادم أرجع رسالة خطأ من قاعدة البيانات تحتوي على معلومات داخلية "
                            "يمكن استغلالها لاستخراج البيانات."
                        ),
                        "param": param_name,
                        "evidence": (
                            f"DB error: {err_name} | Payload: {payload} | "
                            f"Status: {resp.status_code} | Snippet: ...{snippet}..."
                        ),
                    })
                    break  # اكتفِ بأول Payload ناجح لكل باراميتر
    finally:
        if own_client:
            await client.aclose()

    return findings
