import httpx
from typing import List, Dict, Any

SQLI_PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
]

SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "pg_query()",
    "sqlite3.operationalerror",
]

async def check_sql_injection(url: str, params: Dict[str, str]) -> List[Dict[str, Any]]:
    findings = []
    async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
        for param_name in params.keys():
            for payload in SQLI_PAYLOADS:
                test_params = params.copy()
                test_params[param_name] = payload
                try:
                    response = await client.get(url, params=test_params)
                    text_lower = response.text.lower()
                    for err in SQL_ERRORS:
                        if err in text_lower:
                            findings.append({
                                "type": "SQL Injection (Error-Based)",
                                "severity": "High",
                                "param": param_name,
                                "payload": payload,
                                "evidence": f"Matched signature: '{err}'"
                            })
                            break
                except httpx.RequestError:
                    continue
    return findings