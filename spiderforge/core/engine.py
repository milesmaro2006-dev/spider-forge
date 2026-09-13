from urllib.parse import urlparse, parse_qs, urlunparse
from typing import Dict, Any, Optional
from spiderforge.scanners.xss import check_reflected_xss
from spiderforge.scanners.sqli import check_sql_injection
from spiderforge.scanners.headers import check_security_headers

def extract_url_params(target_url: str):
    parsed = urlparse(target_url)
    base_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', ''))
    raw_params = parse_qs(parsed.query)
    params = {k: v[0] for k, v in raw_params.items()}
    return base_url, params

async def run_full_security_assessment(target_url: str, params: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    base_url, parsed_params = extract_url_params(target_url)
    effective_params = params if params is not None else parsed_params
    
    all_findings = []
    
    # 1. Headers Check
    h_findings = await check_security_headers(base_url or target_url)
    all_findings.extend(h_findings)
    
    # 2. XSS & SQLi Check (إذا كانت الباراميترات متوفرة)
    if effective_params:
        xss_findings = await check_reflected_xss(base_url, effective_params)
        all_findings.extend(xss_findings)
        
        sqli_findings = await check_sql_injection(base_url, effective_params)
        all_findings.extend(sqli_findings)
        
    return {
        "target": target_url,
        "base_url": base_url,
        "parameters": effective_params,
        "total_findings": len(all_findings),
        "findings": all_findings
    }