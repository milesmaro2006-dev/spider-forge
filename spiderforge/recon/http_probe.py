from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import httpx

from spiderforge.scope.validator import ScopeValidator
from spiderforge.utils.logging import get_logger
from spiderforge.utils.urls import normalize_url

log = get_logger("recon.http")

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


@dataclass
class ProbeResult:
    url: str
    final_url: str | None = None
    status_code: int | None = None
    reason: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    content_type: str | None = None
    content_length: int | None = None
    title: str | None = None
    server: str | None = None
    redirects: list[str] = field(default_factory=list)
    elapsed_ms: float | None = None
    tls: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    body_snippet: str | None = None


def _extract_title(html: str) -> str | None:
    m = _TITLE_RE.search(html)
    if not m:
        return None
    text = re.sub(r"\s+", " ", m.group(1)).strip()
    return text[:300] or None


def _extract_tls(resp: httpx.Response) -> dict[str, Any]:
    """Best-effort TLS certificate extraction. Never raises."""
    info: dict[str, Any] = {}
    try:
        ext = resp.extensions or {}
        stream = ext.get("network_stream")
        ssl_obj = None
        if stream is not None and hasattr(stream, "get_extra_info"):
            ssl_obj = stream.get_extra_info("ssl_object")
        if ssl_obj is None:
            return info
        try:
            cert = ssl_obj.getpeercert()
        except Exception:
            cert = None
        if cert:
            info["subject"] = dict(x[0] for x in cert.get("subject", ()))
            info["issuer"] = dict(x[0] for x in cert.get("issuer", ()))
            info["notBefore"] = cert.get("notBefore")
            info["notAfter"] = cert.get("notAfter")
            info["subjectAltName"] = [v for _, v in cert.get("subjectAltName", [])]
        info["version"] = ssl_obj.version()
        cipher = ssl_obj.cipher()
        if cipher:
            info["cipher"] = {"name": cipher[0], "protocol": cipher[1], "bits": cipher[2]}
    except Exception as exc:  # noqa: BLE001
        info["error"] = f"{type(exc).__name__}: {exc}"
    return info


async def probe(
    url: str,
    *,
    scope: ScopeValidator,
    client: httpx.AsyncClient | None = None,
    max_body: int = 200_000,
    verify_tls: bool = True,
    timeout: float = 20.0,
) -> ProbeResult:
    """Fetch a URL and extract structured metadata.

    Returns ``ProbeResult(error="out_of_scope")`` without making any request
    if the target fails the scope check.
    """
    normalized = normalize_url(url)
    if not scope.is_allowed(normalized):
        return ProbeResult(url=normalized, error="out_of_scope")

    owns_client = client is None
    if owns_client:
        client = httpx.AsyncClient(
            follow_redirects=True,
            timeout=timeout,
            verify=verify_tls,
        )

    try:
        assert client is not None
        resp = await client.get(normalized)
        result = ProbeResult(
            url=normalized,
            final_url=str(resp.url),
            status_code=resp.status_code,
            reason=resp.reason_phrase,
            headers={k.lower(): v for k, v in resp.headers.items()},
            content_type=resp.headers.get("content-type"),
            content_length=len(resp.content),
            server=resp.headers.get("server"),
            redirects=[str(h.url) for h in resp.history],
        )
        try:
            result.elapsed_ms = resp.elapsed.total_seconds() * 1000 if resp.elapsed else None
        except Exception:  # noqa: BLE001
            result.elapsed_ms = None

        ctype = (result.content_type or "").lower()
        if any(k in ctype for k in ("text/", "html", "json", "javascript", "xml")):
            try:
                text = resp.text
            except Exception:  # noqa: BLE001
                text = resp.content.decode("utf-8", errors="replace")
            if "html" in ctype:
                result.title = _extract_title(text[:max_body])
            result.body_snippet = text[:2000]

        if normalized.startswith("https://"):
            result.tls = _extract_tls(resp)

        return result

    except httpx.HTTPError as exc:
        return ProbeResult(url=normalized, error=f"{type(exc).__name__}: {exc}")
    finally:
        if owns_client:
            await client.aclose()