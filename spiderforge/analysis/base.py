from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

from spiderforge.config.models import SpiderForgeConfig
from spiderforge.findings.models import Evidence, Finding, FindingStatus, Severity
from spiderforge.findings.dedupe import finding_fingerprint
from spiderforge.findings.confidence import clamp
from spiderforge.scope.validator import ScopeValidator
from spiderforge.utils.timestamps import utcnow

if TYPE_CHECKING:
    import logging

    from spiderforge.core.events import EventBus
    from spiderforge.crawler.engine import CrawlResult
    from spiderforge.discovery.models import DiscoveryResult
    from spiderforge.recon.runner import ReconResult


@dataclass
class ModuleContext:
    target: str
    origin: str
    scope: ScopeValidator
    client: httpx.AsyncClient
    config: SpiderForgeConfig
    crawl_result: "CrawlResult | None" = None
    discovery_result: "DiscoveryResult | None" = None
    recon_result: "ReconResult | None" = None
    bus: "EventBus | None" = None
    logger: "logging.Logger | None" = None
    response_cache: dict[str, httpx.Response] = field(default_factory=dict)
    options: dict[str, Any] = field(default_factory=dict)

    async def get(self, url: str, **kwargs: Any) -> httpx.Response | None:
        """Cached GET. Returns None on HTTP errors. Never raises."""
        cache_key = url
        if cache_key in self.response_cache:
            return self.response_cache[cache_key]
        try:
            resp = await self.client.get(url, **kwargs)
        except httpx.HTTPError:
            return None
        self.response_cache[cache_key] = resp
        return resp


class SecurityModule(ABC):
    """Common interface every analysis module implements."""

    name: str = "unnamed"
    category: str = "misc"
    description: str = ""

    @abstractmethod
    async def run(self, ctx: ModuleContext) -> list[Finding]:
        """Execute the module and return findings. Never raise."""
        ...

    # ------------------------------------------------------------------ #
    #  Helpers available to all modules                                   #
    # ------------------------------------------------------------------ #

    def make_finding(
        self,
        *,
        title: str,
        category: str,
        severity: Severity,
        url: str,
        method: str = "GET",
        parameter: str | None = None,
        description: str = "",
        impact: str = "",
        remediation: str = "",
        confidence: float = 0.5,
        evidence: Evidence | None = None,
        status: FindingStatus = FindingStatus.UNCONFIRMED,
        root_cause: str | None = None,
    ) -> Finding:
        fp = finding_fingerprint(category, url, parameter, root_cause)
        fid = f"SF-{fp[:8].upper()}"
        return Finding(
            id=fid,
            fingerprint=fp,
            title=title,
            category=category,
            severity=severity,
            confidence=clamp(confidence),
            url=url,
            method=method,
            parameter=parameter,
            description=description,
            impact=impact,
            remediation=remediation,
            evidence=evidence or Evidence(),
            status=status,
            created_at=utcnow(),
            updated_at=utcnow(),
        )


# ---------------------------------------------------------------------- #
#  Shared helpers used across modules                                     #
# ---------------------------------------------------------------------- #


def in_scope_urls(ctx: ModuleContext, *, require_params: bool = False) -> list[str]:
    """Return the in-scope URLs the module should consider, best-effort."""
    urls: list[str] = []

    if ctx.discovery_result is not None:
        for ep in ctx.discovery_result.endpoints:
            if ep.method.upper() != "GET":
                continue
            if not ctx.scope.is_allowed(ep.url):
                continue
            if require_params and not ep.parameters:
                continue
            urls.append(ep.url)

    if not urls and ctx.crawl_result is not None:
        for page in ctx.crawl_result.pages:
            u = page.final_url or page.url
            if u and ctx.scope.is_allowed(u):
                if require_params and "?" not in u:
                    continue
                urls.append(u)

    if not urls and not require_params:
        urls.append(ctx.target)

    return list(dict.fromkeys(urls))


def with_param(url: str, name: str, value: str) -> str:
    """Return ``url`` with ``name`` set to ``value`` (preserving other params)."""
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    pairs = [(k, value if k == name else v) for k, v in pairs]
    if not any(k == name for k, _ in pairs):
        pairs.append((name, value))
    new_query = urlencode(pairs)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, ""))


def extract_params(url: str) -> list[tuple[str, str]]:
    return parse_qsl(urlsplit(url).query, keep_blank_values=True)


def body_text(resp: httpx.Response, limit: int = 100_000) -> str:
    try:
        return resp.text[:limit]
    except Exception:
        return resp.content[:limit].decode("utf-8", errors="replace")


def build_request_evidence(
    method: str, url: str, headers: dict[str, str] | None = None, body: str | None = None
) -> str:
    lines = [f"{method.upper()} {url}"]
    for k, v in (headers or {}).items():
        lines.append(f"{k}: {v}")
    if body:
        lines.append("")
        lines.append(body)
    return "\n".join(lines)


def build_response_evidence(resp: httpx.Response | None, max_body: int = 4000) -> str:
    if resp is None:
        return ""
    lines = [f"HTTP {resp.status_code} {resp.reason_phrase}"]
    for k, v in resp.headers.items():
        lines.append(f"{k}: {v}")
    body = body_text(resp, max_body)
    if body:
        lines.append("")
        lines.append(body)
    return "\n".join(lines)


def looks_like_url_param(name: str) -> bool:
    low = name.lower()
    return any(
        token in low
        for token in ("url", "uri", "link", "next", "redirect", "return", "returnurl",
                      "callback", "target", "dest", "destination", "continue", "goto",
                      "image", "img", "file", "path", "src", "source", "host", "domain")
    )


def looks_like_id_param(name: str, value: str) -> bool:
    low = name.lower()
    if any(token in low for token in ("id", "uid", "user", "order", "doc", "file", "account", "key")):
        return True
    if value.isdigit():
        return True
    return False