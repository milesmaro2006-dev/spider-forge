from __future__ import annotations

from dataclasses import asdict, dataclass, field
from urllib.parse import urlsplit

import httpx

from spiderforge.core.events import Event, EventBus, EventType
from spiderforge.recon import dns as dns_mod
from spiderforge.recon import http_probe, robots, sitemap, technologies
from spiderforge.scope.validator import ScopeValidator
from spiderforge.utils.logging import get_logger
from spiderforge.utils.urls import normalize_url

log = get_logger("recon.runner")


@dataclass
class ReconResult:
    target: str
    final_url: str | None = None
    dns: dict = field(default_factory=dict)
    http: dict = field(default_factory=dict)
    technologies: list[dict] = field(default_factory=list)
    robots: dict = field(default_factory=dict)
    sitemaps: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


async def run(
    target: str,
    *,
    scope: ScopeValidator,
    bus: EventBus | None = None,
    timeout: float = 20.0,
    user_agent: str = "SpiderForge/0.1",
    verify_tls: bool = True,
    fetch_sitemaps: bool = True,
    max_sitemaps: int = 5,
) -> ReconResult:
    """Run a full recon pass against a target."""
    target = normalize_url(target)
    result = ReconResult(target=target)

    if not scope.is_allowed(target):
        result.errors.append(f"target out of scope: {target}")
        if bus:
            await bus.emit(Event(EventType.OUT_OF_SCOPE, message=target))
        return result

    parts = urlsplit(target)
    host = parts.hostname or ""
    origin = f"{parts.scheme}://{parts.netloc}"

    # ---------- DNS ----------
    if bus:
        await bus.emit(Event(EventType.RECON_DNS, message=f"resolving {host}"))
    try:
        dns_result = await dns_mod.resolve(host, timeout=min(timeout, 10.0))
        result.dns = {
            "hostname": dns_result.hostname,
            "records": dns_result.flat(),
            "errors": dns_result.errors,
        }
    except Exception as exc:  # noqa: BLE001
        result.errors.append(f"dns: {exc}")
        result.dns = {"error": str(exc)}

    # ---------- HTTP session ----------
    headers = {"User-Agent": user_agent}
    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=timeout,
        headers=headers,
        verify=verify_tls,
    ) as client:
        # HTTP probe
        if bus:
            await bus.emit(Event(EventType.RECON_HTTP, message=f"probing {target}"))
        probe = await http_probe.probe(
            target, scope=scope, client=client, verify_tls=verify_tls
        )
        result.final_url = probe.final_url
        result.http = {
            "url": probe.url,
            "final_url": probe.final_url,
            "status_code": probe.status_code,
            "reason": probe.reason,
            "server": probe.server,
            "content_type": probe.content_type,
            "content_length": probe.content_length,
            "title": probe.title,
            "redirects": probe.redirects,
            "elapsed_ms": probe.elapsed_ms,
            "tls": probe.tls,
            "error": probe.error,
        }
        if probe.error:
            result.errors.append(f"http: {probe.error}")

        # Technology detection
        techs = technologies.detect(probe)
        result.technologies = [asdict(t) for t in techs]
        for t in techs:
            if bus:
                await bus.emit(
                    Event(EventType.TECHNOLOGY_FOUND, message=t.name, data=asdict(t))
                )

        # Robots.txt
        if bus:
            await bus.emit(
                Event(EventType.RECON_ROBOTS, message=f"fetching {origin}/robots.txt")
            )
        robots_result = await robots.fetch(origin, scope=scope, client=client)
        result.robots = {
            "url": robots_result.url,
            "found": robots_result.found,
            "status_code": robots_result.status_code,
            "disallow": robots_result.disallow,
            "allow": robots_result.allow,
            "sitemaps": robots_result.sitemaps,
            "crawl_delay": robots_result.crawl_delay,
            "error": robots_result.error,
        }

        # Sitemaps
        sitemap_urls = list(robots_result.sitemaps)
        if not sitemap_urls:
            sitemap_urls = [f"{origin}/sitemap.xml"]

        if fetch_sitemaps:
            for sm_url in sitemap_urls[:max_sitemaps]:
                if bus:
                    await bus.emit(
                        Event(EventType.RECON_SITEMAP, message=f"fetching {sm_url}")
                    )
                sm = await sitemap.fetch(sm_url, scope=scope, client=client)
                result.sitemaps.append(
                    {
                        "url": sm.url,
                        "found": sm.found,
                        "status_code": sm.status_code,
                        "urls": sm.urls,
                        "sub_sitemaps": sm.sub_sitemaps,
                        "error": sm.error,
                    }
                )

    return result