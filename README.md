# SpiderForge

**Personal Web Security Assessment Platform** — CLI-first reconnaissance,
attack-surface mapping, vulnerability assessment, evidence collection, and
reporting. Built for authorized security testing.

> **Scope is mandatory.** Every outbound request is validated against a scope
> file. Discovered third-party resources are recorded as `OUT_OF_SCOPE` and
> never requested.

## Features

- **Recon** — DNS (A/AAAA/CNAME/MX/NS/TXT/SOA), HTTP probe, TLS certificate
  extraction, technology detection (headers, cookies, meta, script signatures),
  robots.txt, sitemap.xml.
- **Crawl** — async, scope-aware, bounded-queue crawler with link, form, JS,
  resource, redirect, parameter, and API-hint extraction.
- **Discovery** — endpoint templating (`/users/{id}`), parameter type inference
  (numeric, UUID, email, date, MD5/SHA1/SHA256, base64, URL, path), API
  clustering, JS static analysis (fetch/axios/XHR/jQuery/WebSocket/source maps),
  Swagger/OpenAPI parsing, GraphQL detection, hidden-path probing.
- **Analysis** — 12 security modules: headers, cookies, CORS, redirects, XSS,
  SQLi, SSRF (candidate), SSTI, command injection (timing), path traversal,
  file upload (candidate), IDOR (candidate).
- **Evidence** — SHA256-hashed artifacts on disk in a per-scan workspace.
- **CVSS v3.1** — full base-score calculator with 11 presets.
- **Reports** — JSON, Markdown, HTML (Jinja2), and PDF (WeasyPrint).
- **Lifecycle** — discovered → unconfirmed → confirmed / false_positive /
  reported / fixed / retest_pending / retest_passed / retest_failed.
- **Browser** — optional Playwright + Chromium for SPA crawling and screenshots.
- **Integrations** — optional wrappers for nmap, httpx, nuclei, ffuf.
- **CLI** — Rich tables, colored severities, JSON export on every command.

## Installation (Kali / Debian / macOS)

```bash
git clone <repo> spiderforge && cd spiderforge
bash scripts/install.sh
spiderforge doctor