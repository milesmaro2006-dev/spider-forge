```markdown
<p align="center">
  <h1 align="center">🕷️ SpiderForge</h1>
  <p align="center">
    <b>Automated Web Reconnaissance, Crawling & Security Assessment Framework</b>
  </p>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-2.0.0-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue.svg" alt="Python Version">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-orange.svg" alt="Platform">
  <img src="https://img.shields.io/badge/Status-Active-brightgreen.svg" alt="Status">
</p>

---

## Overview

**SpiderForge** is a modular web security assessment framework designed for penetration testers, security researchers, bug bounty hunters, and red teamers.

The goal of SpiderForge is to automate the repetitive parts of a web security assessment while keeping the workflow structured, scope-aware, and evidence-driven.

SpiderForge is designed around an assessment lifecycle that starts with target scoping and reconnaissance, continues through crawling and endpoint discovery, and then performs security analysis and report generation.

### Assessment Lifecycle

```text
Target
  │
  ▼
Scope Validation
  │
  ▼
Reconnaissance
  │
  ▼
HTTP Probing
  │
  ▼
Crawling
  │
  ▼
Endpoint Discovery
  │
  ▼
Security Analysis
  │
  ▼
Evidence Collection
  │
  ▼
Finding Management
  │
  ▼
Report Generation
```

---

## Key Features

### Scope-Aware Security Testing

* Explicit target scope validation
* Scope-aware crawling and analysis
* Protection against accidental out-of-scope requests
* Structured handling of external and third-party resources
* Designed to support authorized Rules of Engagement (RoE)

### Reconnaissance

SpiderForge provides automated reconnaissance capabilities including:

* DNS enumeration (A / AAAA / CNAME / MX / NS / TXT / SOA)
* HTTP/HTTPS probing
* TLS certificate information
* HTTP header collection
* Technology fingerprinting
* `robots.txt` discovery
* Sitemap discovery

### Asynchronous Web Crawler

The crawler is designed to efficiently map web applications while respecting the configured scope.

Capabilities include:

* Asynchronous HTTP requests
* Configurable concurrency
* Scope-aware URL processing
* Link extraction
* Form discovery
* Parameter discovery
* JavaScript endpoint extraction
* Query parameter analysis
* Crawl depth control

### Endpoint & API Discovery

SpiderForge is designed to identify and organize application attack surface components:

* API endpoint discovery
* Endpoint normalization
* Parameter inference
* JavaScript endpoint analysis
* Swagger / OpenAPI detection
* GraphQL detection
* Hidden path discovery
* Endpoint clustering

### Security Analysis Modules

SpiderForge ships with real, active-analysis modules that have been tested against
real-world targets:

| Module | Type | Severity Range |
|---|---|---|
| **Security Headers** | Passive | Low / Info |
| **SQL Injection (Error-Based)** | Active | High |
| **Reflected XSS** | Active | Medium / High |
| **Cookie Security** | Passive | Low |
| **CORS Misconfiguration** | Passive | Medium |
| **Open Redirects** | Active | Medium |
| **SSRF Candidates** | Active | High |
| **SSTI** | Active | High |
| **Command Injection Candidates** | Active | High |
| **Path Traversal** | Active | High |
| **File Upload Security** | Active | Medium |
| **IDOR Candidates** | Active | Medium |

> Detection modules are designed to assist authorized security assessments and should be manually validated before treating a result as a confirmed vulnerability.

---

## Evidence Collection

Security findings are backed by reproducible evidence:

* HTTP requests
* HTTP responses
* Request/response metadata
* Relevant payloads
* Screenshots
* Evidence hashes
* Finding-specific artifacts

Evidence can then be associated with individual findings and reports.

---

## Findings & Severity

SpiderForge maintains structured vulnerability findings containing:

* Finding title
* Category
* Severity (Critical / High / Medium / Low / Info)
* Confidence
* CVSS score
* CVSS vector
* Affected URL
* HTTP method
* Parameter
* Description
* Impact
* Evidence
* Remediation
* Finding status
* Finding fingerprint

The framework is designed to support vulnerability lifecycle management from initial detection through validation and reporting.

---

## Reporting

SpiderForge supports structured security reports in multiple formats:

* **JSON** — machine-readable, ideal for CI/CD
* **Markdown** — version-control friendly
* **HTML** — rich, interactive, browser-viewable
* **PDF** — professional, shareable (requires WeasyPrint)

Report workflow:

```text
Scan
  │
  ├── Recon Results
  ├── Crawled URLs
  ├── Discovered Endpoints
  ├── Security Findings
  ├── Evidence
  └── Metadata
        │
        ▼
   Report Generator
        │
        ├── JSON
        ├── Markdown
        ├── HTML
        └── PDF
```

---

## Browser Automation

SpiderForge ships with optional browser automation support for modern web applications.

The browser layer can be used for tasks that cannot be reliably performed using HTTP requests alone:

* JavaScript-heavy applications
* Browser-based interaction
* Screenshot collection
* Dynamic application analysis

Browser automation is optional and is based on Playwright/Chromium.

---

## External Security Tools

SpiderForge integrates with commonly used security tools when available:

* **Nmap** — port scanning / service detection
* **httpx** — HTTP probing
* **Nuclei** — template-based vulnerability scanner
* **FFUF** — web fuzzing
* **Nikto** — web server scanner
* **Gobuster** — directory / DNS brute-force
* **WhatWeb** — technology fingerprinting

These integrations complement SpiderForge's native capabilities rather than replace them.

---

## CLI

SpiderForge provides a command-line interface built around modular workflows.

### Interactive Mode

```bash
spiderforge
```

Opens an interactive control center with:

1. 🎯 Run Full Assessment (Scan)
2. 🌐 Launch Web Dashboard (GUI)
3. 🔍 Run Reconnaissance Only
4. 📊 Generate Reports
5. 🩺 Run System Diagnostics (Doctor)
6. 🚪 Exit

### Direct Commands

```bash
# Full assessment
spiderforge scan run https://example.com

# Reconnaissance only
spiderforge recon run https://example.com

# Generate reports for a workspace
spiderforge report generate ~/.spiderforge/workspaces/example.com/scans/scan-TIMESTAMP \
  --format json,md,html,pdf

# System health check
spiderforge doctor

# CLI-only check (ignores web deps)
spiderforge doctor --cli-only

# JSON output (for CI)
spiderforge doctor --json
```

---

## Web Dashboard

SpiderForge ships an optional FastAPI-based web dashboard for interactive scanning
from the browser.

```bash
# Launch via CLI menu
spiderforge    # → [2] Launch Web Dashboard

# Or directly
uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000 to access:

* Interactive target scanner
* Real-time findings with severity badges
* Downloadable reports (PDF / HTML)
* Network-accessible via `--host 0.0.0.0`

---

## Installation

### Requirements

* Python 3.10+
* Linux or macOS (Windows via WSL)
* pipx recommended

### Quick Install (recommended)

```bash
git clone https://github.com/milesmaro2006-dev/spider-forge.git
cd spider-forge
chmod +x scripts/install.sh
./scripts/install.sh
```

The installer will:

1. Verify Python version
2. Install pipx if missing
3. Install SpiderForge core
4. Optionally install Web Dashboard
5. Optionally install PDF export
6. Create `~/.spiderforge` and `~/.config/spiderforge`
7. Run a system health check

### Alternative — pipx from git

```bash
pipx install git+https://github.com/milesmaro2006-dev/spider-forge.git

# Optional extras
pipx inject spiderforge fastapi "uvicorn[standard]"   # Web Dashboard
pipx inject spiderforge weasyprint                    # PDF export
```

### Manual Installation

```bash
git clone https://github.com/milesmaro2006-dev/spider-forge.git
cd spider-forge
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[web,pdf]"
```

### Verify

```bash
spiderforge doctor
```

Expected output:

```text
╭───────────────────────────────────────────╮
│ Checks: 22   PASS: 22   WARN: 0   FAIL: 0 │
│ System Status: Ready                      │
╰───────────────────────────────────────────╯
```

---

## Development Installation

```bash
git clone https://github.com/milesmaro2006-dev/spider-forge.git
cd spider-forge
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

---

## Configuration

SpiderForge stores its configuration under:

```text
~/.config/spiderforge/
```

Default workspace data is stored under:

```text
~/.spiderforge/
├── workspaces/
├── logs/
└── ...
```

Configuration can control:

* Request concurrency
* Request timeout
* Crawl depth
* Reconnaissance options
* Browser automation
* Reporting formats
* Logging level

Example `config.yaml`:

```yaml
scanner:
  concurrency: 20
  timeout: 20.0
  max_depth: 5
  aggressive: false
recon:
  subdomains: true
  ports: false
  technologies: true
browser:
  enabled: false
  screenshots: false
reporting:
  enable_json: true
  enable_html: true
  enable_markdown: true
  enable_pdf: false
logging:
  level: INFO
```

---

## Security Design Principles

### Scope First

Every assessment begins with explicit target scope:

```text
Scope
  ↓
Validate
  ↓
Enumerate
  ↓
Crawl
  ↓
Analyze
```

### Evidence Driven

Every vulnerability finding contains enough evidence to reproduce the result.

### Modular Architecture

Reconnaissance, crawling, discovery, analysis, evidence collection, and reporting
are separated into independent components, allowing each to evolve without
tightly coupling the framework.

### Safe Automation

Automated security testing minimizes unintended traffic and prevents accidental
interaction with targets outside the authorized scope.

---

## Project Structure

```text
spider-forge/
│
├── spiderforge/
│   │
│   ├── cli/                  # Command-line interface (main, recon, scan, report, doctor)
│   ├── core/                 # Core engine, orchestration and events
│   ├── config/               # Configuration management
│   ├── database/             # SQLAlchemy models, engine, repositories
│   ├── scope/                # Scope parsing and validation
│   ├── recon/                # DNS, HTTP and technology reconnaissance
│   ├── crawler/              # Asynchronous web crawler
│   ├── discovery/            # Endpoint and API discovery
│   ├── scanners/             # Security scanners (headers, sqli, xss)
│   ├── analysis/             # Additional security analysis modules
│   ├── evidence/             # Evidence collection and hashing
│   ├── findings/             # Finding lifecycle and severity management
│   ├── browser/              # Optional browser automation
│   ├── integrations/         # External security tool integrations
│   └── reporting/            # JSON / Markdown / HTML / PDF reports
│
├── backend/                  # FastAPI web backend
│   └── main.py
│
├── frontend/                 # Web dashboard (HTML / CSS / JS)
│   ├── index.html
│   ├── styles.css
│   └── app.js
│
├── scripts/
│   └── install.sh
│
├── tests/
│   ├── unit/
│   └── integration/
│
├── docs/                     # Project documentation
├── pyproject.toml
├── README.md
└── LICENSE
```

---

## Roadmap

### ✅ Implemented (v2.0)

- [x] Interactive CLI menu
- [x] Real SQL Injection (error-based) scanner
- [x] Real Reflected XSS scanner
- [x] Security headers analyzer
- [x] Async engine with shared HTTP client
- [x] Reports: JSON / Markdown / HTML / PDF
- [x] FastAPI web dashboard with live scanning
- [x] Interactive workspace selector
- [x] System Doctor (health check with exit codes)
- [x] pipx-based installation flow
- [x] Report serving via HTTP (inline + download)

### 🚧 In Progress

- [ ] Complete database repository layer
- [ ] Complete reconnaissance pipeline
- [ ] Complete asynchronous crawler
- [ ] Expand endpoint discovery
- [ ] Additional analysis modules (SSRF, SSTI, IDOR, CORS)
- [ ] Evidence collection pipeline with screenshots
- [ ] CVSS v3.1 calculation
- [ ] Browser automation (Playwright)

### 📋 Planned

- [ ] External tool integrations (Nuclei, FFUF)
- [ ] GitHub Actions CI/CD pipeline
- [ ] Expanded unit tests + E2E tests
- [ ] PyPI release
- [ ] Docker image
- [ ] Improved documentation

---

## Legal Disclaimer

SpiderForge is intended **only for authorized security testing, research, education,
and defensive security assessments**.

You must have explicit permission before scanning, crawling, fuzzing, or testing
any system that you do not own or have authorization to assess.

Unauthorized security testing may violate applicable laws, regulations, contracts,
or terms of service.

The authors and contributors are not responsible for misuse, damage, or unauthorized
activity involving this software.

---

## License

SpiderForge is released under the **MIT License**.

See [`LICENSE`](LICENSE) for the full license text.

---

## Author

**Amr Shaban**

Cybersecurity Student — Offensive Security & Web Application Security

GitHub: [https://github.com/milesmaro2006-dev](https://github.com/milesmaro2006-dev)

---

<p align="center">
  <sub>Built with ❤️ for the security community</sub>
</p>
```
