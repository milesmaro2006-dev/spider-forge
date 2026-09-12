<p align="center">
  <h1 align="center">🕷️ SpiderForge</h1>
  <p align="center">
    <b>Automated Web Reconnaissance, Crawling & Security Assessment Framework</b>
  </p>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue.svg" alt="Python Version">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-orange.svg" alt="Platform">
  <img src="https://img.shields.io/badge/Status-In%20Development-yellow.svg" alt="Status">
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

* DNS enumeration
* A / AAAA / CNAME / MX / NS / TXT / SOA records
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

SpiderForge is designed to identify and organize application attack surface components, including:

* API endpoint discovery
* Endpoint normalization
* Parameter inference
* JavaScript endpoint analysis
* Swagger / OpenAPI detection
* GraphQL detection
* Hidden path discovery
* Endpoint clustering

### Security Analysis

SpiderForge provides modular security analysis components for common web application security issues.

Current analysis modules include:

* Security Headers
* Cookie Security
* CORS Misconfiguration
* Open Redirects
* Cross-Site Scripting (XSS)
* SQL Injection (SQLi)
* Server-Side Request Forgery (SSRF) Candidates
* Server-Side Template Injection (SSTI)
* Command Injection Candidates
* Path Traversal
* File Upload Security
* Insecure Direct Object Reference (IDOR) Candidates

> Detection modules are designed to assist authorized security assessments and should be manually validated before treating a result as a confirmed vulnerability.

---

## Evidence Collection

Security findings should be backed by reproducible evidence whenever possible.

SpiderForge provides an evidence layer designed to collect and associate information such as:

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

SpiderForge maintains structured vulnerability findings containing information such as:

* Finding title
* Category
* Severity
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

* JSON
* Markdown
* HTML
* PDF

Example report workflow:

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

SpiderForge is designed with optional browser automation support for modern web applications.

The browser layer can be used for tasks that cannot be reliably performed using HTTP requests alone, including:

* JavaScript-heavy applications
* Browser-based interaction
* Screenshot collection
* Dynamic application analysis

Browser automation is optional and is based on Playwright/Chromium.

---

## External Security Tools

SpiderForge is designed to integrate with commonly used security tools where available.

Planned / supported integrations include:

* Nmap
* httpx
* Nuclei
* FFUF

These integrations are intended to complement SpiderForge's native reconnaissance and analysis capabilities rather than replace them.

---

## CLI

SpiderForge provides a command-line interface designed around modular security assessment workflows.

### Full Assessment

```bash
spiderforge scan run https://example.com
```

### Reconnaissance

```bash
spiderforge recon run https://example.com
```

### Generate Reports

```bash
spiderforge report generate ~/.spiderforge/workspaces/example.com/scans/scan-TIMESTAMP \
  --format json,md,html
```

### Health Check

```bash
spiderforge doctor
```

---

## Project Structure

```text
spider-forge/
│
├── spiderforge/
│   │
│   ├── cli/
│   │   └── # Command-line interface
│   │
│   ├── core/
│   │   └── # Core engine, orchestration and events
│   │
│   ├── config/
│   │   └── # Configuration management
│   │
│   ├── database/
│   │   ├── models.py
│   │   ├── engine.py
│   │   └── repositories.py
│   │
│   ├── scope/
│   │   └── # Scope parsing and validation
│   │
│   ├── recon/
│   │   └── # DNS, HTTP and technology reconnaissance
│   │
│   ├── crawler/
│   │   └── # Asynchronous web crawler
│   │
│   ├── discovery/
│   │   └── # Endpoint and API discovery
│   │
│   ├── analysis/
│   │   └── # Security analysis modules
│   │
│   ├── evidence/
│   │   └── # Evidence collection and hashing
│   │
│   ├── findings/
│   │   └── # Finding lifecycle and severity management
│   │
│   ├── browser/
│   │   └── # Optional browser automation
│   │
│   ├── integrations/
│   │   └── # External security tool integrations
│   │
│   └── reporting/
│       ├── # JSON reports
│       ├── # Markdown reports
│       ├── # HTML reports
│       └── # PDF reports
│
├── scripts/
│   └── install.sh
│
├── tests/
│   ├── unit/
│   └── integration/
│
├── docs/
│   └── # Project documentation
│
├── pyproject.toml
├── README.md
└── LICENSE
```

---

## Installation

### Requirements

* Python 3.10+
* Linux or macOS
* pipx recommended

Clone the repository:

```bash
git clone https://github.com/milesmaro2006-dev/spider-forge.git
cd spider-forge
```

Run the installer:

```bash
chmod +x scripts/install.sh
./scripts/install.sh
```

Verify the installation:

```bash
spiderforge doctor
```

---

## Development Installation

For development and testing, create an isolated Python environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install the project with development dependencies:

```bash
pip install -e ".[dev]"
```

Run the test suite:

```bash
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
```

Example structure:

```text
~/.spiderforge/
├── workspaces/
├── logs/
└── ...
```

Configuration can be used to control items such as:

* Request concurrency
* Request timeout
* Crawl depth
* Reconnaissance options
* Browser automation
* Reporting formats
* Logging level

---

## Security Design Principles

SpiderForge is built around several core principles:

### Scope First

Every assessment should begin with explicit target scope.

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

A vulnerability finding should contain enough evidence to allow a security researcher to understand and reproduce the result.

### Modular Architecture

Reconnaissance, crawling, discovery, analysis, evidence collection, and reporting are separated into independent components.

This allows individual components to evolve without tightly coupling the entire framework.

### Safe Automation

Automated security testing should minimize unintended traffic and prevent accidental interaction with targets outside the authorized scope.

---

## Roadmap

SpiderForge is actively being developed.

Planned development areas include:

* [ ] Complete database repository layer
* [ ] Complete reconnaissance pipeline
* [ ] Complete asynchronous crawler
* [ ] Expand endpoint discovery
* [ ] Complete security analysis modules
* [ ] Evidence collection pipeline
* [ ] Finding lifecycle management
* [ ] CVSS v3.1 calculation
* [ ] Browser automation
* [ ] External tool integrations
* [ ] JSON / Markdown / HTML reporting
* [ ] PDF reporting
* [ ] Expanded unit tests
* [ ] End-to-end testing
* [ ] CI/CD pipeline
* [ ] Improved documentation

---

## Legal Disclaimer

SpiderForge is intended **only for authorized security testing, research, education, and defensive security assessments**.

You must have explicit permission before scanning, crawling, fuzzing, or testing any system that you do not own or have authorization to assess.

Unauthorized security testing may violate applicable laws, regulations, contracts, or terms of service.

The authors and contributors are not responsible for misuse, damage, or unauthorized activity involving this software.

---

## License

SpiderForge is released under the **MIT License**.

See [`LICENSE`](LICENSE) for the full license text.

---

## Author

**Amr Shaban**

Cybersecurity Student
Offensive Security & Web Application Security

GitHub: [https://github.com/milesmaro2006-dev](https://github.com/milesmaro2006-dev)
