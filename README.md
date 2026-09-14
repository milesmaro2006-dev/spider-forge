<h1 align="center">🕷️ SpiderForge</h1>

<p align="center">
  <b>Automated Web Reconnaissance, Crawling & Security Assessment Framework</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-2.0.0-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue.svg" alt="Python Version">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-orange.svg" alt="Platform">
  <img src="https://img.shields.io/badge/Status-Active-brightgreen.svg" alt="Status">
</p>

<p align="center">
  A modular security assessment framework for penetration testers, bug bounty hunters, and red teamers.<br>
  Scope-aware scanning. Real findings. Professional reports.
</p>

---

## ⚡ Quick Start

Get SpiderForge running in under 2 minutes.

### 1. Requirements

- **Python 3.10+**
- **Linux** or **macOS** (Windows via WSL)
- `pipx` *(the installer will add it automatically if missing)*

### 2. Install

```bash
git clone https://github.com/milesmaro2006-dev/spider-forge.git
cd spider-forge
chmod +x scripts/install.sh
./scripts/install.sh
```

The installer walks you through everything:

1. ✅ Verifies Python version
2. ✅ Installs `pipx` if missing
3. ✅ Installs SpiderForge core
4. ❓ Asks if you want the **Web Dashboard** (fastapi + uvicorn)
5. ❓ Asks if you want **PDF export** (weasyprint)
6. ✅ Creates `~/.spiderforge` and `~/.config/spiderforge`
7. ✅ Runs a system health check

### 3. Run

```bash
spiderforge
```

That's it. You'll see the interactive control center:

```
[1] 🎯 Run Full Assessment (Scan)
[2] 🌐 Launch Web Dashboard (GUI)
[3] 🔍 Run Reconnaissance Only
[4] 📊 Generate Reports
[5] 🩺 Run System Diagnostics (Doctor)
[6] 🚪 Exit
```

### 4. Verify (optional)

```bash
spiderforge doctor
```

Expected:

```text
╭───────────────────────────────────────────╮
│ Checks: 22   PASS: 22   WARN: 0   FAIL: 0 │
│ System Status: Ready                      │
╰───────────────────────────────────────────╯
```

---

## 🎯 Usage

### Interactive Mode

Just run:

```bash
spiderforge
```

Pick an option from the menu and follow the prompts.

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

# CLI-only check (ignores web dependencies)
spiderforge doctor --cli-only

# Machine-readable output (for CI/CD)
spiderforge doctor --json
```

### Web Dashboard

```bash
# Via CLI menu
spiderforge    # → [2] Launch Web Dashboard

# Or directly
uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Open **http://127.0.0.1:8000** in your browser to access the interactive scanner with:

- Live target scanning
- Real-time findings with severity badges
- Downloadable reports (PDF / HTML)
- Network access via `--host 0.0.0.0`

---

## 🔧 Optional Extras

SpiderForge works out of the box with the CLI. These extras add more capabilities.

| Feature | Install Command | Notes |
|---|---|---|
| **Web Dashboard** | `pipx inject spiderforge fastapi "uvicorn[standard]"` | Interactive browser-based scanner |
| **PDF Export** | `pipx inject spiderforge weasyprint` | Needs system libs (see below) |
| **Browser Automation** | `pipx inject spiderforge playwright && playwright install chromium` | ~200 MB download — for JS-heavy apps |

**System libs for PDF (Linux only):**

```bash
sudo apt install libpango-1.0-0 libpangoft2-1.0-0 libcairo2 libgdk-pixbuf-2.0-0
```

---

## 📦 Alternative Installation Methods

### pipx from git

```bash
pipx install git+https://github.com/milesmaro2006-dev/spider-forge.git
pipx inject spiderforge fastapi "uvicorn[standard]"   # optional: web
pipx inject spiderforge weasyprint                    # optional: pdf
```

### Manual (development)

```bash
git clone https://github.com/milesmaro2006-dev/spider-forge.git
cd spider-forge
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[web,pdf]"
```

### Run tests

```bash
pip install -e ".[dev]"
pytest
```

---

## ✨ Features

### Scope-Aware Security Testing

- Explicit target scope validation
- Scope-aware crawling and analysis
- Protection against accidental out-of-scope requests
- Designed to support authorized Rules of Engagement (RoE)

### Reconnaissance

- DNS enumeration (A / AAAA / CNAME / MX / NS / TXT / SOA)
- HTTP/HTTPS probing
- TLS certificate information
- HTTP header collection
- Technology fingerprinting
- `robots.txt` and sitemap discovery

### Asynchronous Web Crawler

- Async HTTP requests with configurable concurrency
- Scope-aware URL processing
- Link, form, and parameter discovery
- JavaScript endpoint extraction
- Crawl depth control

### Endpoint & API Discovery

- API endpoint discovery and normalization
- Parameter inference
- Swagger / OpenAPI detection
- GraphQL detection
- Hidden path discovery
- Endpoint clustering

### Security Analysis Modules

Real, active-analysis modules tested against real-world targets:

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

> Detection modules assist authorized security assessments. Manually validate results before treating them as confirmed vulnerabilities.

### Evidence Collection

Findings are backed by reproducible evidence:

- HTTP requests and responses
- Request/response metadata
- Relevant payloads
- Screenshots
- Evidence hashes

### Findings & Severity

Structured findings contain:

- Title, category, severity (Critical / High / Medium / Low / Info)
- Confidence, CVSS score, CVSS vector
- Affected URL, HTTP method, parameter
- Description, impact, evidence, remediation
- Status and fingerprint

### Reporting

- **JSON** — machine-readable, ideal for CI/CD
- **Markdown** — version-control friendly
- **HTML** — rich, browser-viewable
- **PDF** — professional, shareable (requires WeasyPrint)

### External Tool Integrations

Works alongside:

- **Nmap** — port scanning / service detection
- **httpx** — HTTP probing
- **Nuclei** — template-based vulnerability scanner
- **FFUF** — web fuzzing
- **Nikto** — web server scanner
- **Gobuster** — directory / DNS brute-force
- **WhatWeb** — technology fingerprinting

---

## 🏗️ How It Works

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

### Design Principles

**Scope First** — Every assessment begins with explicit target scope:

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

**Evidence Driven** — Every finding contains enough evidence to reproduce it.

**Modular Architecture** — Recon, crawling, discovery, analysis, evidence, and reporting are independent components.

**Safe Automation** — Minimizes unintended traffic and prevents out-of-scope requests.

---

## ⚙️ Configuration

Configuration lives under:

```text
~/.config/spiderforge/
```

Workspace data lives under:

```text
~/.spiderforge/
├── workspaces/
├── logs/
└── ...
```

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

## 📁 Project Structure

```text
spider-forge/
│
├── spiderforge/
│   ├── cli/                  # Command-line interface
│   ├── core/                 # Engine, orchestration, events
│   ├── config/               # Configuration management
│   ├── database/             # SQLAlchemy models and repositories
│   ├── scope/                # Scope parsing and validation
│   ├── recon/                # DNS, HTTP, technology recon
│   ├── crawler/              # Async web crawler
│   ├── discovery/            # Endpoint and API discovery
│   ├── scanners/             # Security scanners (headers, sqli, xss)
│   ├── analysis/             # Additional analysis modules
│   ├── evidence/             # Evidence collection and hashing
│   ├── findings/             # Finding lifecycle and severity
│   ├── browser/              # Optional browser automation
│   ├── integrations/         # External tool integrations
│   └── reporting/            # JSON / Markdown / HTML / PDF
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
├── docs/
├── pyproject.toml
├── README.md
└── LICENSE
```

---

## 🗺️ Roadmap

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

## ⚠️ Legal Disclaimer

SpiderForge is intended **only for authorized security testing, research, education, and defensive security assessments**.

You must have explicit permission before scanning, crawling, fuzzing, or testing any system that you do not own or have authorization to assess.

Unauthorized security testing may violate applicable laws, regulations, contracts, or terms of service.

The authors and contributors are not responsible for misuse, damage, or unauthorized activity involving this software.

---

## 📄 License

SpiderForge is released under the **MIT License**. See [`LICENSE`](LICENSE) for the full text.

---

## 👤 Author

**Amr Shaban**

Cybersecurity Student — Offensive Security & Web Application Security

GitHub: [https://github.com/milesmaro2006-dev](https://github.com/milesmaro2006-dev)

---

<p align="center">
  <sub>Built with ❤️ for the security community</sub>
</p>
```
