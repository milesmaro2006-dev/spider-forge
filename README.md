```markdown
<p align="center">
  <h1 align="center">🕷️ SpiderForge</h1>
  <p align="center"><b>Advanced Automated Reconnaissance, Crawling & Web Vulnerability Assessment Framework</b></p>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue.svg" alt="Python Version">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-orange.svg" alt="Platform">
  <img src="https://img.shields.io/badge/Status-Active-success.svg" alt="Status">
</p>

---

## 🚀 Overview

**SpiderForge** is a modular, high-performance web reconnaissance and security assessment framework built for penetration testers, bug bounty hunters, and red teamers. It automates the entire assessment lifecycle—from target scoping and DNS enumeration to deep asynchronous crawling, endpoint discovery, and multi-module vulnerability analysis—all wrapped in a clean, professional CLI interface.

---

## 🛠️ Key Features

- **🎯 Automated Scoping:** Strict scope enforcement and auto-derivation to ensure Rules of Engagement (RoE) are never violated.
- **🔍 Comprehensive Recon:** DNS records extraction, HTTP probing, technology fingerprinting, robots.txt parsing, and sitemap collection.
- **🕷️ Smart Async Crawler:** Fast, scope-aware asynchronous crawler with form, parameter, and JavaScript endpoint extraction.
- **⚡ Advanced Discovery:** API endpoint clustering, Swagger/GraphQL detection, and hidden path fuzzing.
- **🛡️ 12+ Security Analysis Modules:** Automated checks for headers, cookies, CORS misconfigurations, Open Redirects, XSS, SQLi, SSRF, SSTI, CMDi, Path Traversal, File Upload issues, and IDORs.
- **📊 Professional Reporting:** Instant generation of reports in **JSON**, **Markdown (MD)**, **HTML**, and **PDF** formats.

---

## 📦 Installation

It is highly recommended to install SpiderForge in an isolated environment using `pipx`:

```bash
# Clone the repository
git clone [https://github.com/YOUR_USERNAME/spider-forge.git](https://github.com/YOUR_USERNAME/spider-forge.git)
cd spider-forge

# Run the automated installer script
chmod +x scripts/install.sh
./scripts/install.sh

```

*(Or manually install in editable mode)*:

```bash
pipx install --force -e .

```

---

## 💡 Usage Guide

### 1. Run a Full End-to-End Assessment

Perform recon, crawling, discovery, and analysis in a single command:

```bash
spiderforge scan run [http://example.com](http://example.com)

```

### 2. Run Reconnaissance Only

Quickly gather DNS, technologies, and HTTP headers:

```bash
spiderforge recon run [http://example.com](http://example.com)

```

### 3. Generate Reports from an Existing Workspace

If you already completed a scan and want to export reports:

```bash
spiderforge report generate ~/.spiderforge/workspaces/[example.com/scans/scan-TIMESTAMP](https://example.com/scans/scan-TIMESTAMP) --format json,md,html

```

---

## 🗂️ Project Structure

```text
spider-forge/
├── spiderforge/
│   ├── cli/         # Typer-based CLI commands (recon, scan, report, etc.)
│   ├── core/        # Event bus, engine, and orchestrator
│   ├── crawler/     # Async web crawler & parser
│   ├── discovery/   # Endpoint analysis, JS, Swagger, GraphQL
│   ├── database/    # SQLAlchemy models, engines, and repositories
│   ├── modules/     # Security checks and vulnerability scanners
│   ├── reporting/   # JSON, Markdown, HTML, and PDF renderers
│   └── scope/       # Scope validation and parsing
├── scripts/         # Installation & setup scripts
└── pyproject.toml

```

---

## 🛡️ Disclaimer

> **Warning:** SpiderForge is designed for authorized security testing and educational purposes only. Unauthorized scanning of targets without prior written consent is illegal. The authors assume no liability for any misuse or damage caused by this tool.

---
