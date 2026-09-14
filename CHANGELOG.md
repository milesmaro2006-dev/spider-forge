# Changelog

All notable changes to SpiderForge will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned

- Additional analysis modules (SSRF, SSTI, IDOR, CORS)
- Complete asynchronous crawler
- Evidence collection pipeline with screenshots
- CVSS v3.1 calculation
- Browser automation (Playwright)
- External tool integrations (Nuclei, FFUF)
- GitHub Actions CI/CD pipeline
- PyPI release
- Docker image

---

## [2.0.0] - 2026-09-14

### Added

#### CLI

- Interactive control center with 6-option menu
- `spiderforge doctor` — system health check with exit codes
- `spiderforge doctor --cli-only` — ignore web dependencies
- `spiderforge doctor --web` — treat web deps as required
- `spiderforge doctor --json` — machine-readable output
- `spiderforge doctor --quiet` — single-line output
- `spiderforge recon run <target>` — reconnaissance sub-command
- `spiderforge scan run <target>` — full assessment sub-command
- `spiderforge report generate <workspace>` — report generation
- Interactive workspace selector for reports
- Auto-open reports (PDF/HTML) in browser after generation

#### Scanners

- **Security Headers** analyzer (5 headers, passive)
- **SQL Injection** scanner (error-based, 7 payloads)
- **Reflected XSS** scanner (unencoded reflection detection)
- Async engine with shared `httpx.AsyncClient`

#### Reports

- **JSON** export (machine-readable)
- **Markdown** export (version-control friendly)
- **HTML** export (interactive, styled)
- **PDF** export (via WeasyPrint)
- HTTP serving: `/reports/{workspace}/view/{file}` (inline)
- HTTP serving: `/reports/{workspace}/download/{file}?as_attachment=true`
- Path traversal protection via `_safe_join()`

#### Web Dashboard

- FastAPI backend with `/api/scan` endpoint
- Interactive frontend with live scanning
- Severity badges (High / Medium / Low / Info)
- Copy-to-clipboard for payloads and evidence
- Report download bar (PDF / HTML)

#### Findings

- Unified finding schema across all scanners
- Fields: `title`, `severity`, `description`, `param`, `evidence`
- `Finding` model with id, fingerprint, category, url
- Auto-normalization of legacy finding formats in `report.py`

#### Installation

- `scripts/install.sh` — one-shot installer with pipx
- Optional extras: `web`, `pdf`, `browser`, `all`
- Optional system libs installation for WeasyPrint
- Auto-creates `~/.spiderforge` and `~/.config/spiderforge`
- Default `config.yaml` written on first install
- Pre-flight health check after installation

#### Documentation

- Complete `README.md` with installation guides
- `LICENSE` (MIT)
- `CONTRIBUTING.md`
- `SECURITY.md`
- `CHANGELOG.md`
- `CODE_OF_CONDUCT.md`
- `.gitignore` covering Python + SpiderForge artifacts

### Fixed

- `TypeError: Header value must be str or bytes, not OptionInfo`
  when invoking Typer commands programmatically
- `ctx.invoke()` not unwrapping `OptionInfo`/`ArgumentInfo`
- `rich` version reported as "unknown" (now uses `importlib.metadata`)
- `fastapi`/`uvicorn` incorrectly classified as required (now WARN)
- Report generation failing on scanner-format `scan.json`
- Workspace discovery including `reports/`, `.venv/`, `.git/` directories

### Changed

- `pyproject.toml`: version bumped to `2.0.0`, includes `backend/` package
- `pyproject.toml`: added `[project.optional-dependencies]` groups
- `requirements.txt`: aligned with `pyproject.toml` as source of truth
- `install.sh`: pipx-based instead of `.venv` + system wrapper
- `README.md`: reflects v2.0 reality instead of "in development"

---

## [1.0.0] - 2026-09-12

### Added

- Initial release
- Basic CLI structure with Typer
- Scope validation module
- Reconnaissance module (DNS, HTTP, tech detection)
- Basic reporting (JSON, Markdown)
- Database layer (SQLAlchemy)
- Configuration loader (YAML)

### Known Limitations

- No real scanners (only stubs)
- No web dashboard
- No PDF export
- No reports serving

---

## Version Format

- **MAJOR** — incompatible API changes
- **MINOR** — new features, backward compatible
- **PATCH** — bug fixes, backward compatible

[Unreleased]: https://github.com/milesmaro2006-dev/spider-forge/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/milesmaro2006-dev/spider-forge/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/milesmaro2006-dev/spider-forge/releases/tag/v1.0.0
