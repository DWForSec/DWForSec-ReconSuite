# Changelog

All notable changes to DWForSec-ReconSuite are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [v1.0.0] — 2025-05-25

### Initial Public Release

#### Added

**Core Framework**
- Fully async recon pipeline using `asyncio` and `SQLAlchemy 2.0` async engine
- SQLite database persistence with async ORM models: `Target`, `Scan`, `Subdomain`, `Finding`, `SSLFinding`, `CrawlResult`, `Technology`
- Pydantic v2 schemas for all data models
- Structured logging via `Loguru` (console + rotating file)
- Centralized configuration via `pydantic-settings` + `.env` support

**CLI Layer**
- Global `dwforsec` entrypoint via `pyproject.toml [project.scripts]`
- Simplified commands: `dwforsec recon`, `nuclei`, `ssl`, `crawl`, `js`, `report`, `tools`
- Shorthand aliases: `r`, `n`, `s`, `c`, `j`
- Interactive terminal menu when run without arguments
- Global flags: `--verbose`, `--json`, `--quiet`, `--debug`, `--public-only`
- Shell autocomplete: bash, zsh, PowerShell
- Shared `AppContext` for flag propagation across subcommands
- Live scanning dashboard using `Rich Live` panel

**Tool Integration (15 tools)**
- Subfinder, Assetfinder, Amass — subdomain enumeration
- HTTPX — live host probing with technology detection
- Naabu, Nmap — port scanning and service fingerprinting
- Wafw00f — WAF detection
- Katana, GAU, Waybackurls, Hakrawler — URL crawling and archive mining
- Nuclei — vulnerability scanning
- SSLScan, testssl.sh — TLS/cipher/certificate audit
- WhatWeb — technology classification

**Python Fallbacks (5 services)**
- HTTPX service: Python `httpx` async client fallback
- Naabu service: Python `asyncio` socket port scanner fallback
- SSLScan service: Python `ssl` + `cryptography` TLS inspector fallback
- Katana service: Python `httpx` + `BeautifulSoup` link extractor fallback
- Waybackurls service: Wayback Machine CDX API fallback
- Wafw00f service: HTTP response header signature analysis fallback

**Intelligence Analyzers**
- JS Secret Analyzer — 18 regex patterns: Google API, AWS keys, JWT, Firebase, Stripe, GraphQL, Swagger, WebSocket, S3, internal IPs, debug flags, Bearer tokens, Admin routes
- Route Extractor — `/api/`, `/admin`, `/graphql`, `/swagger` endpoint detection
- SSL Analyzer — weak cipher, protocol version, HSTS, self-signed detection
- Risk Classifier — overall risk score based on finding severity distribution
- Technology Classifier — server stack categorization

**Report Engine (5 formats)**
- HTML — dark-themed Jinja2 template with severity badges and summary cards
- PDF — ReportLab multi-page report with cover page and data tables
- Markdown — GitHub-compatible structured report
- JSON — machine-readable export for SIEM/tooling integration
- TXT — plain monospace report for terminal review

**Security Controls**
- No `shell=True` — all subprocess execution via `asyncio.create_subprocess_exec`
- `--public-only` mode — blocks private/loopback IP ranges
- Input sanitization via `sanitize.py`
- Secret masking with `--reveal` flag for local audit

**Installer Scripts**
- `scripts/install-tools.ps1` — Windows PowerShell: clones + compiles all 15 tools
- `scripts/install-tools.sh` — Linux/macOS bash: clones + compiles with Go detection

---

## Roadmap

### v1.1.0 (planned)
- [ ] PostgreSQL support via `DATABASE_URL` env override
- [ ] `dwforsec history` — list all past scans
- [ ] `dwforsec diff` — compare two scan results
- [ ] Rate limiting / concurrency controls per tool
- [ ] Nuclei template auto-update on scan start

### v1.2.0 (planned)
- [ ] REST API mode (`dwforsec serve`) for CI/CD integration
- [ ] Slack / Discord webhook notifications
- [ ] CVSS score enrichment from NVD API
- [ ] DNS brute-force module
