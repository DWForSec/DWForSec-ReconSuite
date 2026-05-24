# DWForSec-ReconSuite

**Offensive Reconnaissance & Attack Surface Mapping Platform**

A modular, async-first offensive recon framework for security researchers, bug bounty hunters, and red team operators. Integrates 15 real security tools with intelligent Python fallbacks — works even with partial tooling.

---

## Installation

```bash
git clone https://github.com/DWForSec/DWForSec-ReconSuite.git
cd DWForSec-ReconSuite
pip install .
```

After install, `dwforsec` is immediately available globally:

```
dwforsec -h
```

---

## Quick Start

```bash
# Full recon pipeline
dwforsec recon example.com

# With public-only mode (blocks private IP ranges)
dwforsec recon example.com --public-only

# Nuclei vulnerability scan
dwforsec nuclei https://example.com

# SSL/TLS audit
dwforsec ssl example.com

# Web crawler
dwforsec crawl https://example.com

# JS secret & endpoint analysis (file or URL)
dwforsec js app.js
dwforsec js https://example.com/assets/main.js --reveal

# Generate report from scan
dwforsec report 1 --format html
dwforsec report 1 --all          # all formats at once

# Tool manager
dwforsec tools status
dwforsec tools install
```

### Shorthand Aliases

| Full Command         | Alias                |
|:---------------------|:---------------------|
| `dwforsec recon`     | `dwforsec r`         |
| `dwforsec nuclei`    | `dwforsec n`         |
| `dwforsec ssl`       | `dwforsec s`         |
| `dwforsec crawl`     | `dwforsec c`         |
| `dwforsec js`        | `dwforsec j`         |

---

## Interactive Mode

Running `dwforsec` with no arguments launches an interactive selection menu:

```
dwforsec
```

```
 Select Operation
┌────┬──────────────────────────┐
│ [1]│ Full Recon Pipeline      │
│ [2]│ Nuclei Vulnerability Scan│
│ [3]│ SSL / TLS Audit          │
│ [4]│ Web Crawler              │
│ [5]│ JS Secret Analysis       │
│ [6]│ Generate Report          │
│ [7]│ Tool Status              │
│ [0]│ Exit                     │
└────┴──────────────────────────┘
  Choice [0]: _
```

---

## Global Flags

| Flag              | Description                          |
|:------------------|:-------------------------------------|
| `--verbose` / `-v`| Verbose output                       |
| `--json`          | Machine-readable JSON output         |
| `--quiet` / `-q`  | Suppress banner and decorations      |
| `--debug`         | Show full stack traces               |
| `--public-only`   | Block private/local IP scanning      |

---

## Recon Pipeline Phases

When you run `dwforsec recon example.com`, the following phases execute automatically:

```
Phase 1   Subfinder + Assetfinder + Amass     → Subdomain enumeration
Phase 2   HTTPX                               → Live host probing + tech detection
Phase 3   Naabu + Nmap                        → Port scan + service fingerprint
Phase 4   Wafw00f                             → WAF detection
Phase 5   Katana + GAU + Waybackurls          → URL crawling + archive mining
Phase 6   JS Secret Analyzer                  → API key, JWT, AWS key detection
Phase 7   Nuclei                              → Vulnerability scanning
Phase 8   SSLScan                             → TLS/cipher/cert audit
          ↓
          SQLite database save
          Auto-generated HTML report
```

Each phase has a **Python fallback** — the framework remains functional even if external binaries are not installed.

---

## Report Formats

```bash
dwforsec report 1 --format html      # Dark-themed HTML
dwforsec report 1 --format md        # GitHub Markdown
dwforsec report 1 --format pdf       # PDF with cover + tables
dwforsec report 1 --format json      # Machine-readable JSON
dwforsec report 1 --format txt       # Plain text
dwforsec report 1 --all              # All formats at once
```

Reports are saved to `outputs/reports/<format>/`.

---

## Installing External Tools

```bash
# Windows
dwforsec tools install    # runs scripts/install-tools.ps1

# Linux / macOS
dwforsec tools install    # runs scripts/install-tools.sh
```

Requires **Go** to compile ProjectDiscovery tools. Missing tools are replaced with Python fallbacks automatically.

---

## Shell Autocomplete

```bash
# Bash
dwforsec --install-completion bash

# Zsh
dwforsec --install-completion zsh

# PowerShell
dwforsec --install-completion powershell
```

---

## Project Structure

```
dwforsec/
├── cli/
│   ├── main.py                 # Entrypoint, interactive menu, aliases
│   ├── context.py              # Global flag propagation
│   ├── output.py               # Rich theming & output helpers
│   └── commands/               # recon, nuclei, ssl, crawl, js, report, tools
├── core/                       # Config, logging, banner, constants
├── database/                   # SQLAlchemy async ORM (SQLite)
├── models/                     # Pydantic schemas
├── services/
│   ├── recon/                  # 15 tool services (all with Python fallbacks)
│   ├── parser/                 # Nuclei, Nmap, SSL, HTTPX parsers
│   └── analyzer/               # JS secrets, SSL weakness, risk classification
├── reports/                    # HTML, Markdown, PDF, JSON, TXT exporters
└── utils/                      # subprocess runner, validator, sanitize
scripts/
├── install-tools.ps1           # Windows installer
└── install-tools.sh            # Linux/macOS installer
```

---

## Security Notice

This framework is intended **strictly for authorized security testing** on assets you own or have explicit written permission to assess. The author assumes no responsibility for misuse.
