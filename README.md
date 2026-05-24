# DWForSec-ReconSuite

**Offensive Reconnaissance & Attack Surface Mapping Platform**

Modular, async-first offensive recon framework for security researchers, bug bounty hunters, and red team operators. Integrates 15 security tools with intelligent Python fallbacks — works even with partial tooling.

```
  DWForSec-ReconSuite  v1.0.0
  Offensive Reconnaissance & Attack Surface Mapping Platform
  Recon  Crawl  JSIntel  SSLAudit  NucleiScan  Reporting  Database
  Tools: 15 supported  |  Modules: 7 loaded  |  DB: SQLite (async)
```

---

## Installation

```bash
git clone https://github.com/DWForSec/DWForSec-ReconSuite.git
cd DWForSec-ReconSuite
pip install .
```

The `dwforsec` command is immediately available globally after install:

```bash
dwforsec -h
```

---

## Help Menu

```
 Usage: dwforsec [OPTIONS] COMMAND [ARGS]...

+- Options -------------------------------------------------------------------+
| --verbose    -v    Verbose output                                           |
| --json             Machine-readable JSON output                             |
| --quiet      -q    Suppress banner and decorations                          |
| --debug            Show full stack traces                                   |
| --public-only -P   Block private/local IP scanning                          |
| --help       -h    Show this message and exit                               |
+-----------------------------------------------------------------------------+
+- Commands ------------------------------------------------------------------+
| recon    Full recon pipeline                                                |
| nuclei   Nuclei vulnerability scan                                          |
| ssl      SSL/TLS security audit                                             |
| crawl    Web crawler                                                        |
| js       JS intelligence analyzer                                           |
| report   Report generator                                                   |
| tools    Tool manager                                                       |
+-----------------------------------------------------------------------------+
```

---

## Usage

### Full Recon Pipeline

```bash
dwforsec recon example.com
dwforsec recon example.com --public-only
dwforsec recon example.com --json
```

### Nuclei Vulnerability Scan

```bash
dwforsec nuclei https://example.com
```

### SSL/TLS Audit

```bash
dwforsec ssl example.com
```

### Web Crawler

```bash
dwforsec crawl https://example.com
```

### JavaScript Intelligence

```bash
# Analyze local file
dwforsec js app.js

# Analyze remote URL
dwforsec js https://example.com/assets/main.js

# Show unmasked secrets
dwforsec js app.js --reveal
```

### Generate Reports

```bash
dwforsec report 1                    # HTML (default)
dwforsec report 1 --format pdf
dwforsec report 1 --format md
dwforsec report 1 --format json
dwforsec report 1 --format txt
dwforsec report 1 --all             # All formats at once
```

### Tool Manager

```bash
dwforsec tools status
dwforsec tools install
dwforsec tools update
```

---

## Shorthand Aliases

| Full Command      | Alias              | Description              |
|:------------------|:-------------------|:-------------------------|
| `dwforsec recon`  | `dwforsec r`       | Full recon pipeline      |
| `dwforsec nuclei` | `dwforsec n`       | Nuclei vulnerability scan|
| `dwforsec ssl`    | `dwforsec s`       | SSL/TLS audit            |
| `dwforsec crawl`  | `dwforsec c`       | Web crawler              |
| `dwforsec js`     | `dwforsec j`       | JS intelligence          |

---

## Interactive Mode

Running `dwforsec` with no arguments launches an interactive selection menu:

```
dwforsec
```

```
 Select Operation
+----+--------------------------+
| [1]| Full Recon Pipeline      |
| [2]| Nuclei Vulnerability Scan|
| [3]| SSL / TLS Audit          |
| [4]| Web Crawler              |
| [5]| JS Secret Analysis       |
| [6]| Generate Report          |
| [7]| Tool Status              |
| [0]| Exit                     |
+----+--------------------------+
  Choice [0]:
```

---

## Global Flags

| Flag            | Short | Description                      |
|:----------------|:------|:---------------------------------|
| `--verbose`     | `-v`  | Verbose output                   |
| `--json`        |       | Machine-readable JSON output     |
| `--quiet`       | `-q`  | Suppress banner                  |
| `--debug`       |       | Show full stack traces           |
| `--public-only` | `-P`  | Block private/local IP ranges    |

---

## Real-World Workflow

```bash
# 1. Check which tools are installed
dwforsec tools status

# 2. Install missing tools (requires Go for ProjectDiscovery tools)
dwforsec tools install

# 3. Run full recon pipeline (blocks private IP scanning)
dwforsec recon example.com --public-only

# 4. Run on internal lab target (no --public-only restriction)
dwforsec recon 10.1.2.240

# 5. Analyze a JavaScript bundle for exposed secrets
dwforsec js https://example.com/static/bundle.js

# 6. Run standalone Nuclei scan
dwforsec nuclei https://example.com

# 7. Audit SSL/TLS configuration
dwforsec ssl example.com

# 8. Generate all report formats from scan results
dwforsec report 1 --all

# 9. Use alias shortcuts
dwforsec r example.com
dwforsec n https://example.com
dwforsec j app.js --reveal
```

---

## Recon Pipeline Phases

When you run `dwforsec recon example.com`, the following 8 phases execute automatically:

```
Phase 1   Subfinder + Assetfinder + Amass     Subdomain enumeration
Phase 2   HTTPX                               Live host probing + tech detection
Phase 3   Naabu + Nmap                        Port scan + service fingerprint
Phase 4   Wafw00f                             WAF detection
Phase 5   Katana + GAU + Waybackurls          URL crawling + archive mining
Phase 6   JS Secret Analyzer                  API key, JWT, AWS cred detection
Phase 7   Nuclei                              Vulnerability scanning
Phase 8   SSLScan                             TLS protocol + cipher audit
          |
          SQLite database (async save)
          Auto-generated HTML report
```

> **Resilience:** Every phase has a Python fallback. The framework runs even if external binaries are not installed.

---

## Report Formats

Reports are saved to `outputs/reports/<format>/`:

| Format   | Description                                      |
|:---------|:-------------------------------------------------|
| HTML     | Dark-themed report with severity badges          |
| PDF      | ReportLab PDF with cover page and tables         |
| Markdown | GitHub-compatible markdown report                |
| JSON     | Machine-readable structured data                 |
| TXT      | Plain monospace text report                      |

---

## Supported Tools

| Tool          | Fallback              | Purpose                     |
|:--------------|:----------------------|:----------------------------|
| Subfinder     | DNS enumeration       | Subdomain discovery         |
| Assetfinder   | DNS enumeration       | Subdomain discovery         |
| Amass         | DNS enumeration       | Subdomain discovery         |
| HTTPX         | Python httpx client   | Live host probing           |
| Naabu         | Python socket scanner | Port scanning               |
| Nmap          | —                     | Service fingerprinting      |
| Nuclei        | —                     | Vulnerability scanning      |
| Katana        | Python link extractor | Web crawling                |
| GAU           | —                     | URL archive mining          |
| Waybackurls   | archive.org CDX API   | Historical URL mining       |
| Hakrawler     | —                     | Web crawling                |
| SSLScan       | Python ssl + cryptography | TLS audit               |
| testssl.sh    | —                     | TLS audit                   |
| WhatWeb       | —                     | Technology detection        |
| Wafw00f       | Python header analysis| WAF detection               |

---

## Shell Autocomplete

```bash
dwforsec --install-completion bash
dwforsec --install-completion zsh
dwforsec --install-completion powershell
```

---

## Project Structure

```
dwforsec/
├── cli/
│   ├── main.py              Entrypoint, interactive menu, aliases
│   ├── context.py           Global flag propagation (AppContext)
│   ├── output.py            Rich theming and output helpers
│   └── commands/
│       ├── recon.py         Full pipeline orchestrator
│       ├── nuclei.py        Nuclei scanner
│       ├── ssl.py           SSL/TLS auditor
│       ├── crawl.py         Web crawler
│       ├── js.py            JS intelligence analyzer
│       ├── report.py        Report generator
│       └── tools.py         Tool manager
├── core/                    Config, logging, banner, constants
├── database/                SQLAlchemy 2.0 async ORM (SQLite)
├── models/                  Pydantic v2 schemas
├── services/
│   ├── recon/               15 tool services (all with Python fallbacks)
│   ├── parser/              Nuclei, Nmap, SSL, HTTPX output parsers
│   └── analyzer/            JS secrets, SSL weakness, risk scoring
├── reports/                 HTML, Markdown, PDF, JSON, TXT exporters
│   └── templates/report.html   Dark Jinja2 HTML template
└── utils/                   Subprocess runner, validator, sanitize
scripts/
├── install-tools.ps1        Windows PowerShell installer
└── install-tools.sh         Linux/macOS bash installer
```

---

## Requirements

- Python 3.11+
- Go (optional — for compiling ProjectDiscovery tools)

```bash
pip install -r requirements.txt
```

---

## License

[MIT License](LICENSE) © 2025 DWForSec

---

> **Security Notice:** This framework is intended strictly for **authorized security testing** on assets you own or have explicit written permission to assess. The authors assume no responsibility for misuse.
