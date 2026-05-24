# DWForSec-ReconSuite

**DWForSec-ReconSuite** adalah offensive reconnaissance & attack surface intelligence framework berbasis terminal/CLI untuk security researcher, bug bounty hunter, dan offensive security engineer.

Framework ini didesain secara modular, asinkron (*asynchronous-first*), aman (*sanitized argument input*), dan siap produksi (*production-ready*).

---

## Fitur Utama

- **Discovery & Enumeration**: Integrasi otomatis dengan Subfinder, Assetfinder, dan Amass.
- **Service & Port Probing**: Integrasi dengan Naabu, HTTPX, dan Nmap.
- **WAF & Tech Profiling**: Deteksi otomatis Web Application Firewall (Wafw00f) dan profil teknologi server (WhatWeb).
- **Crawling & Archive Scraping**: Crawling dinamis via Katana, Gau, Waybackurls, dan Hakrawler.
- **JS Intelligence & Secret Leak Analyzer**: Pemindaian berkas JavaScript terhadap kebocoran API Keys, JWT tokens, dev/staging URLs, AWS credentials, dsb.
- **Vulnerability Scanning**: Integrasi dengan Nuclei.
- **SSL/TLS Auditing**: Audit protokol TLS lemah, cipher lemah, sertifikat kedaluwarsa, dan status HSTS.
- **Multi-Format Reports**: Ekspor laporan otomatis ke format **HTML** (dark-theme modern), **Markdown**, **PDF**, **JSON**, dan **TXT**.

---

## Struktur Proyek

```
DWForSec-ReconSuite/
├── dwforsec/
│   ├── cli/
│   │   ├── main.py
│   │   └── commands/           # CLI Commands (recon, scan, crawl, jsanalyze, report, tools)
│   ├── core/                   # Config, logging, banner, constants
│   ├── services/               # Tool execution & parsers (Subfinder, Nuclei, JS, SSL)
│   ├── models/                 # Pydantic data schemas
│   ├── database/               # SQLite DB setup & ORM Models
│   └── reports/                # Report generation templates & templates (HTML, CSS, PDF)
├── scripts/                    # Installers (install-tools.ps1, install-tools.sh)
└── requirements.txt
```

---

## Panduan Penggunaan / Quick Start

### 1. Instalasi Dependensi
Jalankan perintah berikut untuk menginstal semua dependensi Python:

```bash
pip install -r requirements.txt
```

### 2. Instalasi Tooling Security (Opsional / Otomatis)
Gunakan perintah internal suite untuk mengkloning dan mengompilasi semua *binary tools* eksternal (Subfinder, Nuclei, Katana, dsb.):

```bash
python -m dwforsec.cli.main tools install
```

Atau jalankan status check untuk melihat tools apa saja yang sudah terdeteksi di system PATH atau direktori lokal:

```bash
python -m dwforsec.cli.main tools status
```

*Catatan: Jika binary tools eksternal tidak ditemukan, framework akan secara otomatis beralih menggunakan scanner fallback berbasis Python/Socket.*

---

## Panduan Perintah CLI (Command Guide)

### 1. Menjalankan Pipeline Pengintaian Penuh
Menjalankan seluruh pipeline recon (subdomain discovery -> ports -> waf -> crawling -> JS secrets -> Nuclei -> SSL audit -> database save):

```bash
python -m dwforsec.cli.main recon run example.com
```

Gunakan mode `--public-only` untuk memblokir pemindaian terhadap IP private/internal/localhost:

```bash
python -m dwforsec.cli.main recon run example.com --public-only
```

### 2. Melakukan Pemindaian Kerentanan (Nuclei) Standalone
```bash
python -m dwforsec.cli.main scan nuclei run https://example.com
```

### 3. Melakukan Crawling Website Standalone
```bash
python -m dwforsec.cli.main crawl run https://example.com
```

### 4. Menganalisis File JavaScript (Secret Leaks) Standalone
Menganalisis berkas lokal:
```bash
python -m dwforsec.cli.main jsanalyze file app.js
```

Menganalisis berkas dari URL:
```bash
python -m dwforsec.cli.main jsanalyze url https://example.com/assets/app.js
```

Tampilkan secret tanpa sensor menggunakan flag `--reveal`:
```bash
python -m dwforsec.cli.main jsanalyze file app.js --reveal
```

### 5. Melakukan Ekspor Laporan
Setelah pipeline selesai dijalankan, Anda akan mendapatkan `Scan ID` (contoh: `1`). Ekspor data tersebut menjadi format laporan pilihan Anda:

```bash
# Semua format sekaligus (HTML, Markdown, PDF, JSON, TXT)
python -m dwforsec.cli.main report generate 1 --all-formats

# Format spesifik
python -m dwforsec.cli.main report generate 1 --format html
python -m dwforsec.cli.main report generate 1 --format pdf
python -m dwforsec.cli.main report generate 1 --format markdown
```

Laporan akan disimpan secara terstruktur di direktori:
`outputs/reports/html/`, `outputs/reports/pdf/`, `outputs/reports/markdown/`, dsb.

---

## Security Warning
This framework is intended strictly for authorized security testing on assets you own or have explicit permission to assess.
