from pathlib import Path
from dwforsec.reports.base_report import BaseReport
from dwforsec.utils.file_helpers import write_file_async
from dwforsec.core.constants import SEVERITY_EMOJIS

class MarkdownReport(BaseReport):
    async def generate(self) -> Path:
        filename = self.get_filename("md")
        out_path = self.output_dir / "markdown" / filename
        out_path.parent.mkdir(parents=True, exist_ok=True)
        
        summary = self.data.get("summary", {})
        
        lines = [
            f"# Recon & Vulnerability Report: {self.target}",
            f"**Scan ID:** `{self.scan_id}`  ",
            f"**Timestamp:** {self.timestamp}  ",
            "",
            "## Table of Contents",
            "- [1. Executive Summary](#1-executive-summary)",
            "- [2. Discovered Subdomains](#2-discovered-subdomains)",
            "- [3. Vulnerability Findings](#3-vulnerability-findings)",
            "- [4. SSL/TLS Audit](#4-ssltls-audit)",
            "- [5. Crawling and JS Analysis](#5-crawling-and-js-analysis)",
            "",
            "## 1. Executive Summary",
            "| Metric | Value |",
            "| :--- | :--- |",
            f"| Total Subdomains | {summary.get('total_subdomains', 0)} |",
            f"| Live Hosts | {summary.get('live_hosts', 0)} |",
            f"| Open Ports | {summary.get('open_ports', 0)} |",
            f"| Technologies | {', '.join(summary.get('technologies', [])) or 'None'} |",
            "",
            "### Vulnerability Severity Breakdown",
            f"- {SEVERITY_EMOJIS['critical']} **Critical:** {summary.get('critical', 0)}",
            f"- {SEVERITY_EMOJIS['high']} **High:** {summary.get('high', 0)}",
            f"- {SEVERITY_EMOJIS['medium']} **Medium:** {summary.get('medium', 0)}",
            f"- {SEVERITY_EMOJIS['low']} **Low:** {summary.get('low', 0)}",
            f"- {SEVERITY_EMOJIS['info']} **Info:** {summary.get('info', 0)}",
            "",
            "## 2. Discovered Subdomains",
            "| Subdomain | IP Address | Status | Title |",
            "| :--- | :--- | :--- | :--- |"
        ]
        
        for sub in self.data.get("subdomains", []):
            lines.append(f"| {sub.get('subdomain')} | {sub.get('ip_address') or 'N/A'} | {sub.get('status_code') or 'N/A'} | {sub.get('title') or 'N/A'} |")
            
        lines.append("")
        lines.append("## 3. Vulnerability Findings")
        if not self.data.get("findings"):
            lines.append("*No vulnerabilities detected.*")
        else:
            for f in self.data.get("findings", []):
                sev = f.get('severity', 'info').lower()
                emoji = SEVERITY_EMOJIS.get(sev, "⚪")
                lines.append(f"### {emoji} [{sev.upper()}] {f.get('template_id') or f.get('tool')}")
                lines.append(f"- **Matched:** `{f.get('matched_url') or f.get('host')}`")
                if f.get('description'):
                    lines.append(f"- **Description:** {f.get('description')}")
                if f.get('recommendation'):
                    lines.append(f"- **Remediation:** {f.get('recommendation')}")
                lines.append("")
                
        lines.append("## 4. SSL/TLS Audit")
        if not self.data.get("ssl_findings"):
            lines.append("*No SSL/TLS hosts audited.*")
        else:
            for s in self.data.get("ssl_findings", []):
                lines.append(f"### Host: {s.get('host')}")
                lines.append(f"- **TLS Protocol:** `{s.get('tls_version') or 'N/A'}`")
                lines.append(f"- **Issuer:** `{s.get('issuer') or 'N/A'}`")
                lines.append(f"- **Expiry Date:** `{s.get('expiry_date') or 'N/A'}`")
                if s.get('weak_ciphers'):
                    lines.append(f"- **Weak Ciphers:** `{s.get('weak_ciphers')}`")
                if s.get('recommendation'):
                    lines.append(f"- **Recommendation:** {s.get('recommendation')}")
                lines.append("")
                
        lines.append("## 5. Crawling and JS Analysis")
        if not self.data.get("js_analysis"):
            lines.append("*No JS files analyzed.*")
        else:
            for j in self.data.get("js_analysis", []):
                lines.append(f"### File: {j.get('url')}")
                if j.get("secrets_found"):
                    lines.append(f"- **Secrets Identified:** `{j.get('secrets_found')}`")
                lines.append("")
                
        lines.append("---")
        lines.append("*Report generated automatically by DWForSec-ReconSuite framework.*")
        
        content = "\n".join(lines)
        await write_file_async(out_path, content)
        return out_path
