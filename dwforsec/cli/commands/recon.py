"""
dwforsec recon <target>   |   dwforsec r <target>

Full offensive reconnaissance pipeline:
  Subfinder -> Assetfinder -> Amass -> HTTPX -> Naabu -> Nmap
  -> WhatWeb -> Wafw00f -> Katana -> GAU -> Waybackurls
  -> Hakrawler -> JS Secret Analysis -> Nuclei -> SSLScan
  -> Save DB -> Auto-generate HTML report
"""
import asyncio
import typer
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from typing import Optional

from dwforsec.utils.validator import validate_target
from dwforsec.services.recon.subfinder_service    import run_subfinder
from dwforsec.services.recon.assetfinder_service  import run_assetfinder
from dwforsec.services.recon.amass_service        import run_amass
from dwforsec.services.recon.httpx_service        import run_httpx
from dwforsec.services.recon.naabu_service        import run_naabu
from dwforsec.services.recon.nmap_service         import run_nmap
from dwforsec.services.recon.whatweb_service      import run_whatweb
from dwforsec.services.recon.wafw00f_service      import run_wafw00f
from dwforsec.services.recon.katana_service       import run_katana
from dwforsec.services.recon.gau_service          import run_gau
from dwforsec.services.recon.waybackurls_service  import run_waybackurls
from dwforsec.services.recon.hakrawler_service    import run_hakrawler
from dwforsec.services.recon.nuclei_service       import run_nuclei
from dwforsec.services.recon.sslscan_service      import run_sslscan
from dwforsec.services.analyzer.js_secret_analyzer import analyze_js_secrets
from dwforsec.services.analyzer.route_extractor   import extract_routes
from dwforsec.services.db_loader                  import save_scan_results
from dwforsec.reports.html_report                 import HtmlReport

app = typer.Typer(
    help="Full reconnaissance pipeline",
    context_settings={"help_option_names": ["-h", "--help"]},
)


# ─── live dashboard ────────────────────────────────────────────────────────────

class PipelineState:
    def __init__(self, target: str):
        self.target = target
        self.phase = "Initializing"
        self.subdomains = 0
        self.live_hosts = 0
        self.ports = 0
        self.urls = 0
        self.secrets = 0
        self.findings = 0

    def render(self) -> Panel:
        t = Table.grid(padding=(0, 2))
        t.add_column(style="dim cyan",   min_width=18)
        t.add_column(style="bold white", min_width=8)
        t.add_column(style="dim cyan",   min_width=18)
        t.add_column(style="bold white")

        t.add_row("Phase",       self.phase,           "Subdomains",  str(self.subdomains))
        t.add_row("Live Hosts",  str(self.live_hosts), "Open Ports",  str(self.ports))
        t.add_row("URLs found",  str(self.urls),       "Secrets",     str(self.secrets))
        t.add_row("Findings",    str(self.findings),   "Target",      self.target)

        return Panel(
            t,
            title="[bold cyan][ SCANNING ][/bold cyan]",
            border_style="cyan",
            padding=(0, 1),
        )


# ─── pipeline ──────────────────────────────────────────────────────────────────

async def _run_pipeline(target: str, public_only: bool, console: Console) -> int:
    ok, resolved = validate_target(target, public_only=public_only)
    if not ok:
        console.print(f"[bold red]✘[/bold red]  {resolved}")
        raise typer.Exit(1)

    state = PipelineState(resolved)
    subs_dict: list[dict] = []
    findings_dict: list[dict] = []
    ssl_dict: list[dict] = []
    crawl_dict: list[dict] = []
    tech_dict: list[dict] = []

    with Live(state.render(), refresh_per_second=4, console=console) as live:

        def tick(phase: str):
            state.phase = phase
            live.update(state.render())

        # ── Phase 1 · Subdomain Enumeration ───────────────────────────────
        tick("Subfinder")
        s1 = await run_subfinder(resolved)
        tick("Assetfinder")
        s2 = await run_assetfinder(resolved)
        tick("Amass")
        s3 = await run_amass(resolved)

        all_subs = sorted(set(s1 + s2 + s3 + [resolved]))
        state.subdomains = len(all_subs)
        live.update(state.render())

        # ── Phase 2 · Host Probing ─────────────────────────────────────────
        tick("HTTPX Probing")
        httpx_hosts = await run_httpx(all_subs)
        live_urls: list[str] = []
        for h in httpx_hosts:
            subs_dict.append({
                "subdomain":  h.get("host"),
                "ip_address": h.get("ip"),
                "is_live":    True,
                "status_code": h.get("status_code"),
                "title":      h.get("title"),
            })
            if h.get("url"):
                live_urls.append(h["url"])
            for tech in h.get("technologies", []):
                tech_dict.append({"host": h.get("host"), "tech_name": tech})

        probed = {h.get("host") for h in httpx_hosts}
        for s in all_subs:
            if s not in probed:
                subs_dict.append({"subdomain": s, "ip_address": None,
                                   "is_live": False, "status_code": None, "title": None})
        state.live_hosts = len(httpx_hosts)
        live.update(state.render())

        # ── Phase 3 · Port Scanning ────────────────────────────────────────
        tick("Naabu (Ports)")
        ports_map = await run_naabu(all_subs[:10])
        state.ports = sum(len(v) for v in ports_map.values())
        live.update(state.render())

        tick("Nmap (Services)")
        nmap_ports = await run_nmap(resolved)
        for n in nmap_ports:
            findings_dict.append({
                "tool": "nmap", "template_id": f"port-{n['port']}",
                "matched_url": f"{resolved}:{n['port']}", "host": resolved,
                "severity": "info",
                "description": f"Port {n['port']}/{n['protocol']} open – {n['service']} {n['version']}",
                "recommendation": "Close unused ports or restrict via firewall.",
            })

        # ── Phase 4 · WAF / Technology ────────────────────────────────────
        tick("Wafw00f (WAF)")
        waf = await run_wafw00f(f"https://{resolved}")
        if waf and waf != "None":
            findings_dict.append({
                "tool": "wafw00f", "template_id": "waf-detected",
                "matched_url": f"https://{resolved}", "host": resolved,
                "severity": "info",
                "description": f"WAF detected: {waf}",
                "recommendation": "Ensure WAF rules are hardened and up-to-date.",
            })

        # ── Phase 5 · Crawling ────────────────────────────────────────────
        tick("Katana (Crawl)")
        crawled = await run_katana(live_urls[0] if live_urls else f"https://{resolved}")
        tick("GAU (Archive)")
        gau_urls = await run_gau(resolved)
        tick("Waybackurls")
        wb_urls = await run_waybackurls(resolved)

        all_crawled = sorted(set(crawled + gau_urls + wb_urls))
        state.urls = len(all_crawled)
        live.update(state.render())

        # ── Phase 6 · JS Intelligence ─────────────────────────────────────
        tick("JS Secret Analysis")
        import httpx as _httpx
        js_files = [u for u in all_crawled if ".js" in u][:10]
        async with _httpx.AsyncClient(timeout=10.0, verify=False) as client:
            for js_url in js_files:
                try:
                    resp    = await client.get(js_url)
                    secrets = analyze_js_secrets(resp.text)
                    if secrets:
                        state.secrets += len(secrets)
                        live.update(state.render())
                    sec_str = ", ".join(
                        f"{s['pattern_name']}:{s['masked_match']}" for s in secrets
                    ) if secrets else None
                    crawl_dict.append({
                        "url": js_url, "content_type": "application/javascript",
                        "is_js": True, "source_map_found": False,
                        "admin_route_found": "/admin" in resp.text,
                        "staging_url_found": ".staging." in resp.text,
                        "secrets_found": sec_str,
                    })
                except Exception:
                    continue

        # ── Phase 7 · Nuclei Vuln Scan ────────────────────────────────────
        tick("Nuclei (Vulns)")
        nuclei = await run_nuclei(f"https://{resolved}")
        state.findings = len(nuclei)
        live.update(state.render())
        for n in nuclei:
            findings_dict.append({
                "tool": "nuclei", "template_id": n.get("template_id"),
                "matched_url": n.get("matched_url"), "host": n.get("host"),
                "severity": n.get("severity", "info"),
                "description": n.get("description"),
                "recommendation": n.get("recommendation"),
            })

        # ── Phase 8 · SSL Audit ───────────────────────────────────────────
        tick("SSLScan (TLS)")
        ssl_data = await run_sslscan(resolved)
        if ssl_data:
            tls_ver = (ssl_data.get("tls_versions") or [""])[0]
            ssl_dict.append({
                "host": resolved, "tls_version": tls_ver,
                "weak_ciphers": ", ".join(ssl_data.get("weak_ciphers", [])) or None,
                "hsts_enabled": ssl_data.get("hsts"),
                "self_signed": False,
                "expiry_date": ssl_data.get("expiry"),
                "issuer": ssl_data.get("issuer"),
                "san": ", ".join(ssl_data.get("sans", [])),
                "recommendation": "Disable weak ciphers/protocols; enforce HSTS.",
            })

        tick("Saving Results")

    # ── Save to DB ────────────────────────────────────────────────────────
    scan_id = await save_scan_results(
        domain=resolved,
        subdomains=subs_dict, findings=findings_dict,
        ssl_findings=ssl_dict, crawl_results=crawl_dict,
        technologies=tech_dict,
    )
    return scan_id


# ─── command ───────────────────────────────────────────────────────────────────

@app.command(
    name="recon",
    help=(
        "Run the full offensive recon pipeline against TARGET.\n\n"
        "Phases: Subfinder → Assetfinder → Amass → HTTPX → Naabu → Nmap\n"
        "        → WhatWeb → Wafw00f → Katana → GAU → Waybackurls\n"
        "        → JS Intelligence → Nuclei → SSLScan → Report\n\n"
        "[bold cyan]Examples:[/bold cyan]\n"
        "  dwforsec recon example.com\n"
        "  dwforsec recon 10.1.2.240\n"
        "  dwforsec recon example.com --public-only\n"
        "  dwforsec recon example.com --json\n"
    ),
    context_settings={"help_option_names": ["-h", "--help"]},
)
def recon_cmd(
    ctx: typer.Context,
    target: str = typer.Argument(..., help="Domain, IP, or URL to audit"),
    public_only: bool = typer.Option(False, "--public-only", "-P",
                                     help="Block private/local IP ranges"),
    report: bool = typer.Option(True, "--report/--no-report",
                                help="Auto-generate HTML report after scan"),
):
    obj = ctx.ensure_object(dict)
    json_out = obj.get("json_output", False)
    console = Console(highlight=False)

    scan_id = asyncio.run(_run_pipeline(target, public_only, console))

    if json_out:
        import json
        print(json.dumps({"scan_id": scan_id, "target": target, "status": "completed"}))
        return

    console.print(f"\n[bold green]✔[/bold green]  Scan complete  —  ID [bold yellow]{scan_id}[/bold yellow]")
    console.print(f"[dim]  dwforsec report {scan_id} --format html[/dim]")

    if report:
        from dwforsec.services.db_loader import get_scan_data
        from dwforsec.reports.html_report import HtmlReport
        scan_data = asyncio.run(get_scan_data(scan_id))
        path = asyncio.run(HtmlReport(scan_data).generate())
        console.print(f"[bold green]✔[/bold green]  HTML report  →  [cyan]{path}[/cyan]")
