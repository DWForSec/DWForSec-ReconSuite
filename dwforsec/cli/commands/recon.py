import typer
import asyncio
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.spinner import Spinner
from rich.layout import Layout
from dwforsec.utils.validator import validate_target
from dwforsec.services.recon.subfinder_service import run_subfinder
from dwforsec.services.recon.assetfinder_service import run_assetfinder
from dwforsec.services.recon.amass_service import run_amass
from dwforsec.services.recon.httpx_service import run_httpx
from dwforsec.services.recon.naabu_service import run_naabu
from dwforsec.services.recon.nmap_service import run_nmap
from dwforsec.services.recon.whatweb_service import run_whatweb
from dwforsec.services.recon.wafw00f_service import run_wafw00f
from dwforsec.services.recon.katana_service import run_katana
from dwforsec.services.recon.gau_service import run_gau
from dwforsec.services.recon.waybackurls_service import run_waybackurls
from dwforsec.services.recon.hakrawler_service import run_hakrawler
from dwforsec.services.recon.nuclei_service import run_nuclei
from dwforsec.services.recon.sslscan_service import run_sslscan
from dwforsec.services.recon.testssl_service import run_testssl
from dwforsec.services.analyzer.js_secret_analyzer import analyze_js_secrets
from dwforsec.services.analyzer.route_extractor import extract_routes
from dwforsec.services.db_loader import save_scan_results, get_scan_data
from dwforsec.reports.html_report import HtmlReport
from dwforsec.reports.markdown_report import MarkdownReport
from dwforsec.reports.json_report import JsonReport
from dwforsec.reports.txt_report import TxtReport
from dwforsec.reports.pdf_report import PdfReport

app = typer.Typer(help="Run full offensive reconnaissance pipeline")
console = Console()

class ScanProgressState:
    def __init__(self, target: str):
        self.target = target
        self.active_tool = "Initializing..."
        self.discovered_hosts = 0
        self.open_ports = 0
        self.findings_count = 0
        self.crawled_urls = 0
        self.secrets_found = 0
        self.elapsed = 0
        
    def generate_dashboard(self) -> Panel:
        table = Table(show_header=False, box=None)
        table.add_row("[cyan]Target:[/cyan]", f"[bold white]{self.target}[/bold white]")
        table.add_row("[cyan]Active Phase/Tool:[/cyan]", f"[bold yellow]{self.active_tool}[/bold yellow]")
        table.add_row("[cyan]Subdomains Discovered:[/cyan]", f"[bold green]{self.discovered_hosts}[/bold green]")
        table.add_row("[cyan]Open Ports Mapping:[/cyan]", f"[bold magenta]{self.open_ports}[/bold magenta]")
        table.add_row("[cyan]Crawled Targets:[/cyan]", f"[bold blue]{self.crawled_urls}[/bold blue]")
        table.add_row("[cyan]Secret Leaks Detected:[/cyan]", f"[bold red]{self.secrets_found}[/bold red]")
        table.add_row("[cyan]Vulnerability Findings:[/cyan]", f"[bold red]{self.findings_count}[/bold red]")
        
        return Panel(
            table,
            title="[bold green]DWForSec-ReconSuite Scanning Engine[/bold green]",
            border_style="cyan"
        )

async def update_timer(state: ScanProgressState):
    while True:
        await asyncio.sleep(1)
        state.elapsed += 1

async def run_pipeline(target: str, public_only: bool):
    is_valid, resolved_target = validate_target(target, public_only=public_only)
    if not is_valid:
        console.print(f"[bold red]Validation Error:[/bold red] {resolved_target}")
        raise typer.Exit(1)
        
    state = ScanProgressState(resolved_target)
    
    # Start timer task
    timer_task = asyncio.create_task(update_timer(state))
    
    # Store dynamic collection objects
    subdomains_dict = []
    findings_dict = []
    ssl_findings_dict = []
    crawl_results_dict = []
    techs_dict = []
    
    with Live(state.generate_dashboard(), refresh_per_second=2) as live:
        # Phase 1: Subdomain Discovery
        state.active_tool = "Subfinder (Subdomains enum)"
        live.update(state.generate_dashboard())
        subs1 = await run_subfinder(resolved_target)
        
        state.active_tool = "Assetfinder (Subdomains enum)"
        live.update(state.generate_dashboard())
        subs2 = await run_assetfinder(resolved_target)
        
        state.active_tool = "Amass (Subdomains enum)"
        live.update(state.generate_dashboard())
        subs3 = await run_amass(resolved_target)
        
        all_subs = sorted(list(set(subs1 + subs2 + subs3 + [resolved_target])))
        state.discovered_hosts = len(all_subs)
        live.update(state.generate_dashboard())
        
        # Phase 2: Host Probing
        state.active_tool = "HTTPX (Probing web servers)"
        live.update(state.generate_dashboard())
        httpx_hosts = await run_httpx(all_subs)
        
        # Log to db structure
        live_subdomains = []
        for h in httpx_hosts:
            subdomains_dict.append({
                "subdomain": h.get("host"),
                "ip_address": h.get("ip"),
                "is_live": True,
                "status_code": h.get("status_code"),
                "title": h.get("title")
            })
            live_subdomains.append(h.get("url"))
            
            # Save technologies
            for tech in h.get("technologies", []):
                techs_dict.append({
                    "host": h.get("host"),
                    "tech_name": tech
                })
                
        # Fill non-live subdomains
        probed_subs = [h.get("host") for h in httpx_hosts]
        for sub in all_subs:
            if sub not in probed_subs:
                subdomains_dict.append({
                    "subdomain": sub,
                    "ip_address": None,
                    "is_live": False,
                    "status_code": None,
                    "title": None
                })
                
        # Phase 3: Port Scan
        state.active_tool = "Naabu (Ports enum)"
        live.update(state.generate_dashboard())
        ports_map = await run_naabu(all_subs[:10]) # Limit to top 10 subs for speed
        state.open_ports = sum(len(ports) for ports in ports_map.values())
        live.update(state.generate_dashboard())
        
        # Phase 4: Nmap Service Fingerprinting
        state.active_tool = "Nmap (Service scan)"
        live.update(state.generate_dashboard())
        nmap_ports = await run_nmap(resolved_target)
        for n in nmap_ports:
            # Add open ports as info findings
            findings_dict.append({
                "tool": "nmap",
                "template_id": f"port-{n['port']}",
                "matched_url": f"{resolved_target}:{n['port']}",
                "host": resolved_target,
                "severity": "info",
                "description": f"Port {n['port']}/{n['protocol']} is open. Service: {n['service']} ({n['version']})",
                "recommendation": "Close unused ports or restrict access using system firewall rules."
            })
            
        # Phase 5: WAF & Tech Classification
        state.active_tool = "Wafw00f (WAF check)"
        live.update(state.generate_dashboard())
        waf_info = await run_wafw00f(f"https://{resolved_target}")
        if waf_info and waf_info != "None":
            findings_dict.append({
                "tool": "wafw00f",
                "template_id": "waf-detected",
                "matched_url": f"https://{resolved_target}",
                "host": resolved_target,
                "severity": "info",
                "description": f"Web Application Firewall (WAF) detected: {waf_info}",
                "recommendation": "WAF is active. Ensure rules are configured securely."
            })
            
        # Phase 6: Crawling & Archives Extraction
        state.active_tool = "Katana (Crawling links)"
        live.update(state.generate_dashboard())
        crawled_urls = []
        if live_subdomains:
            crawled_urls = await run_katana(live_subdomains[0])
            
        state.active_tool = "Gau (Wayback archive search)"
        live.update(state.generate_dashboard())
        gau_urls = await run_gau(resolved_target)
        
        state.active_tool = "Waybackurls (Web history extraction)"
        live.update(state.generate_dashboard())
        wb_urls = await run_waybackurls(resolved_target)
        
        all_crawled = sorted(list(set(crawled_urls + gau_urls + wb_urls)))
        state.crawled_urls = len(all_crawled)
        live.update(state.generate_dashboard())
        
        # Phase 7: JavaScript Source Code Analyzer
        state.active_tool = "JavaScript Secrets Analyzer"
        live.update(state.generate_dashboard())
        
        js_files = [u for u in all_crawled if u.endswith(".js") or ".js?" in u]
        import httpx
        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            for js_url in js_files[:10]: # Limit to top 10 JS files for performance
                try:
                    resp = await client.get(js_url)
                    js_content = resp.text
                    
                    # Search secrets
                    secrets = analyze_js_secrets(js_content)
                    routes = extract_routes(js_content)
                    
                    sec_str = ""
                    if secrets:
                        state.secrets_found += len(secrets)
                        live.update(state.generate_dashboard())
                        sec_str = ", ".join([f"{s['pattern_name']}:{s['masked_match']}" for s in secrets])
                        
                    # Save Crawl Result
                    crawl_results_dict.append({
                        "url": js_url,
                        "content_type": "application/javascript",
                        "is_js": True,
                        "source_map_found": False,
                        "admin_route_found": any(r in js_content for r in ["/admin", "/dashboard"]),
                        "staging_url_found": ".staging." in js_content or ".dev." in js_content,
                        "secrets_found": sec_str if sec_str else None
                    })
                except Exception:
                    continue
                    
        # Phase 8: Nuclei Vuln Scan
        state.active_tool = "Nuclei (Vulnerability scan)"
        live.update(state.generate_dashboard())
        nuclei_findings = await run_nuclei(f"https://{resolved_target}")
        state.findings_count = len(nuclei_findings)
        live.update(state.generate_dashboard())
        
        for n in nuclei_findings:
            findings_dict.append({
                "tool": "nuclei",
                "template_id": n.get("template_id"),
                "matched_url": n.get("matched_url"),
                "host": n.get("host"),
                "severity": n.get("severity"),
                "description": n.get("description"),
                "recommendation": n.get("recommendation")
            })
            
        # Phase 9: SSL Certificate Audit
        state.active_tool = "SSLScan (TLS analyzer)"
        live.update(state.generate_dashboard())
        ssl_data = await run_sslscan(resolved_target)
        
        if ssl_data:
            # Generate recommendation and check weaknesses
            tls_version = ssl_data.get("tls_versions")[0] if ssl_data.get("tls_versions") else ""
            weak_ciphers = ", ".join(ssl_data.get("weak_ciphers", []))
            
            ssl_findings_dict.append({
                "host": resolved_target,
                "tls_version": tls_version,
                "weak_ciphers": weak_ciphers if weak_ciphers else None,
                "hsts_enabled": ssl_data.get("hsts"),
                "self_signed": False,
                "expiry_date": ssl_data.get("expiry"),
                "issuer": ssl_data.get("issuer"),
                "san": ", ".join(ssl_data.get("sans", [])),
                "recommendation": "Enforce strict ciphers and disable weak SSL/TLS protocols."
            })
            
        state.active_tool = "Finalizing scan & reports"
        live.update(state.generate_dashboard())
        
        # Save to database
        scan_id = await save_scan_results(
            domain=resolved_target,
            subdomains=subdomains_dict,
            findings=findings_dict,
            ssl_findings=ssl_findings_dict,
            crawl_results=crawl_results_dict,
            technologies=techs_dict
        )
        
        timer_task.cancel()
        return scan_id

@app.command("run")
def run(
    target: str = typer.Argument(..., help="Target domain, IP, or URL to audit"),
    public_only: bool = typer.Option(False, "--public-only", help="Enforce blocking local/private address resolution")
):
    """
    Executes full multi-phase reconnaissance and vulnerability intelligence pipeline.
    """
    scan_id = asyncio.run(run_pipeline(target, public_only))
    
    console.print(f"\n[bold green]✓ Pipeline execution completed successfully![/bold green]")
    console.print(f"[bold green]✓ Scan ID:[/bold green] [yellow]{scan_id}[/yellow]")
    console.print(f"Run `dwforsec report generate {scan_id} --all-formats` to compile intelligence outputs.")
