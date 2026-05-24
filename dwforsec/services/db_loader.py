import datetime
from sqlalchemy.future import select
from dwforsec.database.db import AsyncSessionLocal, init_db
from dwforsec.database.models import Target, Scan, Subdomain, Finding, SSLFinding, CrawlResult, Technology

async def save_scan_results(
    domain: str,
    subdomains: list[dict],      # list of dict matching Subdomain
    findings: list[dict],        # list of dict matching Finding
    ssl_findings: list[dict],    # list of dict matching SSLFinding
    crawl_results: list[dict],   # list of dict matching CrawlResult
    technologies: list[dict]     # list of dict matching Technology
) -> int:
    """
    Initializes DB, registers or fetches the target, creates a Scan,
    saves all outputs, updates scan to 'completed', and returns the scan_id.
    """
    await init_db()
    
    async with AsyncSessionLocal() as session:
        async with session.begin():
            # Check if target exists
            stmt = select(Target).where(Target.domain == domain)
            result = await session.execute(stmt)
            target = result.scalars().first()
            
            if not target:
                target = Target(domain=domain)
                session.add(target)
                await session.flush()
                
            # Create Scan
            scan = Scan(target_id=target.id, status="running")
            session.add(scan)
            await session.flush()
            
            scan_id = scan.id
            
            # Save subdomains
            for s in subdomains:
                sub = Subdomain(
                    scan_id=scan_id,
                    subdomain=s.get("subdomain"),
                    ip_address=s.get("ip_address"),
                    is_live=s.get("is_live", False),
                    status_code=s.get("status_code"),
                    title=s.get("title")
                )
                session.add(sub)
                
            # Save findings
            for f in findings:
                fin = Finding(
                    scan_id=scan_id,
                    tool=f.get("tool"),
                    template_id=f.get("template_id"),
                    matched_url=f.get("matched_url"),
                    host=f.get("host"),
                    severity=f.get("severity", "info"),
                    description=f.get("description"),
                    recommendation=f.get("recommendation")
                )
                session.add(fin)
                
            # Save SSL findings
            for s in ssl_findings:
                ssl_f = SSLFinding(
                    scan_id=scan_id,
                    host=s.get("host"),
                    tls_version=s.get("tls_version"),
                    weak_ciphers=s.get("weak_ciphers"),
                    hsts_enabled=s.get("hsts_enabled"),
                    self_signed=s.get("self_signed"),
                    expiry_date=s.get("expiry_date"),
                    issuer=s.get("issuer"),
                    san=s.get("san"),
                    recommendation=s.get("recommendation")
                )
                session.add(ssl_f)
                
            # Save crawl results
            for c in crawl_results:
                cr = CrawlResult(
                    scan_id=scan_id,
                    url=c.get("url"),
                    content_type=c.get("content_type"),
                    is_js=c.get("is_js", False),
                    source_map_found=c.get("source_map_found", False),
                    admin_route_found=c.get("admin_route_found", False),
                    staging_url_found=c.get("staging_url_found", False),
                    secrets_found=c.get("secrets_found")
                )
                session.add(cr)
                
            # Save technologies
            for t in technologies:
                tech = Technology(
                    scan_id=scan_id,
                    host=t.get("host"),
                    tech_name=t.get("tech_name")
                )
                session.add(tech)
                
            # Mark scan as completed
            scan.status = "completed"
            scan.completed_at = datetime.datetime.utcnow()
            
    return scan_id

async def get_scan_data(scan_id: int) -> dict:
    """
    Fetches all data related to a scan and returns a dictionary.
    """
    async with AsyncSessionLocal() as session:
        # Fetch scan
        stmt = select(Scan).where(Scan.id == scan_id)
        res = await session.execute(stmt)
        scan = res.scalars().first()
        if not scan:
            return {}
            
        # Target domain
        stmt = select(Target).where(Target.id == scan.target_id)
        res = await session.execute(stmt)
        target = res.scalars().first()
        domain = target.domain if target else "unknown"
        
        # Subdomains
        stmt = select(Subdomain).where(Subdomain.scan_id == scan_id)
        res = await session.execute(stmt)
        subdomains = res.scalars().all()
        
        # Findings
        stmt = select(Finding).where(Finding.scan_id == scan_id)
        res = await session.execute(stmt)
        findings = res.scalars().all()
        
        # SSL Findings
        stmt = select(SSLFinding).where(SSLFinding.scan_id == scan_id)
        res = await session.execute(stmt)
        ssl_findings = res.scalars().all()
        
        # Crawls
        stmt = select(CrawlResult).where(CrawlResult.scan_id == scan_id)
        res = await session.execute(stmt)
        crawls = res.scalars().all()
        
        # Techs
        stmt = select(Technology).where(Technology.scan_id == scan_id)
        res = await session.execute(stmt)
        techs = res.scalars().all()
        
        # Count severities
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.severity.lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
                
        # Unique technologies list
        tech_list = list(set([t.tech_name for t in techs]))
        
        return {
            "target": domain,
            "scan_id": str(scan_id),
            "timestamp": scan.started_at.strftime("%Y-%m-%d %H:%M:%S"),
            "summary": {
                "total_subdomains": len(subdomains),
                "live_hosts": len([s for s in subdomains if s.is_live]),
                "open_ports": len(set([s.ip_address for s in subdomains if s.ip_address])),
                "technologies": tech_list,
                "critical": severity_counts["critical"],
                "high": severity_counts["high"],
                "medium": severity_counts["medium"],
                "low": severity_counts["low"],
                "info": severity_counts["info"]
            },
            "subdomains": [
                {
                    "subdomain": s.subdomain,
                    "ip_address": s.ip_address,
                    "is_live": s.is_live,
                    "status_code": s.status_code,
                    "title": s.title
                } for s in subdomains
            ],
            "findings": [
                {
                    "tool": f.tool,
                    "template_id": f.template_id,
                    "matched_url": f.matched_url,
                    "host": f.host,
                    "severity": f.severity,
                    "description": f.description,
                    "recommendation": f.recommendation
                } for f in findings
            ],
            "ssl_findings": [
                {
                    "host": s.host,
                    "tls_version": s.tls_version,
                    "weak_ciphers": s.weak_ciphers,
                    "hsts_enabled": s.hsts_enabled,
                    "self_signed": s.self_signed,
                    "expiry_date": s.expiry_date,
                    "issuer": s.issuer,
                    "san": s.san,
                    "recommendation": s.recommendation
                } for s in ssl_findings
            ],
            "crawl_results": [
                {
                    "url": c.url,
                    "content_type": c.content_type,
                    "is_js": c.is_js,
                    "source_map_found": c.source_map_found,
                    "admin_route_found": c.admin_route_found,
                    "staging_url_found": c.staging_url_found,
                    "secrets_found": c.secrets_found
                } for c in crawls
            ],
            # To match structure
            "js_analysis": [
                {
                    "url": c.url,
                    "secrets_found": c.secrets_found
                } for c in crawls if c.secrets_found
            ]
        }
