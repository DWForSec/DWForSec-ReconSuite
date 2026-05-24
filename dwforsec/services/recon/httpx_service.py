import json
import httpx
import asyncio
from pathlib import Path
from dwforsec.utils.subprocess_runner import run_subprocess
from dwforsec.utils.command_builder import get_tool_executable
from dwforsec.services.parser.httpx_parser import parse_httpx_json
from dwforsec.core.logging import logger

async def run_httpx(subdomains: list[str]) -> list[dict]:
    """
    Probes subdomains to discover status code, title, tech stack.
    If binary is not found, falls back to Python httpx client probing.
    """
    if not subdomains:
        return []
        
    executable = get_tool_executable("httpx")
    
    # Check if executable points to system/local command or is missing
    # Shutil.which returns None and our tool resolves to raw name if missing
    # Let's check if the file actually exists or if we can run it
    import shutil
    has_bin = shutil.which(executable) is not None or Path(executable).exists()
    
    if has_bin:
        logger.info(f"Running httpx binary on {len(subdomains)} hosts")
        temp_file = Path("g:/tools hacking/tools reconsuite/outputs/temp/subdomains.txt")
        temp_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(temp_file, "w", encoding="utf-8") as f:
            f.write("\n".join(subdomains))
            
        cmd = [executable, "-l", str(temp_file), "-status-code", "-tech-detect", "-title", "-json", "-silent"]
        code, stdout, stderr = await run_subprocess(cmd)
        
        # Cleanup
        try:
            temp_file.unlink()
        except OSError:
            pass
            
        if code == 0 or stdout:
            return parse_httpx_json(stdout)
            
    logger.info("Falling back to Python-native httpx client probing")
    results = []
    
    async def probe(sub: str):
        # Add schemes
        for scheme in ["https", "http"]:
            url = f"{scheme}://{sub}"
            try:
                async with httpx.AsyncClient(timeout=5.0, follow_redirects=True, verify=False) as client:
                    resp = await client.get(url)
                    
                    # Extract title
                    title = ""
                    import re
                    match = re.search(r"<title>(.*?)</title>", resp.text, re.IGNORECASE)
                    if match:
                        title = match.group(1).strip()
                        
                    # Extract tech clues from headers
                    tech = []
                    server = resp.headers.get("Server")
                    if server:
                        tech.append(server)
                    powered = resp.headers.get("X-Powered-By")
                    if powered:
                        tech.append(powered)
                        
                    results.append({
                        "url": str(resp.url),
                        "input": sub,
                        "host": sub,
                        "title": title,
                        "status_code": resp.status_code,
                        "technologies": tech,
                        "ip": None
                    })
                    break # Found a live one, skip next scheme
            except Exception:
                continue
                
    # Run concurrently with concurrency semaphore limit
    tasks = [probe(sub) for sub in subdomains]
    await asyncio.gather(*tasks)
    return results
