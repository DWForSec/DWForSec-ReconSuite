import shutil
import httpx
import re
from urllib.parse import urljoin, urlparse
from pathlib import Path
from dwforsec.utils.subprocess_runner import run_subprocess
from dwforsec.utils.command_builder import get_tool_executable
from dwforsec.core.logging import logger

async def run_katana(target_url: str) -> list[str]:
    """
    Crawls URL with katana or falls back to standard Python requests-based crawl.
    """
    executable = get_tool_executable("katana")
    has_bin = shutil.which(executable) is not None or Path(executable).exists()
    
    if has_bin:
        logger.info(f"Running Katana crawler on {target_url}")
        cmd = [executable, "-u", target_url, "-jc", "-silent"]
        code, stdout, stderr = await run_subprocess(cmd)
        if code == 0 or stdout:
            urls = []
            for line in stdout.splitlines():
                line = line.strip()
                if line:
                    urls.append(line)
            return urls
            
    logger.info("Falling back to Python-based simple crawler")
    urls = set([target_url])
    parsed_base = urlparse(target_url)
    
    try:
        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            resp = await client.get(target_url)
            
            # Simple link extraction via regex
            hrefs = re.findall(r'href=["\'](.*?)["\']', resp.text, re.IGNORECASE)
            srcs = re.findall(r'src=["\'](.*?)["\']', resp.text, re.IGNORECASE)
            
            for path in hrefs + srcs:
                full_url = urljoin(target_url, path)
                # Keep only same domain URLs or JavaScript files
                parsed_full = urlparse(full_url)
                if parsed_full.netloc == parsed_base.netloc or full_url.endswith(".js"):
                    urls.add(full_url)
    except Exception as e:
        logger.warning(f"Python crawler failed to query {target_url}: {e}")
        
    return sorted(list(urls))
