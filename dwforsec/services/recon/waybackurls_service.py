import shutil
import httpx
from pathlib import Path
from dwforsec.utils.subprocess_runner import run_subprocess
from dwforsec.utils.command_builder import get_tool_executable
from dwforsec.core.logging import logger

async def run_waybackurls(domain: str) -> list[str]:
    """
    Runs waybackurls tool or queries archive.org CDX API directly using httpx.
    """
    executable = get_tool_executable("waybackurls")
    has_bin = shutil.which(executable) is not None or Path(executable).exists()
    
    if has_bin:
        logger.info(f"Running Waybackurls binary on {domain}")
        cmd = [executable, domain]
        code, stdout, stderr = await run_subprocess(cmd)
        if code == 0 or stdout:
            urls = []
            for line in stdout.splitlines():
                line = line.strip()
                if line:
                    urls.append(line)
            return urls
            
    logger.info("Falling back to archive.org API for wayback URLs extraction")
    urls = []
    # Query Web Archive CDX API
    archive_url = f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&collapse=urlkey&fl=original&limit=100"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(archive_url)
            if resp.status_code == 200:
                data = resp.json()
                if len(data) > 1:
                    # Skip header row [ "original" ]
                    for item in data[1:]:
                        urls.append(item[0])
    except Exception as e:
        logger.warning(f"Archive.org query failed: {e}")
        
    return sorted(list(set(urls)))
