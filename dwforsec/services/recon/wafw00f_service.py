import shutil
import httpx
from pathlib import Path
from dwforsec.utils.subprocess_runner import run_subprocess
from dwforsec.utils.command_builder import get_tool_executable
from dwforsec.core.logging import logger

async def run_wafw00f(target_url: str) -> str:
    """
    Runs wafw00f or analyzes response headers natively in Python for WAF fingerprints.
    """
    executable = get_tool_executable("wafw00f")
    has_bin = shutil.which(executable) is not None or Path(executable).exists()
    
    if has_bin:
        logger.info(f"Running Wafw00f binary on {target_url}")
        cmd = [executable, target_url]
        code, stdout, stderr = await run_subprocess(cmd)
        if code == 0 or stdout:
            # Parse stdout
            for line in stdout.splitlines():
                if "is behind" in line:
                    return line.split("is behind", 1)[1].strip()
            if "No WAF detected" in stdout:
                return "None"
                
    logger.info("Falling back to Python WAF header detection")
    try:
        async with httpx.AsyncClient(timeout=5.0, verify=False) as client:
            resp = await client.get(target_url)
            headers = resp.headers
            
            # Simple signature mapping
            if "cloudflare" in headers.get("Server", "").lower() or "cf-ray" in headers:
                return "Cloudflare"
            if "incap-sess" in str(resp.cookies) or "visid_incap" in str(resp.cookies):
                return "Imperva Incapsula"
            if "akamai" in headers.get("Server", "").lower() or "akamai-origin-hop" in headers:
                return "Akamai"
            if "awsalbgoback" in str(resp.cookies) or "awsalb" in str(resp.cookies):
                return "AWS Elastic Load Balancer (WAF)"
            if "sucuri" in headers.get("x-sucuri-id", "").lower() or "sucuri" in headers.get("server", "").lower():
                return "Sucuri"
    except Exception as e:
        logger.warning(f"Python WAF check failed: {e}")
        
    return "None"
