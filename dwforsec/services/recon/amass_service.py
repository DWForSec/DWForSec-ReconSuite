from dwforsec.utils.subprocess_runner import run_subprocess
from dwforsec.utils.command_builder import get_tool_executable
from dwforsec.core.logging import logger

async def run_amass(domain: str) -> list[str]:
    """
    Executes amass enum -d domain -silent -timeout 10.
    """
    executable = get_tool_executable("amass")
    # Timeout after 5 mins to prevent long hanging enum
    cmd = [executable, "enum", "-d", domain, "-silent", "-timeout", "10"]
    logger.info(f"Running Amass enum on {domain}")
    
    code, stdout, stderr = await run_subprocess(cmd, timeout_sec=600)
    if code != 0:
        logger.warning(f"Amass returned code {code}: {stderr}")
        
    subdomains = []
    for line in stdout.splitlines():
        line = line.strip()
        if line:
            subdomains.append(line)
            
    return sorted(list(set(subdomains)))
