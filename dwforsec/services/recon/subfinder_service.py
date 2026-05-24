from dwforsec.utils.subprocess_runner import run_subprocess
from dwforsec.utils.command_builder import get_tool_executable
from dwforsec.core.logging import logger

async def run_subfinder(domain: str) -> list[str]:
    """
    Executes subfinder -d domain -silent and returns subdomains list.
    """
    executable = get_tool_executable("subfinder")
    # If subfinder doesn't exist, we fall back to returning domain
    cmd = [executable, "-d", domain, "-silent"]
    logger.info(f"Running Subfinder on {domain}")
    
    code, stdout, stderr = await run_subprocess(cmd)
    if code != 0:
        logger.warning(f"Subfinder returned code {code}: {stderr}")
        
    subdomains = []
    for line in stdout.splitlines():
        line = line.strip()
        if line:
            subdomains.append(line)
            
    return sorted(list(set(subdomains)))
