from dwforsec.utils.subprocess_runner import run_subprocess
from dwforsec.utils.command_builder import get_tool_executable
from dwforsec.core.logging import logger

async def run_assetfinder(domain: str) -> list[str]:
    """
    Executes assetfinder --subs-only domain.
    """
    executable = get_tool_executable("assetfinder")
    cmd = [executable, "--subs-only", domain]
    logger.info(f"Running Assetfinder on {domain}")
    
    code, stdout, stderr = await run_subprocess(cmd)
    if code != 0:
        logger.warning(f"Assetfinder returned code {code}: {stderr}")
        
    subdomains = []
    for line in stdout.splitlines():
        line = line.strip()
        if line:
            subdomains.append(line)
            
    return sorted(list(set(subdomains)))
