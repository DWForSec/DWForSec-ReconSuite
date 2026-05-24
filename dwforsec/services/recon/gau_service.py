import shutil
from pathlib import Path
from dwforsec.utils.subprocess_runner import run_subprocess
from dwforsec.utils.command_builder import get_tool_executable
from dwforsec.core.logging import logger

async def run_gau(domain: str) -> list[str]:
    """
    Executes gau domain and returns the list of URLs.
    """
    executable = get_tool_executable("gau")
    has_bin = shutil.which(executable) is not None or Path(executable).exists()
    
    if not has_bin:
        logger.warning("Gau is not installed or not in PATH. Skipping Gau URLs collection.")
        return []
        
    cmd = [executable, domain]
    logger.info(f"Running Gau on {domain}")
    
    code, stdout, stderr = await run_subprocess(cmd)
    if code != 0 and not stdout:
        logger.warning(f"Gau returned code {code}: {stderr}")
        
    urls = []
    for line in stdout.splitlines():
        line = line.strip()
        if line:
            urls.append(line)
            
    return sorted(list(set(urls)))
