import shutil
from pathlib import Path
from dwforsec.utils.subprocess_runner import run_subprocess
from dwforsec.utils.command_builder import get_tool_executable
from dwforsec.core.logging import logger

async def run_hakrawler(target_url: str) -> list[str]:
    """
    Runs hakrawler -url target_url -depth 3.
    """
    executable = get_tool_executable("hakrawler")
    has_bin = shutil.which(executable) is not None or Path(executable).exists()
    
    if not has_bin:
        logger.warning("Hakrawler is not installed or not in PATH. Skipping Hakrawler.")
        return []
        
    cmd = [executable, "-url", target_url, "-depth", "3"]
    logger.info(f"Running Hakrawler on {target_url}")
    
    code, stdout, stderr = await run_subprocess(cmd)
    if code != 0 and not stdout:
        logger.warning(f"Hakrawler returned code {code}: {stderr}")
        
    urls = []
    for line in stdout.splitlines():
        line = line.strip()
        if line:
            urls.append(line)
            
    return sorted(list(set(urls)))
