import shutil
from pathlib import Path
from dwforsec.utils.subprocess_runner import run_subprocess
from dwforsec.utils.command_builder import get_tool_executable
from dwforsec.services.parser.nmap_parser import parse_nmap_text
from dwforsec.core.logging import logger

async def run_nmap(target: str) -> list[dict]:
    """
    Executes nmap -sV -Pn -T4 target and parses the ports.
    """
    executable = get_tool_executable("nmap")
    has_bin = shutil.which(executable) is not None or Path(executable).exists()
    
    if not has_bin:
        logger.warning("Nmap is not installed or not in PATH. Skipping Nmap scan.")
        return []
        
    cmd = [executable, "-sV", "-Pn", "-T4", target]
    logger.info(f"Running Nmap on {target}")
    
    code, stdout, stderr = await run_subprocess(cmd, timeout_sec=600)
    if code != 0:
        logger.warning(f"Nmap returned code {code}: {stderr}")
        
    return parse_nmap_text(stdout)
