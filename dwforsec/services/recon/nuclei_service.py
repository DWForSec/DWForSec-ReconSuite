import shutil
from pathlib import Path
from dwforsec.utils.subprocess_runner import run_subprocess
from dwforsec.utils.command_builder import get_tool_executable
from dwforsec.services.parser.nuclei_parser import parse_nuclei_json
from dwforsec.core.logging import logger

async def run_nuclei(target: str) -> list[dict]:
    """
    Executes nuclei -u target -severity low,medium,high,critical -json -silent.
    """
    executable = get_tool_executable("nuclei")
    has_bin = shutil.which(executable) is not None or Path(executable).exists()
    
    if not has_bin:
        logger.warning("Nuclei is not installed or not in PATH. Skipping Nuclei scan.")
        return []
        
    cmd = [
        executable, 
        "-u", target, 
        "-severity", "low,medium,high,critical", 
        "-json", 
        "-silent"
    ]
    logger.info(f"Running Nuclei on {target}")
    
    code, stdout, stderr = await run_subprocess(cmd, timeout_sec=900)
    if code != 0 and not stdout:
        logger.warning(f"Nuclei returned code {code}: {stderr}")
        
    return parse_nuclei_json(stdout)
