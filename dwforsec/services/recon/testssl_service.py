import shutil
from pathlib import Path
from dwforsec.utils.subprocess_runner import run_subprocess
from dwforsec.utils.command_builder import get_tool_executable
from dwforsec.core.logging import logger

async def run_testssl(target_url: str) -> str:
    """
    Executes testssl.sh target_url. Returns raw output text.
    """
    executable = get_tool_executable("testssl.sh")
    has_bin = shutil.which(executable) is not None or Path(executable).exists()
    
    if not has_bin:
        logger.warning("testssl.sh is not installed. Skipping testssl scan.")
        return ""
        
    cmd = [executable, "--quiet", "--color", "0", target_url]
    logger.info(f"Running testssl.sh on {target_url}")
    
    code, stdout, stderr = await run_subprocess(cmd, timeout_sec=900)
    if code != 0 and not stdout:
        logger.warning(f"testssl.sh returned code {code}: {stderr}")
        
    return stdout
