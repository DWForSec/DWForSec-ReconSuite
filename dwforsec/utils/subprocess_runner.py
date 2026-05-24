import asyncio
import sys
from dwforsec.core.config import settings
from dwforsec.core.logging import logger

async def run_subprocess(cmd: list[str], timeout_sec: int = None) -> tuple[int, str, str]:
    """
    Executes a program asynchronously using asyncio.create_subprocess_exec.
    Allows capturing stdout and stderr. Enforces timeouts.
    """
    timeout = timeout_sec or settings.COMMAND_TIMEOUT
    logger.debug(f"Running subprocess: {' '.join(cmd)} with timeout {timeout}s")
    
    # Argument sanitization: ensure all are strings
    sanitized_cmd = [str(arg) for arg in cmd]
    
    try:
        process = await asyncio.create_subprocess_exec(
            *sanitized_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
            
            # Safe decode
            stdout = stdout_bytes.decode('utf-8', errors='replace')
            stderr = stderr_bytes.decode('utf-8', errors='replace')
            
            return process.returncode or 0, stdout, stderr
            
        except asyncio.TimeoutError:
            logger.error(f"Command timed out after {timeout} seconds: {' '.join(sanitized_cmd)}")
            try:
                process.kill()
            except ProcessLookupError:
                pass
            stdout_bytes, stderr_bytes = await process.communicate()
            stdout = stdout_bytes.decode('utf-8', errors='replace') + "\n[ERROR: Timeout occurred]"
            stderr = stderr_bytes.decode('utf-8', errors='replace')
            return -1, stdout, stderr
            
    except Exception as e:
        logger.error(f"Failed to execute command {' '.join(sanitized_cmd)}: {e}")
        return -1, "", str(e)
