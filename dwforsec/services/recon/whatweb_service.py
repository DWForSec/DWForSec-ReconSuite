import shutil
from pathlib import Path
from dwforsec.utils.subprocess_runner import run_subprocess
from dwforsec.utils.command_builder import get_tool_executable
from dwforsec.core.logging import logger

async def run_whatweb(target: str) -> list[str]:
    """
    Executes whatweb target --color=never. Returns list of detected techs.
    """
    executable = get_tool_executable("whatweb")
    has_bin = shutil.which(executable) is not None or Path(executable).exists()
    
    if not has_bin:
        logger.warning("WhatWeb is not installed. Skipping WhatWeb scan.")
        return []
        
    cmd = [executable, "--color=never", target]
    logger.info(f"Running WhatWeb on {target}")
    
    code, stdout, stderr = await run_subprocess(cmd)
    if code != 0 and not stdout:
        logger.warning(f"WhatWeb returned code {code}: {stderr}")
        
    techs = []
    # Parse whatweb output line format: http://example.com [200 OK] Apache[2.4.41], Bootstrap, ...
    if stdout:
        parts = stdout.split("[200 OK]")
        if len(parts) > 1:
            tech_part = parts[1].strip()
        else:
            tech_part = stdout.strip()
            
        for t in tech_part.split(","):
            cleaned = t.split("[")[0].strip()
            if cleaned and not cleaned.startswith("http"):
                techs.append(cleaned)
                
    return sorted(list(set(techs)))
