import os
import shutil
import sys
from pathlib import Path
from dwforsec.core.config import settings
from dwforsec.core.logging import logger

def get_tool_executable(tool_name: str) -> str:
    """
    Looks for the tool executable in:
    1. dwforsec/tools/<tool_name>/<binary>
    2. System PATH
    Returns the absolute path or just the command if not found locally.
    """
    tools_dir = Path(settings.TOOLS_DIR)
    
    # Executable naming variants for Windows vs Linux/macOS
    is_windows = sys.platform == "win32"
    extensions = [".exe", ".bat", ".cmd", ""] if is_windows else ["", ".sh"]
    
    # Try looking in subdirectory or local path
    tool_subdir = tools_dir / tool_name
    possible_paths = []
    
    if tool_subdir.exists() and tool_subdir.is_dir():
        for ext in extensions:
            # Check direct executable in folder, e.g. tools/subfinder/subfinder.exe
            exec_file = tool_subdir / f"{tool_name}{ext}"
            if exec_file.exists():
                possible_paths.append(exec_file)
            # Check nested executables or inside build folders
            for root, _, files in os.walk(tool_subdir):
                for f in files:
                    if f.lower() == f"{tool_name}{ext}".lower():
                        possible_paths.append(Path(root) / f)
                        
    # Try looking in main tools_dir root
    for ext in extensions:
        exec_file = tools_dir / f"{tool_name}{ext}"
        if exec_file.exists():
            possible_paths.append(exec_file)
            
    if possible_paths:
        # Return first found path
        resolved = str(possible_paths[0].resolve())
        logger.debug(f"Resolved tool '{tool_name}' locally at {resolved}")
        return resolved

    # Fallback to system path
    system_path = shutil.which(tool_name)
    if system_path:
        logger.debug(f"Resolved tool '{tool_name}' on system PATH at {system_path}")
        return system_path
        
    logger.warning(f"Tool '{tool_name}' could not be resolved. Will invoke directly as raw command name.")
    return tool_name
