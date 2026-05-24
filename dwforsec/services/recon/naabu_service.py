import socket
import asyncio
from pathlib import Path
import shutil
from dwforsec.utils.subprocess_runner import run_subprocess
from dwforsec.utils.command_builder import get_tool_executable
from dwforsec.core.constants import DEFAULT_PORTS
from dwforsec.core.logging import logger

async def run_naabu(subdomains: list[str]) -> dict[str, list[int]]:
    """
    Executes naabu port scanner or falls back to Python socket scanning.
    Returns a dict mapping host -> open ports list.
    """
    if not subdomains:
        return {}
        
    executable = get_tool_executable("naabu")
    has_bin = shutil.which(executable) is not None or Path(executable).exists()
    
    if has_bin:
        logger.info(f"Running Naabu binary on {len(subdomains)} hosts")
        temp_file = Path("g:/tools hacking/tools reconsuite/outputs/temp/naabu_hosts.txt")
        temp_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(temp_file, "w", encoding="utf-8") as f:
            f.write("\n".join(subdomains))
            
        cmd = [executable, "-list", str(temp_file), "-top-ports", "1000", "-silent"]
        code, stdout, stderr = await run_subprocess(cmd)
        
        try:
            temp_file.unlink()
        except OSError:
            pass
            
        if code == 0 or stdout:
            results = {}
            for line in stdout.splitlines():
                line = line.strip()
                if ":" in line:
                    host, port_str = line.rsplit(":", 1)
                    try:
                        port = int(port_str)
                        results.setdefault(host, []).append(port)
                    except ValueError:
                        pass
            return results
            
    logger.info("Falling back to Python-socket port scanner")
    results = {}
    
    async def scan_host(host: str):
        open_ports = []
        # Test default subset of ports to save time
        ports_to_test = DEFAULT_PORTS[:10] 
        
        for port in ports_to_test:
            try:
                # Async socket connection check
                conn = asyncio.open_connection(host, port)
                _, writer = await asyncio.wait_for(conn, timeout=1.0)
                open_ports.append(port)
                writer.close()
                await writer.wait_closed()
            except Exception:
                continue
                
        if open_ports:
            results[host] = open_ports
            
    tasks = [scan_host(sub) for sub in subdomains]
    await asyncio.gather(*tasks)
    return results
