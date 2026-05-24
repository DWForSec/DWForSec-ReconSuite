import re

PORT_STATE_SERVICE_REGEX = re.compile(
    r'^(\d+)/(tcp|udp)\s+open\s+([^\s\n\r]+)(?:\s+(.*))?$'
)

def parse_nmap_text(nmap_stdout: str) -> list[dict]:
    """
    Parses typical terminal output of Nmap.
    Example: 80/tcp open  http    Apache httpd 2.4.41
    """
    ports = []
    if not nmap_stdout:
        return ports
        
    for line in nmap_stdout.splitlines():
        line = line.strip()
        match = PORT_STATE_SERVICE_REGEX.match(line)
        if match:
            port_num = int(match.group(1))
            proto = match.group(2)
            service = match.group(3)
            version = match.group(4) or ""
            
            ports.append({
                "port": port_num,
                "protocol": proto,
                "service": service,
                "version": version.strip()
            })
            
    return ports
