import json
from dwforsec.core.logging import logger

def parse_httpx_json(raw_json_lines: str) -> list[dict]:
    """
    Parses httpx JSON output line by line.
    """
    results = []
    if not raw_json_lines:
        return results
        
    for line in raw_json_lines.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            # Standardize output format
            results.append({
                "url": data.get("url"),
                "input": data.get("input"),
                "host": data.get("host"),
                "title": data.get("title"),
                "status_code": data.get("status_code") or data.get("status-code"),
                "technologies": data.get("tech") or data.get("technologies") or [],
                "ip": data.get("ip") or data.get("ip_address")
            })
        except json.JSONDecodeError:
            # Fallback for plain lines
            if line.startswith("http://") or line.startswith("https://"):
                results.append({
                    "url": line,
                    "host": line.split("://", 1)[-1].split("/", 1)[0],
                    "status_code": None,
                    "technologies": [],
                    "title": None,
                    "ip": None
                })
                
    return results
