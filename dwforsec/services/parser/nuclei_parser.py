import json
from dwforsec.core.logging import logger

def parse_nuclei_json(raw_json_lines: str) -> list[dict]:
    """
    Parses nuclei --json multi-line string output.
    """
    findings = []
    if not raw_json_lines:
        return findings
        
    for line in raw_json_lines.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            findings.append({
                "template_id": data.get("template-id"),
                "matched_url": data.get("matched-at"),
                "host": data.get("host"),
                "severity": data.get("info", {}).get("severity", "info"),
                "description": data.get("info", {}).get("description", ""),
                "recommendation": data.get("info", {}).get("remediation", "") or data.get("info", {}).get("recommendation", "")
            })
        except json.JSONDecodeError:
            logger.debug(f"Skipped parsing non-JSON line from Nuclei: {line}")
            
    return findings
