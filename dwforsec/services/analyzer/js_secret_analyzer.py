from dwforsec.data.js_detection_patterns import COMPILED_PATTERNS
from dwforsec.utils.mask_secret import mask_credential

def analyze_js_secrets(content: str, reveal: bool = False) -> list[dict]:
    """
    Analyzes JavaScript or other files for sensitive credentials, API keys, etc.
    Returns a list of finding dicts.
    """
    findings = []
    if not content:
        return findings
        
    lines = content.splitlines()
    for line_idx, line in enumerate(lines, 1):
        for pattern_name, regex in COMPILED_PATTERNS.items():
            matches = regex.findall(line)
            if matches:
                for match in matches:
                    # Clean match string if it's a tuple or object assignment
                    match_str = str(match).strip()
                    masked = mask_credential(match_str, reveal=reveal)
                    findings.append({
                        "pattern_name": pattern_name,
                        "line_number": line_idx,
                        "raw_match": match_str,
                        "masked_match": masked,
                        "snippet": line[:150].strip()
                    })
    return findings
