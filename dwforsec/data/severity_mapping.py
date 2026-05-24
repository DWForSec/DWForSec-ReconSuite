from dwforsec.core.constants import Severity

def map_severity(raw_severity: str) -> Severity:
    if not raw_severity:
        return Severity.INFO
        
    s = raw_severity.strip().lower()
    
    if s in ["critical", "crit", "c", "fatal", "9", "10"]:
        return Severity.CRITICAL
    elif s in ["high", "h", "error", "7", "8"]:
        return Severity.HIGH
    elif s in ["medium", "med", "m", "warning", "warn", "4", "5", "6"]:
        return Severity.MEDIUM
    elif s in ["low", "l", "notice", "1", "2", "3"]:
        return Severity.LOW
    else:
        return Severity.INFO
