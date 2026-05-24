from enum import Enum

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

SEVERITY_COLORS = {
    Severity.CRITICAL: "red",
    Severity.HIGH: "orange3",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "grey50",
}

SEVERITY_EMOJIS = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}

DEFAULT_PORTS = [80, 443, 8080, 8443, 22, 21, 23, 25, 53, 110, 143, 445, 139, 3389, 3306, 5432, 27017, 6379, 8000, 9000]

SECURITY_WARNING = "This framework is intended strictly for authorized security testing on assets you own or have explicit permission to assess."
VERSION = "1.0.0"
