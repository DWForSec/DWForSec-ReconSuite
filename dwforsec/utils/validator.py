import re
import ipaddress
from urllib.parse import urlparse
from dwforsec.core.config import settings

DOMAIN_REGEX = re.compile(
    r'^(?:[a-zA-Z0-9]'
    r'(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+'
    r'[a-zA-Z]{2,6}$'
)

def is_valid_domain(domain: str) -> bool:
    if not domain:
        return False
    if domain.lower() in ["localhost", "local"]:
        return True
    return bool(DOMAIN_REGEX.match(domain))

def is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False

def validate_target(target: str, public_only: bool = None) -> tuple[bool, str]:
    """
    Validates target string. Returns (is_valid, reason_or_clean_target).
    Target can be a domain, IP address, or URL.
    """
    if public_only is None:
        public_only = settings.PUBLIC_ONLY

    # Strip scheme if present for general check
    clean_target = target.strip()
    if "://" in clean_target:
        parsed = urlparse(clean_target)
        hostname = parsed.hostname
        if not hostname:
            return False, "Failed to parse hostname from URL"
        clean_target = hostname
    
    # Check IP validity
    is_ip = False
    try:
        ipaddress.ip_address(clean_target)
        is_ip = True
    except ValueError:
        pass
        
    if is_ip:
        if public_only and is_private_ip(clean_target):
            return False, f"Target {clean_target} is a private/local IP, but public-only mode is active"
        return True, clean_target
        
    # Check Domain validity
    if is_valid_domain(clean_target):
        if public_only:
            # Check if domain resolves to private IP, or is localhost/local
            if clean_target.lower() in ["localhost", "local"] or clean_target.endswith(".local"):
                return False, f"Target {clean_target} is a local domain, but public-only mode is active"
        return True, clean_target
        
    return False, f"Invalid domain name or IP address format: {target}"
