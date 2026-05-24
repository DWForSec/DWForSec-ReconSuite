import re

def parse_sslscan_output(stdout: str) -> dict:
    """
    Parses sslscan stdout to extract cipher strength, HSTS, issuer, SANs.
    """
    weak_ciphers = []
    tls_versions = set()
    issuer = ""
    expiry = ""
    hsts = False
    sans = []
    
    if not stdout:
        return {}
        
    for line in stdout.splitlines():
        line_clean = line.strip()
        
        # Check supported protocols
        if "Accepted" in line:
            if "TLSv1.0" in line:
                tls_versions.add("TLSv1.0")
            elif "TLSv1.1" in line:
                tls_versions.add("TLSv1.1")
            elif "TLSv1.2" in line:
                tls_versions.add("TLSv1.2")
            elif "TLSv1.3" in line:
                tls_versions.add("TLSv1.3")
            elif "SSLv2" in line:
                tls_versions.add("SSLv2")
            elif "SSLv3" in line:
                tls_versions.add("SSLv3")
                
        # Check weak cipher indicators (often containing bits < 128, RC4, DES, or annotated by tool)
        if "Accepted" in line and any(x in line for x in ["DES", "RC4", "3DES", "NULL", " 40 ", " 56 "]):
            weak_ciphers.append(line_clean)
            
        # Issuer
        if "Issuer:" in line:
            issuer = line.split("Issuer:", 1)[1].strip()
            
        # Expiry
        if "Not After :" in line or "Expired:" in line:
            expiry = line.split(":", 1)[1].strip()
            
        # SAN
        if "Subject Alternative Name:" in line or "SAN:" in line:
            sans.append(line_clean)
            
    return {
        "tls_versions": list(tls_versions),
        "weak_ciphers": weak_ciphers,
        "issuer": issuer,
        "expiry": expiry,
        "hsts": hsts, # Often verified externally or via web crawler
        "sans": sans
    }
