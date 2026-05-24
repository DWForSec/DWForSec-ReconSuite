def analyze_ssl_issues(
    tls_version: str, 
    weak_ciphers: list[str] | str, 
    hsts_enabled: bool, 
    self_signed: bool
) -> list[dict]:
    """
    Analyzes parameters from SSL/TLS scans and outputs recommendations.
    """
    findings = []
    
    # Check for weak protocols
    if tls_version:
        tls_clean = tls_version.strip().upper()
        if any(p in tls_clean for p in ["SSLV2", "SSLV3", "TLSV1.0", "TLSV1.1"]):
            findings.append({
                "issue": f"Outdated TLS Protocol Supported: {tls_version}",
                "severity": "high",
                "recommendation": "Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1. Require TLS 1.2 or TLS 1.3."
            })
            
    # Check for weak ciphers
    if weak_ciphers:
        ciphers_str = str(weak_ciphers)
        if any(c in ciphers_str.upper() for c in ["RC4", "3DES", "DES", "MD5", "NULL", "EXPORT", "SWEET32", "CBC"]):
            findings.append({
                "issue": "Insecure or Weak Ciphers Enabled",
                "severity": "medium",
                "recommendation": "Configure the web server to disable weak ciphers (e.g. RC4, 3DES, CBC mode ciphers) and prefer AES-GCM or CHACHA20-POLY1305."
            })
            
    # HSTS check
    if not hsts_enabled:
        findings.append({
            "issue": "HTTP Strict Transport Security (HSTS) Missing",
            "severity": "low",
            "recommendation": "Implement HSTS header (Strict-Transport-Security) with a long max-age directive and subdomains support."
        })
        
    # Self-signed
    if self_signed:
        findings.append({
            "issue": "Self-Signed Certificate Used in Production",
            "severity": "high",
            "recommendation": "Replace the self-signed certificate with one issued by a trusted Public Certificate Authority (CA) or internally managed secure PKI."
        })
        
    return findings
