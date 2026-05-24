import shutil
import ssl
import socket
from pathlib import Path
from dwforsec.utils.subprocess_runner import run_subprocess
from dwforsec.utils.command_builder import get_tool_executable
from dwforsec.services.parser.ssl_parser import parse_sslscan_output
from dwforsec.core.logging import logger

async def run_sslscan(domain: str) -> dict:
    """
    Runs sslscan or falls back to native ssl socket parsing on port 443.
    """
    executable = get_tool_executable("sslscan")
    has_bin = shutil.which(executable) is not None or Path(executable).exists()
    
    if has_bin:
        logger.info(f"Running SSLScan binary on {domain}")
        cmd = [executable, "--no-failed", domain]
        code, stdout, stderr = await run_subprocess(cmd)
        if code == 0 or stdout:
            return parse_sslscan_output(stdout)
            
    logger.info("Falling back to Python-native SSL connection checks")
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        # Determine if we can open connection
        with socket.create_connection((domain, 443), timeout=5.0) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                cipher = ssock.cipher()
                version = ssock.version()
                
                # Retrieve text metadata if needed
                from cryptography import x509
                from cryptography.hazmat.backends import default_backend
                
                x509_cert = x509.load_der_x509_certificate(cert, default_backend())
                issuer_str = ", ".join([f"{x.oid._name}={x.value}" for x in x509_cert.issuer])
                expiry_str = str(x509_cert.not_valid_after_utc)
                
                san_names = []
                try:
                    ext = x509_cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                    san_names = ext.value.get_values_for_type(x509.DNSName)
                except Exception:
                    pass
                    
                return {
                    "tls_versions": [version],
                    "weak_ciphers": [],
                    "issuer": issuer_str,
                    "expiry": expiry_str,
                    "hsts": False,
                    "sans": san_names
                }
    except Exception as e:
        logger.warning(f"Python SSL check failed for {domain}: {e}")
        
    return {
        "tls_versions": [],
        "weak_ciphers": [],
        "issuer": "",
        "expiry": "",
        "hsts": False,
        "sans": []
    }
