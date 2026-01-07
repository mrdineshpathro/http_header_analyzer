import ssl
import socket
import datetime
from typing import Dict, List, Any
from urllib.parse import urlparse

def inspect_ssl(url: str, port: int = 443) -> Dict[str, Any]:
    """
    Connects to the host and inspects the SSL certificate.
    """
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        return {"error": "Invalid URL for SSL inspection"}

    context = ssl.create_default_context()
    issues = []
    info = {}
    
    try:
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()
                
                # Protocol Version Check
                info["protocol"] = version
                if version in ["TLSv1", "TLSv1.1"]:
                     issues.append(f"Insecure Protocol: {version} (Should be TLS 1.2 or 1.3)")
                     
                # Expiration Check
                not_after_str = cert['notAfter']
                # Format: May 26 23:59:59 2025 GMT
                ssl_date_fmt = r'%b %d %H:%M:%S %Y %Z'
                expiry_date = datetime.datetime.strptime(not_after_str, ssl_date_fmt)
                days_left = (expiry_date - datetime.datetime.utcnow()).days
                
                info["expires"] = not_after_str
                info["days_left"] = days_left
                
                if days_left < 0:
                    issues.append("Certificate Expired")
                elif days_left < 30:
                    issues.append(f"Certificate expires soon ({days_left} days)")
                    
                # Issuer Check
                # cert['issuer'] is a tuple of tuples. ((('countryName', 'US'),), ...)
                issuer_dict = {key: val for sub in cert['issuer'] for key, val in sub}
                issuer_org = issuer_dict.get('organizationName', 'Unknown')
                info["issuer"] = issuer_org
                
    except Exception as e:
        return {"error": f"SSL connection failed: {e}"}

    return {
        "valid": len(issues) == 0,
        "issues": issues,
        "info": info
    }
