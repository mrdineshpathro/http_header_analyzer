from typing import Dict, Optional

def detect_waf(headers: Dict[str, str]) -> Optional[str]:
    """
    Analyzes headers to detect WAFs or Proxies.
    Returns the name of the WAF/Proxy if found, else None.
    """
    # Cloudflare
    if "cf-ray" in headers or "cf-cache-status" in headers:
        return "Cloudflare"
    if "server" in headers and "cloudflare" in headers["server"].lower():
        return "Cloudflare"

    # AWS CloudFront / ALB
    if any(k.startswith("x-amz-") for k in headers.keys()):
        if "x-amz-cf-id" in headers:
             return "AWS CloudFront"
        return "AWS Load Balancer"

    # Akamai
    if "x-akamai-trans-id" in headers:
        return "Akamai"
        
    # Incapsula
    if "x-iinfo" in headers or "x-cdn" in headers:
         if "Incapsula" in headers.get("x-cdn", ""):
             return "Imperva Incapsula"

    # Generic Nginx/Apache (Recon info, not exactly WAF but useful)
    server = headers.get("Server", "").lower()
    if "nginx" in server:
        return f"Nginx ({server})"
    if "apache" in server:
        return f"Apache ({server})"
        
    return None
