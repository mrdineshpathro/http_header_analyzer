import aiohttp
from typing import List, Dict

async def check_crlf(url: str, session: aiohttp.ClientSession) -> List[str]:
    """Test for CRLF Injection Vulnerability."""
    # Attempt to inject a fake header and a Set-Cookie
    # Header splitting payload
    payload = "val%0d%0aSet-Cookie: hacked=true"
    headers = {"X-Test": payload}
    issues = []
    
    try:
        async with session.get(url, headers=headers) as resp:
            # Check if the injected cookie was set by the server
            # Note: aiohttp processes Set-Cookie headers into session.cookie_jar usually, 
            # but we can scan raw headers.
            # However, if Vulnerable, the server treats %0d%0a as delimiter and adds Set-Cookie line.
            # Client (aiohttp) would see 'Set-Cookie' header.
            
            # Check 'Set-Cookie' header specifically for our value
            # Note: headers.getall('Set-Cookie') returns list
            cookies = resp.headers.getall('Set-Cookie', [])
            for cookie in cookies:
                if "hacked=true" in cookie:
                    issues.append("CRITICAL: CRLF Injection Vulnerability detected (Header Splitting).")
                    break
    except Exception:
        pass # Fail silently (e.g. conn error)
        
    return issues

async def check_cors_exploit(url: str, session: aiohttp.ClientSession) -> List[str]:
    """Test for CORS Misconfiguration."""
    origin = "http://evil.com"
    headers = {"Origin": origin}
    issues = []
    
    try:
        async with session.get(url, headers=headers) as resp:
            allow_origin = resp.headers.get("Access-Control-Allow-Origin")
            allow_creds = resp.headers.get("Access-Control-Allow-Credentials")
            
            if allow_origin == origin and allow_creds == "true":
                issues.append(f"CRITICAL: CORS Exploit (Reflected Origin + Credentials) from {origin}")
            elif allow_origin == "*":
                # Already checked by passive rule, but good to confirm dynamic behavior
                pass 
            elif allow_origin == origin:
                 issues.append(f"High: CORS reflects arbitrary origin: {origin}")
                 
    except Exception:
        pass

    return issues
