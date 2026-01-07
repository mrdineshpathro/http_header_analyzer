from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable
import re

@dataclass
class SecurityRule:
    """Class representing a security rule definition."""
    header: str
    severity: str  # "High", "Medium", "Low", "Info"
    description: str
    remediation: str # Fix advice
    required: bool = True  # True if header MUST be present, False if it MUST NOT be present
    check_function: Optional[Callable[[str], List[str]]] = None # Custom validation logic returning issues

def check_csp(value: str) -> List[str]:
    """Analyzes Content-Security-Policy for unsafe configurations."""
    issues = []
    if "unsafe-inline" in value:
        issues.append("Contains 'unsafe-inline' (XSS Risk)")
    if "unsafe-eval" in value:
        issues.append("Contains 'unsafe-eval' (XSS Risk)")
    if " *" in value or "'*'" in value: 
         if "default-src *" in value or "script-src *" in value:
            issues.append("Wildcard '*' allows loading from anywhere")
    return issues

def check_set_cookie(value: str) -> List[str]:
    """Analyzes Set-Cookie header for security flags."""
    issues = []
    value_lower = value.lower()
    if "secure" not in value_lower:
        issues.append("Missing 'Secure' flag (Plaintext transmission risk)")
    if "httponly" not in value_lower:
        issues.append("Missing 'HttpOnly' flag (XSS risk)")
    if "samesite" not in value_lower:
        issues.append("Missing 'SameSite' attribute (CSRF risk)")
    return issues

def check_hsts(value: str) -> List[str]:
    """Analyzes Strict-Transport-Security header."""
    issues = []
    # Check max-age
    match = re.search(r"max-age=(\d+)", value, re.IGNORECASE)
    if match:
        seconds = int(match.group(1))
        if seconds < 15552000: # ~6 months
            issues.append(f"max-age is too short ({seconds} seconds). Recommended: > 6 months")
    else:
        issues.append("Missing 'max-age' directive")
        
    if "includesubdomains" not in value.lower():
        issues.append("Missing 'includeSubDomains' directive")
    return issues

def check_cors(value: str) -> List[str]:
    """Analyzes Access-Control-Allow-Origin."""
    if value.strip() == "*":
        return ["Origin set to '*' (Allows any domain to access resources)"]
    return []

def check_x_content_type_options(value: str) -> List[str]:
    """Analyzes X-Content-Type-Options."""
    if value.lower() != "nosniff":
        return ["Value is not 'nosniff' (MIME sniffing risk)"]
    return []

# Define the security rules
SECURITY_RULES: List[SecurityRule] = [
    SecurityRule(
        header="X-Frame-Options",
        severity="High",
        description="Clickjacking protection.",
        remediation="Configure your server to send 'X-Frame-Options: SAMEORIGIN' or 'DENY'.",
        required=True
    ),
    SecurityRule(
        header="Content-Security-Policy",
        severity="High",
        description="XSS and Injection protection.",
        remediation="Define a strict CSP. Avoid 'unsafe-inline' and '*'. Example: default-src 'self';",
        required=True,
        check_function=check_csp
    ),
    SecurityRule(
        header="Strict-Transport-Security",
        severity="High",
        description="Enforces HTTPS (HSTS).",
        remediation="Enable HSTS with a long max-age. Example: 'max-age=31536000; includeSubDomains'.",
        required=True,
        check_function=check_hsts
    ),
    SecurityRule(
        header="X-Content-Type-Options",
        severity="Medium",
        description="Prevents MIME-sniffing.",
        remediation="Set 'X-Content-Type-Options: nosniff'.",
        required=True,
        check_function=check_x_content_type_options
    ),
    SecurityRule(
        header="Referrer-Policy",
        severity="Medium",
        description="Controls referrer information leakage.",
        remediation="Set a restrictive policy like 'strict-origin-when-cross-origin'.",
        required=True
    ),
    SecurityRule(
        header="Access-Control-Allow-Origin",
        severity="High",
        description="CORS Policy.",
        remediation="Specify trusted origins explicitly instead of '*'.",
        required=False, # Not required to be present, but check if present. 
        check_function=check_cors
    ),
     SecurityRule(
        header="Set-Cookie",
        severity="High",
        description="Cookie security flags.",
        remediation="Ensure cookies have 'Secure', 'HttpOnly', and 'SameSite=Strict' flags.",
        required=False, 
        check_function=check_set_cookie
    ),
    SecurityRule(
        header="Server",
        severity="Low",
        description="Server version information disclosed.",
        remediation="Disable server signature/version banners in server config.",
        required=False
    ),
    SecurityRule(
        header="X-Powered-By",
        severity="Low",
        description="Technology stack information disclosed.",
        remediation="Remove the 'X-Powered-By' header in your application or server config.",
        required=False
    )
]

