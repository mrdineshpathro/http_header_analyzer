import aiohttp
import asyncio
from typing import Dict, List, Optional, Tuple, Any
from .rules import SECURITY_RULES, SecurityRule
from .ssl_inspect import inspect_ssl
from .waf_detect import detect_waf
from .active_scan import check_crlf, check_cors_exploit

class HeaderAnalyzer:
    """Core logic for analyzing HTTP headers (Async)."""

    def __init__(self, url: str):
        """
        Initialize the analyzer.
        
        Args:
            url: The target URL to scan.
        """
        self.url = self.normalize_url(url)
        # Store results as a list of dictionaries, one for each hop
        self.chain: List[Dict[str, Any]] = []
        self.ssl_info: Dict[str, Any] = {}
        self.active_issues: List[str] = []

    def normalize_url(self, url: str) -> str:
        """Ensures the URL has a valid schema."""
        if not url.startswith(("http://", "https://")):
            return f"http://{url}"
        return url

    async def fetch_headers(self, 
                            timeout: int = 10, 
                            proxies: Optional[Dict] = None, 
                            user_agent: Optional[str] = None,
                            auth_token: Optional[str] = None,
                            cookies: Optional[Dict] = None,
                            safe_mode: bool = False) -> bool:
        """
        Fetches HTTP headers, traces redirects, and performs active/ssl scans.
        """
        headers_request = {}
        if user_agent:
            headers_request['User-Agent'] = user_agent
        else:
            headers_request['User-Agent'] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) aiohttp"
            
        if auth_token:
            headers_request['Authorization'] = f"Bearer {auth_token}"

        proxy_url = None
        if proxies:
            proxy_url = proxies.get('http') or proxies.get('https')

        timeout_client = aiohttp.ClientTimeout(total=timeout)
        
        try:
            async with aiohttp.ClientSession(timeout=timeout_client, cookies=cookies) as session:
                async with session.get(self.url, headers=headers_request, proxy=proxy_url) as response:
                    
                    # 1. Process redirect history
                    for resp in response.history:
                        self.chain.append({
                            'url': str(resp.url),
                            'status': resp.status,
                            'headers': dict(resp.headers)
                        })
                    
                    # 2. Append final response
                    self.chain.append({
                        'url': str(response.url),
                        'status': response.status,
                        'headers': dict(response.headers)
                    })
                    
                    # 3. Active Scanning (if not safe mode)
                    if not safe_mode:
                        crlf_issues = await check_crlf(self.url, session)
                        cors_issues = await check_cors_exploit(self.url, session)
                        self.active_issues.extend(crlf_issues)
                        self.active_issues.extend(cors_issues)

            # 4. SSL Inspection (Blocking I/O, run in thread)
            if self.url.startswith("https://"):
                loop = asyncio.get_running_loop()
                # Run sync SSL check in default executor
                try:
                    parsed = self.url.split("://")[1].split("/")[0].split(":")[0] # Crude parsing for quick host extract
                    self.ssl_info = await loop.run_in_executor(None, inspect_ssl, self.url)
                except Exception as e:
                    self.ssl_info = {"error": str(e)}

            return True
            
        except aiohttp.ClientError as e:
            raise Exception(f"Aiohttp ClientError: {e}")
        except asyncio.TimeoutError:
            raise Exception("Connection timed out")
        except Exception as e:
             raise e

    def analyze(self) -> Dict[str, Any]:
        """
        Analyzes headers, SSL, and Active scan results.
        Returns a dict containing 'chain_results', 'ssl_results', 'active_results'.
        """
        chain_results = {}
        
        for hop in self.chain:
            url = hop['url']
            headers = hop['headers']
            hop_results = []
            
            # WAF Detection per hop
            waf = detect_waf(headers)
            
            for rule in SECURITY_RULES:
                header_value = headers.get(rule.header) or headers.get(rule.header.lower()) 
                
                passed = True
                issues = []

                if rule.required:
                    if header_value:
                        if rule.check_function:
                            custom_issues = rule.check_function(header_value)
                            if custom_issues:
                                passed = False 
                                issues.extend(custom_issues)
                            else:
                                passed = True 
                                issues.append("Present and Secure")
                        else:
                            passed = True
                            issues.append("Present")
                    else:
                        passed = False
                        issues.append("Missing")
                else:
                    if header_value:
                        if rule.check_function:
                            custom_issues = rule.check_function(header_value)
                            if custom_issues:
                                passed = False
                                issues.extend(custom_issues)
                            else:
                                if rule.header in ["Server", "X-Powered-By"]:
                                     passed = False
                                     issues.append(f"Disclosed: {header_value}")
                                else:
                                     passed = True 
                                     issues.append("Present and Secure")
                        else:
                            passed = False
                            issues.append(f"Disclosed: {header_value}")
                    else:
                        passed = True
                        issues.append("Not Disclosed")
                
                hop_results.append((rule, passed, issues))
            
            chain_results[url] = {
                "headers": hop_results,
                "waf": waf
            }
            
        return {
            "chain": chain_results,
            "ssl": self.ssl_info,
            "active": self.active_issues
        }

