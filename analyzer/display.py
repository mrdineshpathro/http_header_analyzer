from colorama import init, Fore, Style
from typing import Dict, List, Tuple, Any
from .rules import SecurityRule

# Initialize colorama
init(autoreset=True)

class Display:
    """Handles console output and formatting."""

    @staticmethod
    def print_banner():
        """Prints the tool banner."""
        print(Fore.CYAN + Style.BRIGHT + "=" * 50)
        print(Fore.CYAN + Style.BRIGHT + "      HTTP HEADER ANALYZER v2.0      ")
        print(Fore.CYAN + Style.BRIGHT + "=" * 50)
        print(Fore.YELLOW + "Scanning for security headers and vulnerabilities...\n")

    @staticmethod
    def print_secure(message: str):
        """Prints a secure/success message."""
        print(f"{Fore.GREEN}[+] {message}")

    @staticmethod
    def print_warning(message: str):
        """Prints a warning message."""
        print(f"{Fore.YELLOW}[!] {message}")

    @staticmethod
    def print_critical(message: str):
        """Prints a critical error message."""
        print(f"{Fore.RED}[-] {message}")

    @staticmethod
    def print_info(message: str):
        """Prints an informational message."""
        print(f"{Fore.BLUE}[*] {message}")
    
    @staticmethod
    def print_error(message: str):
        """Prints a general error message."""
        print(f"{Fore.RED}[ERROR] {message}")

    @staticmethod
    def print_analysis(results: Dict[str, Any], verbose: bool = False):
        """
        Prints the analysis results to the console.
        Input depends on structure: if it's the full dict {chain, ssl, active}, handle accordingly.
        """
        
        # 1. Active Scan Issues
        if "active" in results and results["active"]:
            print(Fore.RED + "\n[!] Active Vulnerabilities Detected:" + Style.RESET_ALL)
            for issue in results["active"]:
                print(f"    {Fore.RED}-> {issue}")
                
        # 2. SSL Info
        if "ssl" in results and results["ssl"]:
            ssl_data = results["ssl"]
            if "error" in ssl_data:
                print(Fore.YELLOW + f"\n[!] SSL Inspection: Failed ({ssl_data['error']})")
            else:
                valid = ssl_data.get("valid", False)
                color = Fore.GREEN if valid else Fore.RED
                print(f"\n{color}[*] SSL/TLS Inspection:{Style.RESET_ALL}")
                print(f"    Issuer:   {ssl_data.get('info', {}).get('issuer', 'Unknown')}")
                print(f"    Expires:  {ssl_data.get('info', {}).get('expires', 'Unknown')} (Days left: {ssl_data.get('info', {}).get('days_left', '?')})")
                print(f"    Protocol: {ssl_data.get('info', {}).get('protocol', 'Unknown')}")
                
                if "issues" in ssl_data and ssl_data["issues"]:
                    for issue in ssl_data["issues"]:
                        print(f"    {Fore.RED}-> {issue}")

        # 3. Chain Analysis
        chain = results.get("chain", {})
        # If passed plain list (legacy), wrap it.
        if isinstance(results, list): # Fallback
             # This shouldn't happen with new core, but safe guard
             pass 
             
        for url, data in chain.items():
            # Only print banner for first/last or intermediate if verbose
            # Actually we usually want to show the Final URL mostly
            is_final = (url == list(chain.keys())[-1])
            
            if not verbose and not is_final:
                continue
                
            print("\n" + Fore.CYAN + f">>> Analysis for: {url}" + Style.RESET_ALL)
            
            # WAF
            if data.get("waf"):
                print(f"{Fore.MAGENTA}[+] WAF Protection Detected: {data['waf']}{Style.RESET_ALL}")
            
            # Headers
            headers_analysis = data.get("headers", [])
            for rule, passed, issues in headers_analysis:
                issues_str = ", ".join(issues)
                
                if rule.required:
                    if passed:
                        Display.print_secure(f"{rule.header}: {issues_str}")
                    else:
                        Display.print_critical(f"{rule.header}: {issues_str}")
                        if rule.remediation:
                             print(f"    {Fore.WHITE}Fix: {rule.remediation}")
                        if len(issues) > 1: 
                             for issue in issues:
                                 if issue != "Missing" and issue != "Present":
                                     print(f"    {Fore.RED}-> {issue}")
                else:
                    if not passed:
                        Display.print_warning(f"{rule.header}: {issues_str}")
                        if rule.remediation:
                             print(f"    {Fore.WHITE}Fix: {rule.remediation}")
                    elif verbose:
                        Display.print_secure(f"{rule.header}: {issues_str}")

    @staticmethod
    def print_grade(url: str, grade: str, score: int):
        """Prints the grade for a URL."""
        color = Fore.GREEN
        if grade in ['C', 'D']: color = Fore.YELLOW
        if grade == 'F': color = Fore.RED
        
        print("\n" + Fore.CYAN + "=" * 50)
        print(f"{Fore.WHITE}Final Score: {color}{score}/100")
        print(f"{Fore.WHITE}Grade:       {color}{grade}")
        print(Fore.CYAN + "=" * 50 + "\n")

    @staticmethod
    def print_diffs(diffs: List[str]):
        """Prints the diff report."""
        print("\n" + Fore.CYAN + "Diff Report:" + Style.RESET_ALL)
        for diff in diffs:
            if "[IMPROVED]" in diff or "[+]" in diff:
                 print(Fore.GREEN + diff)
            elif "[REGRESSED]" in diff or "[-]" in diff:
                 print(Fore.RED + diff)
            else:
                 print(Fore.WHITE + diff)

