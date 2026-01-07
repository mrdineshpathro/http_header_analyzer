import argparse
import sys
import asyncio
import os
from typing import List, Dict, Any
from analyzer import HeaderAnalyzer, Display, ReportGenerator

# Global to store results across async tasks
FULL_REPORT_DATA = {}

async def scan_target(url: str, args: argparse.Namespace, display: Display) -> Dict[str, Any]:
    """
    Scans a single target asynchronously.
    """
    proxies = {"http": args.proxy, "https": args.proxy} if args.proxy else None
    
    # Parse Cookies if provided (format: name=value; name2=value2)
    cookies_dict = None
    if args.cookie:
        cookies_dict = {}
        try:
            for pair in args.cookie.split(';'):
                 if '=' in pair:
                     key, value = pair.strip().split('=', 1)
                     cookies_dict[key] = value
        except Exception:
            display.print_error("Failed to parse cookies. Use format 'key=value; key2=value2'")

    analyzer = HeaderAnalyzer(url)
    
    try:
        await analyzer.fetch_headers(
            timeout=10, 
            proxies=proxies, 
            user_agent=args.user_agent,
            auth_token=args.token,
            cookies=cookies_dict,
            safe_mode=args.safe
        )
    except Exception as e:
        return {"error": f"Error {url}: {e}"}

    try:
        results = analyzer.analyze()
        return {"url": url, "results": results}
    except Exception as e:
        import traceback
        traceback.print_exc()
        return {"error": f"Analysis Error {url}: {e}"}

async def run_scan(targets: List[str], args: argparse.Namespace, display: Display):
    """
    Runs the scan for all targets using asyncio.gather.
    """
    tasks = []
    for url in targets:
        tasks.append(scan_target(url, args, display))
    
    # Run all tasks concurrently
    completed_results = await asyncio.gather(*tasks)
    
    for data in completed_results:
        if "error" in data:
            display.print_error(data["error"])
        else:
            url = data["url"]
            results = data["results"]
            
            try:
                # Print Analysis
                display.print_analysis(results, verbose=args.verbose)
                
                # Calculate Grade
                chain = results.get("chain", {})
                if chain:
                    final_hop_url = list(chain.keys())[-1]
                else:
                    final_hop_url = data["url"] # Fallback

                # ReportGenerator.calculate_grade now handles the full results dict structure
                grade, score = ReportGenerator.calculate_grade(results)
                display.print_grade(final_hop_url, grade, score)
                
                # Store for export
                FULL_REPORT_DATA[url] = results
            except Exception as e:
                import traceback
                traceback.print_exc()
                display.print_error(f"Processing Error for {url}: {e}")

def main():
    """Main entry point for the HTTP Header Analyzer v3.0."""
    
    parser = argparse.ArgumentParser(description="HTTP Header Analyzer v3.0 - Async Security Scanner.")
    
    # Target Arguments
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("-u", "--url", help="Target URL to analyze.")
    target_group.add_argument("-f", "--file", help="File containing list of URLs to scan.")
    
    # Operational Arguments
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output (shows redirect chains).")
    parser.add_argument("-p", "--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080).")
    parser.add_argument("-a", "--user-agent", help="Custom User-Agent string.")
    
    # Auth Arguments
    parser.add_argument("--token", help="Bearer token for Authorization header.")
    parser.add_argument("--cookie", help="Cookie string (e.g., 'session=123; user=admin').")

    # v4.0 Arguments
    parser.add_argument("--safe", action="store_true", help="Disable active vulnerability scans (CRLF, CORS exploitation).")
    parser.add_argument("--fail-on-low-score", action="store_true", help="Return exit code 1 if grade is C, D, or F.")

    # Reporting Arguments
    parser.add_argument("-o", "--output", help="Save results to JSON file.")
    parser.add_argument("--diff", help="Compare current scan against a previous JSON scan file.")
    
    args = parser.parse_args()
    
    display = Display()
    display.print_banner()

    # Collect Targets
    targets = []
    if args.url:
        targets.append(args.url)
    elif args.file:
        try:
            with open(args.file, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            display.print_error(f"File not found: {args.file}")
            sys.exit(1)

    display.print_info(f"Targets: {len(targets)} | Mode: Asyncio")
    if args.safe:
         display.print_info("Safe Mode: Active scans disabled.")
    
    if args.proxy:
         display.print_info(f"Using Proxy: {args.proxy}")

    # Run Async Loop
    try:
        if sys.platform == 'win32':
             asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        asyncio.run(run_scan(targets, args, display))
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
        sys.exit(0)

    # Export
    if args.output:
        ReportGenerator.save_json(FULL_REPORT_DATA, args.output)
        display.print_secure(f"Report saved to {args.output}")

    # Diff
    if args.diff:
        display.print_info(f"Comparing against {args.diff}...")
        
        import tempfile
        
        current_scan_file = args.output
        temp_created = False
        
        if not current_scan_file:
            if not FULL_REPORT_DATA:
                display.print_error("No results to compare.")
                return 

            fd, current_scan_file = tempfile.mkstemp(suffix=".json")
            os.close(fd)
            ReportGenerator.save_json(FULL_REPORT_DATA, current_scan_file)
            temp_created = True
            
        diffs = ReportGenerator.compare_scans(current_scan_file, args.diff)
        display.print_diffs(diffs)
                
        if temp_created:
             try:
                os.remove(current_scan_file)
             except PermissionError:
                 pass 

    # Exit Code Logic
    if args.fail_on_low_score:
        # Check if ANY target failed
        failed = False
        for url, results in FULL_REPORT_DATA.items():
            # In v4 structure, results is the full dict {chain, ...}
            # ReportGenerator.calculate_grade handles it.
            grade, score = ReportGenerator.calculate_grade(results)
            if grade in ['C', 'D', 'F']:
                failed = True
                break
        
        if failed:
            sys.exit(1)
        sys.exit(0)

if __name__ == "__main__":
    main()

