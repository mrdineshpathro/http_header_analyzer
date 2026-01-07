import json
import csv
from typing import Dict, List, Tuple, Any
from .rules import SecurityRule

class ReportGenerator:
    """Handles grading, exporting, and diffing results."""

    @staticmethod
    def calculate_grade(results: Dict[str, Any]) -> Tuple[str, int]:
        """
        Calculates a grade (A-F) based on analysis results.
        Results input is now { "chain": {url: {headers, waf}}, "ssl": {}, "active": [] }
        However, for backward compatibility or direct hop calls, we need to be careful.
        Actually, we generally grade the Final Hop URL.
        
        Let's assume input is the "Final Hop Analysis" part if called directly,
        OR the full results dict.
        
        The main.py calls this with `results[final_hop_url]`. 
        BUT we changed `analyze()` return structure.
        
        New structure: { "chain": map, "ssl": map, "active": list }
        
        We need to extract the header list for the final hop to score headers,
        AND deduct for active/ssl issues.
        """
        score = 100
        
        # 1. Header Scoring
        # We need to find the final hop headers.
        header_results = []
        
        if "chain" in results:
             # It's the new Full Structure
             final_url = list(results["chain"].keys())[-1]
             header_results = results["chain"][final_url]["headers"]
        elif isinstance(results, list):
             # Legacy or direct list passed
             header_results = results
        else:
             # Fallback
             return "F", 0

        for rule, passed, issues in header_results:
            if not passed:
                if rule.severity == "High":
                    score -= 20
                elif rule.severity == "Medium":
                    score -= 10
                elif rule.severity == "Low":
                    score -= 5
        
        # 2. SSL Deductions
        if "ssl" in results:
             ssl_data = results["ssl"]
             if "issues" in ssl_data:
                 for _ in ssl_data["issues"]:
                     score -= 20 # Severe penalty for SSL issues
        
        # 3. Active Scan Deductions
        if "active" in results:
             for issue in results["active"]:
                 if "CRITICAL" in issue:
                     score -= 50 # Massive penalty for confirmed exploit
                 elif "High" in issue:
                     score -= 30
        
        # Normalize
        if score < 0: score = 0
            
        if score >= 90: return "A", score
        if score >= 80: return "B", score
        if score >= 70: return "C", score
        if score >= 60: return "D", score
        return "F", score

    @staticmethod
    def save_json(full_results: Dict[str, List[Tuple[SecurityRule, bool, List[str]]]], filename: str):
        """Saves the analysis results to a JSON file."""
        output_data = {}
        
        for url, hop_results in full_results.items():
            serialized_results = []
            for rule, passed, issues in hop_results:
                serialized_results.append({
                    "header": rule.header,
                    "severity": rule.severity,
                    "passed": passed,
                    "issues": issues,
                    "description": rule.description
                })
            
            grade, score = ReportGenerator.calculate_grade(hop_results)
            output_data[url] = {
                "grade": grade,
                "score": score,
                "results": serialized_results
            }
            
        with open(filename, 'w') as f:
            json.dump(output_data, f, indent=4)

    @staticmethod
    def compare_scans(current_file: str, old_file: str) -> List[str]:
        """
        Compares two JSON scan files and returns a list of differences.
        
        Args:
            current_file_path: Path to the new scan JSON.
            old_file_path: Path to the old scan JSON.
            
        Returns:
            List of strings describing the changes.
        """
        diffs = []
        try:
            with open(current_file, 'r') as f:
                current_data = json.load(f)
            with open(old_file, 'r') as f:
                old_data = json.load(f)
                
            # Compare common URLs
            for url in current_data:
                if url in old_data:
                    curr_score = current_data[url]['score']
                    old_score = old_data[url]['score']
                    
                    if curr_score > old_score:
                        diffs.append(f"[IMPROVED] {url}: Score increased from {old_score} to {curr_score}")
                    elif curr_score < old_score:
                        diffs.append(f"[REGRESSED] {url}: Score decreased from {old_score} to {curr_score}")
                    
                    # Compare specific headers (simplified)
                    curr_headers = {item['header']: item['passed'] for item in current_data[url]['results']}
                    old_headers = {item['header']: item['passed'] for item in old_data[url]['results']}
                    
                    for header, passed in curr_headers.items():
                        if header in old_headers:
                            if passed and not old_headers[header]:
                                diffs.append(f"  [+] {url}: Fixed {header}")
                            elif not passed and old_headers[header]:
                                diffs.append(f"  [-] {url}: Regressed {header}")
                else:
                    diffs.append(f"[NEW] {url} found in current scan.")
                    
        except FileNotFoundError:
            return ["Error: One of the files was not found."]
        except json.JSONDecodeError:
            return ["Error: Failed to decode JSON."]
            
        if not diffs:
            return ["No significant changes detected."]
            
        return diffs
