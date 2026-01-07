# HTTP Header Analyzer v4.0

An advanced, asynchronous security scanner for HTTP headers, SSL/TLS, and infrastructure configurations. Designed for pentesters and DevOps pipelines.

## Features

- **Asynchronous Scanning**: High-performance bulk scanning with `aiohttp`.
- **Infrastructure Analysis**: WAF/Proxy detection (Cloudflare, AWS, etc.) and SSL/TLS inspection (Expiry, Protocol).
- **Active Vulnerability Checks**: Tests for CRLF Injection and CORS Misconfigurations (Reflected Origin).
- **Deep Header Inspection**: Analyzes CSP, HSTS, Cookie Flags, and more.
- **Remediation**: actionable "Fix" advice for every issue.
- **CI/CD Integration**: "Smart" Exit Codes (`--fail-on-low-score`) for pipeline gating.
- **Reporting**: JSON Export, Diff Mode, and Grade (A-F) calculation.

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### Standard Scan
```bash
python main.py -u example.com
```

### Safe Mode (No Active Attacks)
Disable CRLF/CORS exploitation attempts:
```bash
python main.py -u example.com --safe
```

### CI/CD Pipeline Mode
Fail the build (exit code 1) if grade is C, D, or F:
```bash
python main.py -u example.com --fail-on-low-score
```

### Authenticated Scan
```bash
python main.py -u api.example.com --token "BEARER_TOKEN"
python main.py -u app.example.com --cookie "session=123"
```

### Bulk Scan
```bash
python main.py -f targets.txt -o results.json
```

### Diff Mode
Compare against yesterday's results:
```bash
python main.py -f targets.txt --diff results_yesterday.json
```

## Arguments

| Argument | Description |
| :--- | :--- |
| `-u`, `--url` | Target URL to scan. |
| `-f`, `--file` | File containing list of targets. |
| `-o`, `--output` | Save results to JSON file. |
| `--diff` | Compare current scan against previous JSON. |
| `--safe` | **v4.0**: Disable active vulnerability checks. |
| `--fail-on-low-score` | **v4.0**: Exit code 1 if grade < B. |
| `--token` | Bearer token for Authorization. |
| `--cookie` | Cookie string (key=value). |
| `-v` | Verbose output (redirect chains). |
| `-p` | Proxy URL (http/https). |
| `-a` | Custom User-Agent. |
