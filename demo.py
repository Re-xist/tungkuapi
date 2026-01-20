#!/usr/bin/env python3
"""
TungkuApi - Demo Script
Shows basic usage and generates sample reports

Author: Re-xist
GitHub: https://github.com/Re-xist
"""

import sys
import json
from datetime import datetime

# Import tungkuapi modules
from utils import Logger, Vulnerability
from reporter import ReportGenerator


def create_demo_report():
    """Create a demo report with sample findings"""

    print("🔥 TungkuApi - Demo Report Generator")
    print("=" * 60)
    print("Creating demo security report...")
    print()

    # Sample results
    results = {
        "target": "https://api.example.com",
        "scan_date": datetime.now().isoformat(),
        "vulnerabilities": [
            {
                "name": "SQL Injection",
                "severity": "CRITICAL",
                "description": "SQL Injection vulnerability detected via error-based injection",
                "evidence": "Payload: ' OR '1'='1\nError: You have an error in your SQL syntax",
                "endpoint": "/api/users",
                "timestamp": datetime.now().isoformat(),
                "remediation": "Gunakan parameterized queries/prepared statements. Validasi dan sanitasi semua user input."
            },
            {
                "name": "Server-Side Request Forgery (SSRF)",
                "severity": "CRITICAL",
                "description": "SSRF vulnerability detected. Application can make requests to internal resources.",
                "evidence": "Parameter: url\nTest URL: http://169.254.169.254\nStatus: 200",
                "endpoint": "/api/proxy",
                "timestamp": datetime.now().isoformat(),
                "remediation": "Validasi dan whitelist semua URLs. Gunakan network segmentation. Disable internal URL access."
            },
            {
                "name": "Missing Security Header: Content-Security-Policy",
                "severity": "HIGH",
                "description": "Missing CSP header",
                "evidence": "Header 'Content-Security-Policy' not present in response",
                "endpoint": "/",
                "timestamp": datetime.now().isoformat(),
                "remediation": "Implement Content-Security-Policy header"
            },
            {
                "name": "Insecure Direct Object Reference (IDOR)",
                "severity": "HIGH",
                "description": "Can access other users' data by changing ID",
                "evidence": "Endpoint: /api/user/\nTest ID: 999",
                "endpoint": "/api/user/999",
                "timestamp": datetime.now().isoformat(),
                "remediation": "Implement proper authorization checks. Use indirect reference maps. Verify ownership on every request."
            },
            {
                "name": "Missing Rate Limiting",
                "severity": "MEDIUM",
                "description": "No rate limiting detected on authentication endpoint",
                "evidence": "Endpoint: /api/login\nFailed attempts: 20",
                "endpoint": "/api/login",
                "timestamp": datetime.now().isoformat(),
                "remediation": "Implement rate limiting pada authentication endpoints. Gunakan progressive delays dan account lockout."
            },
            {
                "name": "Insecure Cookie Configuration",
                "severity": "MEDIUM",
                "description": "Session cookie 'sessionid' missing Secure or HttpOnly flags",
                "evidence": "Cookie: sessionid\nSecure: False\nHttpOnly: False",
                "endpoint": "/api/auth/session",
                "timestamp": datetime.now().isoformat(),
                "remediation": "Set Secure dan HttpOnly flags pada semua session cookies. Gunakan SameSite attribute."
            }
        ],
        "summary": {
            "total": 6,
            "critical": 2,
            "high": 2,
            "medium": 2,
            "low": 0,
            "info": 0
        }
    }

    # Generate reports
    logger = Logger()
    generator = ReportGenerator(results, logger)

    print("Generating HTML report...")
    generator.generate_html("reports/demo_report.html")
    print("[✓] HTML report: reports/demo_report.html")

    print("Generating JSON report...")
    generator.generate_json("reports/demo_report.json")
    print("[✓] JSON report: reports/demo_report.json")

    print("Generating TXT report...")
    generator.generate_text("reports/demo_report.txt")
    print("[✓] TXT report: reports/demo_report.txt")

    print()
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Target     : {results['target']}")
    print(f"Date       : {results['scan_date']}")
    print(f"Total Vulns: {results['summary']['total']}")
    print()
    print("Severity Breakdown:")
    print(f"  CRITICAL: {results['summary']['critical']}")
    print(f"  HIGH    : {results['summary']['high']}")
    print(f"  MEDIUM  : {results['summary']['medium']}")
    print(f"  LOW     : {results['summary']['low']}")
    print()
    print("Demo report generated successfully! 🔥")
    print("Check the 'reports' directory for output files.")


if __name__ == "__main__":
    create_demo_report()
