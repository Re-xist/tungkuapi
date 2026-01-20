#!/usr/bin/env python3
"""
TungkuApi - API Penetration Testing CLI Tool
A comprehensive tool for testing API security vulnerabilities

Author: Re-xist
GitHub: https://github.com/Re-xist
Version: 1.0
License: MIT
"""

import argparse
import sys
import json
from datetime import datetime
from pathlib import Path

from scanners import SQLScanner, XSSScanner, SSRFScanner, AuthScanner, HeaderScanner
from reporter import ReportGenerator
from utils import APIClient, Logger


class TungkuApi:
    """TungkuApi - API Pentest Tool Utama"""

    def __init__(self, target, output_dir="reports", verbose=False):
        self.target = target
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.verbose = verbose
        self.logger = Logger(verbose)
        self.client = APIClient(target, self.logger)
        self.results = {
            "target": target,
            "scan_date": datetime.now().isoformat(),
            "vulnerabilities": [],
            "info": [],
            "summary": {}
        }

    def run_all_scans(self, config=None):
        """Run all security scans"""
        self.logger.info(f"Starting security scan on: {self.target}")
        self.logger.info("=" * 60)

        # Initialize scanners
        scanners = [
            SQLScanner(self.client, self.logger),
            XSSScanner(self.client, self.logger),
            SSRFScanner(self.client, self.logger),
            AuthScanner(self.client, self.logger),
            HeaderScanner(self.client, self.logger)
        ]

        # Run each scanner
        for scanner in scanners:
            self.logger.info(f"\n[+] Running {scanner.name}...")
            try:
                findings = scanner.scan(config)
                self.results["vulnerabilities"].extend(findings)
                self.logger.info(f"    Found {len(findings)} issues")
            except Exception as e:
                self.logger.error(f"    Error: {e}")

        # Generate summary
        self._generate_summary()

        return self.results

    def scan_specific(self, scan_type, config=None):
        """Run specific scan type"""
        scan_map = {
            "sqli": SQLScanner,
            "xss": XSSScanner,
            "ssrf": SSRFScanner,
            "auth": AuthScanner,
            "headers": HeaderScanner
        }

        if scan_type not in scan_map:
            self.logger.error(f"Unknown scan type: {scan_type}")
            return

        scanner_class = scan_map[scan_type]
        scanner = scanner_class(self.client, self.logger)

        self.logger.info(f"Running {scanner.name}...")
        findings = scanner.scan(config)
        self.results["vulnerabilities"].extend(findings)

        self._generate_summary()
        return self.results

    def _generate_summary(self):
        """Generate scan summary"""
        vulns = self.results["vulnerabilities"]

        self.results["summary"] = {
            "total": len(vulns),
            "critical": len([v for v in vulns if v["severity"] == "CRITICAL"]),
            "high": len([v for v in vulns if v["severity"] == "HIGH"]),
            "medium": len([v for v in vulns if v["severity"] == "MEDIUM"]),
            "low": len([v for v in vulns if v["severity"] == "LOW"]),
            "info": len([v for v in vulns if v["severity"] == "INFO"])
        }

        self.logger.info("\n" + "=" * 60)
        self.logger.info("SCAN SUMMARY")
        self.logger.info("=" * 60)
        for severity, count in self.results["summary"].items():
            if severity != "total" and count > 0:
                self.logger.info(f"  {severity.upper()}: {count}")

    def generate_report(self, format="html"):
        """Generate security report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = self.output_dir / f"report_{timestamp}"

        generator = ReportGenerator(self.results, self.logger)

        if format == "html" or format == "all":
            html_file = str(report_file) + ".html"
            generator.generate_html(html_file)
            self.logger.info(f"\n[+] HTML report saved: {html_file}")

        if format == "json" or format == "all":
            json_file = str(report_file) + ".json"
            generator.generate_json(json_file)
            self.logger.info(f"[+] JSON report saved: {json_file}")

        if format == "txt" or format == "all":
            txt_file = str(report_file) + ".txt"
            generator.generate_text(txt_file)
            self.logger.info(f"[+] Text report saved: {txt_file}")


def main():
    parser = argparse.ArgumentParser(
        description="TungkuApi - API Penetration Testing CLI Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Contoh Penggunaan:
  # Full scan
  python tungkuapi.py -u https://api.example.com

  # Specific scan
  python tungkuapi.py -u https://api.example.com -s sqli

  # Dengan autentikasi
  python tungkuapi.py -u https://api.example.com -t "Bearer TOKEN"

  # Generate semua format report
  python tungkuapi.py -u https://api.example.com -f all
        """
    )

    parser.add_argument("-u", "--url", required=True,
                       help="Target API URL")
    parser.add_argument("-s", "--scan",
                       choices=["sqli", "xss", "ssrf", "auth", "headers", "all"],
                       default="all",
                       help="Scan type to run (default: all)")
    parser.add_argument("-t", "--token",
                       help="Authentication token (e.g., 'Bearer TOKEN')")
    parser.add_argument("-H", "--header", action="append",
                       help="Custom headers (format: 'Name: Value')")
    parser.add_argument("-o", "--output", default="reports",
                       help="Output directory for reports (default: reports)")
    parser.add_argument("-f", "--format",
                       choices=["html", "json", "txt", "all"],
                       default="html",
                       help="Report format (default: html)")
    parser.add_argument("-c", "--config",
                       help="Configuration file (JSON)")
    parser.add_argument("-v", "--verbose", action="store_true",
                       help="Verbose output")
    parser.add_argument("--no-report", action="store_true",
                       help="Skip report generation")

    args = parser.parse_args()

    # Load config
    config = {}
    if args.config:
        try:
            with open(args.config, 'r') as f:
                config = json.load(f)
        except Exception as e:
            print(f"Error loading config: {e}")
            sys.exit(1)

    # Add headers from args
    if args.header:
        if "headers" not in config:
            config["headers"] = {}
        for h in args.header:
            if ":" in h:
                name, value = h.split(":", 1)
                config["headers"][name.strip()] = value.strip()

    if args.token:
        if "headers" not in config:
            config["headers"] = {}
        config["headers"]["Authorization"] = args.token

    # Run scan
    tool = TungkuApi(args.url, args.output, args.verbose)

    try:
        if args.scan == "all":
            results = tool.run_all_scans(config)
        else:
            results = tool.scan_specific(args.scan, config)

        # Generate report
        if not args.no_report:
            tool.generate_report(args.format)

        # Exit with code based on findings
        critical_count = results["summary"].get("critical", 0)
        high_count = results["summary"].get("high", 0)
        if critical_count > 0 or high_count > 0:
            sys.exit(1)

    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
