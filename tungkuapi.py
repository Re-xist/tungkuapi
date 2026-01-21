#!/usr/bin/env python3
"""
TungkuApi - Advanced API Penetration Testing CLI Tool
Comprehensive security scanner with detailed reporting

Author: Re-xist
GitHub: https://github.com/Re-xist
Version: 2.0
License: MIT
"""

import argparse
import sys
import json
import os
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

from scanners import (
    SQLScanner, XSSScanner, SSRFScanner, AuthScanner, HeaderScanner,
    XXEScanner, CommandInjectionScanner, DirectoryTraversalScanner,
    MassAssignmentScanner, ParameterPollutionScanner, TemplateInjectionScanner,
    GraphQLScanner, FileUploadScanner, CORSScanner
)
from reporter import ReportGenerator
from utils import APIClient, Logger, APIDiscovery, WAFDetector, Fuzzer


class TungkuApi:
    """TungkuApi - API Pentest Tool Utama v2.0"""

    def __init__(self, target, output_dir="reports", verbose=False, threads=5):
        self.target = target
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.verbose = verbose
        self.threads = threads
        self.logger = Logger(verbose)
        self.client = APIClient(target, self.logger)
        self.waf_detector = WAFDetector(self.client, self.logger)
        self.api_discovery = APIDiscovery(self.client, self.logger)
        self.fuzzer = Fuzzer(self.client, self.logger)

        self.results = {
            "target": target,
            "scan_date": datetime.now().isoformat(),
            "vulnerabilities": [],
            "info": [],
            "discovered_endpoints": [],
            "waf_detected": False,
            "summary": {}
        }

        self.lock = threading.Lock()
        self._scan_progress = {"completed": 0, "total": 0}

    def run_all_scans(self, config=None, scan_types="all", fuzzing=False):
        """Run all security scans"""
        self.logger.info(f"🔥 TungkuApi v2.0 - Starting security scan on: {self.target}")
        self.logger.info("=" * 80)

        # Detect WAF
        self.logger.info("\n[🛡️] Detecting WAF...")
        waf_info = self.waf_detector.detect()
        if waf_info:
            self.results["waf_detected"] = True
            self.results["waf_info"] = waf_info
            self.logger.warning(f"WAF Detected: {waf_info.get('name', 'Unknown')}")
            self.logger.info("Adjusting scan patterns to avoid blocking...")
        else:
            self.logger.info("No WAF detected")

        # API Discovery
        self.logger.info("\n[🔍] Discovering API endpoints...")
        discovered = self.api_discovery.discover()
        self.results["discovered_endpoints"] = discovered
        self.logger.success(f"Found {len(discovered)} endpoints")

        # Initialize scanners
        all_scanners = {
            "sqli": SQLScanner,
            "xss": XSSScanner,
            "ssrf": SSRFScanner,
            "auth": AuthScanner,
            "headers": HeaderScanner,
            "xxe": XXEScanner,
            "cmdi": CommandInjectionScanner,
            "dirtrav": DirectoryTraversalScanner,
            "massassign": MassAssignmentScanner,
            "parampoll": ParameterPollutionScanner,
            "template": TemplateInjectionScanner,
            "graphql": GraphQLScanner,
            "fileupload": FileUploadScanner,
            "cors": CORSScanner
        }

        # Select scanners to run
        scanners_to_run = []
        if scan_types == "all":
            scanners_to_run = list(all_scanners.values())
        else:
            for scan_type in scan_types.split(","):
                if scan_type in all_scanners:
                    scanners_to_run.append(all_scanners[scan_type])

        self._scan_progress["total"] = len(scanners_to_run)

        # Run scanners with threading
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {}
            for scanner_class in scanners_to_run:
                scanner = scanner_class(self.client, self.logger)
                self.logger.info(f"\n[⚡] Running {scanner.name}...")
                future = executor.submit(self._run_scanner, scanner, config, discovered)
                futures[future] = scanner.name

            for future in as_completed(futures):
                scanner_name = futures[future]
                try:
                    findings = future.result()
                    with self.lock:
                        self.results["vulnerabilities"].extend(findings)
                        self._scan_progress["completed"] += 1
                        progress = (self._scan_progress["completed"] / self._scan_progress["total"]) * 100
                        self.logger.info(f"    Found {len(findings)} issues [{progress:.0f}%]")
                except Exception as e:
                    self.logger.error(f"    {scanner_name} Error: {e}")

        # Run fuzzing if enabled
        if fuzzing:
            self.logger.info("\n[🎲] Running API Fuzzing...")
            fuzz_findings = self.fuzzer.fuzz_endpoints(discovered)
            self.results["vulnerabilities"].extend(fuzz_findings)
            self.logger.success(f"Fuzzing found {len(fuzz_findings)} issues")

        # Generate summary
        self._generate_summary()

        return self.results

    def _run_scanner(self, scanner, config, discovered_endpoints):
        """Run individual scanner"""
        try:
            return scanner.scan(config, discovered_endpoints)
        except Exception as e:
            self.logger.error(f"{scanner.name} failed: {e}")
            return []

    def scan_specific(self, scan_type, config=None):
        """Run specific scan type"""
        scan_map = {
            "sqli": SQLScanner,
            "xss": XSSScanner,
            "ssrf": SSRFScanner,
            "auth": AuthScanner,
            "headers": HeaderScanner,
            "xxe": XXEScanner,
            "cmdi": CommandInjectionScanner,
            "dirtrav": DirectoryTraversalScanner,
            "massassign": MassAssignmentScanner,
            "parampoll": ParameterPollutionScanner,
            "template": TemplateInjectionScanner,
            "graphql": GraphQLScanner,
            "fileupload": FileUploadScanner,
            "cors": CORSScanner,
            "discovery": APIDiscovery,
            "fuzz": Fuzzer
        }

        if scan_type not in scan_map:
            self.logger.error(f"Unknown scan type: {scan_type}")
            return

        scanner_class = scan_map[scan_type]

        # Special handling for non-standard scanners
        if scan_type == "discovery":
            self.logger.info("Running API Discovery...")
            discovered = self.api_discovery.discover()
            self.results["discovered_endpoints"] = discovered
            return []

        if scan_type == "fuzz":
            self.logger.info("Running API Fuzzing...")
            discovered = self.api_discovery.discover()
            fuzz_findings = self.fuzzer.fuzz_endpoints(discovered)
            return fuzz_findings

        scanner = scanner_class(self.client, self.logger)
        self.logger.info(f"Running {scanner.name}...")

        discovered = self.api_discovery.discover()
        findings = scanner.scan(config, discovered)

        self.results["vulnerabilities"].extend(findings)
        self._generate_summary()
        return self.results

    def import_openapi(self, spec_file, config=None):
        """Import OpenAPI/Swagger spec and test"""
        self.logger.info(f"📄 Importing OpenAPI spec: {spec_file}")

        try:
            with open(spec_file, 'r') as f:
                if spec_file.endswith('.json'):
                    spec = json.load(f)
                else:
                    import yaml
                    spec = yaml.safe_load(f)
        except Exception as e:
            self.logger.error(f"Failed to load spec: {e}")
            return

        # Extract endpoints from spec
        endpoints = []
        paths = spec.get('paths', {})
        base_path = spec.get('basePath', '')

        for path, methods in paths.items():
            full_path = base_path + path
            for method, details in methods.items():
                if method.lower() in ['get', 'post', 'put', 'delete', 'patch']:
                    endpoints.append({
                        'path': full_path,
                        'method': method.upper(),
                        'params': details.get('parameters', [])
                    })

        self.logger.info(f"Found {len(endpoints)} endpoints in spec")

        # Test each endpoint
        for endpoint_info in endpoints:
            path = endpoint_info['path']
            method = endpoint_info['method']

            self.logger.info(f"Testing {method} {path}")

            # Test with various scanners
            scanners = [
                SQLScanner(self.client, self.logger),
                XSSScanner(self.client, self.logger)
            ]

            for scanner in scanners:
                try:
                    findings = scanner.scan_from_spec(endpoint_info, config)
                    self.results["vulnerabilities"].extend(findings)
                except Exception as e:
                    self.logger.debug(f"Scanner error: {e}")

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

        self.logger.info("\n" + "=" * 80)
        self.logger.info("📊 SCAN SUMMARY")
        self.logger.info("=" * 80)
        for severity, count in self.results["summary"].items():
            if severity != "total" and count > 0:
                emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "🔵"}
                self.logger.info(f"  {emoji.get(severity, '⚪')} {severity.upper()}: {count}")

    def generate_report(self, format="html"):
        """Generate security report"""
        # Extract target name from URL for report filename
        from urllib.parse import urlparse
        parsed_url = urlparse(self.target)
        target_name = parsed_url.netloc.replace('.', '_') if parsed_url.netloc else 'target'
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = self.output_dir / f"{target_name}_scan_{timestamp}"

        generator = ReportGenerator(self.results, self.logger)

        if format == "html" or format == "all":
            html_file = str(report_file) + ".html"
            generator.generate_html(html_file)
            self.logger.info(f"\n[✓] HTML report saved: {html_file}")

        if format == "json" or format == "all":
            json_file = str(report_file) + ".json"
            generator.generate_json(json_file)
            self.logger.info(f"[✓] JSON report saved: {json_file}")

        if format == "txt" or format == "all":
            txt_file = str(report_file) + ".txt"
            generator.generate_text(txt_file)
            self.logger.info(f"[✓] Text report saved: {txt_file}")

        if format == "pdf" or format == "all":
            pdf_file = str(report_file) + ".pdf"
            generator.generate_pdf(pdf_file)
            self.logger.info(f"[✓] PDF report saved: {pdf_file}")

    def save_results(self, filename):
        """Save scan results to file"""
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        self.logger.info(f"[✓] Results saved to: {filename}")

    @staticmethod
    def load_results(filename):
        """Load scan results from file"""
        with open(filename, 'r') as f:
            return json.load(f)

    def diff_scans(self, previous_results):
        """Compare current scan with previous scan"""
        current_vulns = {v['name'] + v['endpoint'] for v in self.results['vulnerabilities']}
        previous_vulns = {v['name'] + v['endpoint'] for v in previous_results['vulnerabilities']}

        new_vulns = current_vulns - previous_vulns
        fixed_vulns = previous_vulns - current_vulns

        return {
            'new': len(new_vulns),
            'fixed': len(fixed_vulns),
            'new_issues': list(new_vulns),
            'fixed_issues': list(fixed_vulns)
        }


def print_banner():
    """Print tool banner"""
    print("=" * 80)
    print("  TUNGKUAPI v2.0 - Advanced API Penetration Testing Tool")
    print("  Author: Re-xist | GitHub: https://github.com/Re-xist")
    print("=" * 80)
    print()
    banner = r"""
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║  ███╗   ███╗ ██████╗ ███████╗                                ║
║  ████╗ ████║██╔═══██╗██╔════╝                                ║
║  ██╔████╔██║██║   ██║███████╗                                ║
║  ██║╚██╔╝██║██║   ██║╚════██║                                ║
║  ██║ ╚═╝ ██║╚██████╔╝███████║                                ║
║  ╚═╝     ╚═╝ ╚═════╝ ╚══════╝                                ║
║  ═════════════════════════════                               ║
║  API    ██████╗ ██╗██╗     ███████╗██████╗                     ║
║  █████╗██╔═══██╗██║██║     ██╔════╝██╔══██╗                    ║
║  ╚════╝██║   ██║██║██║     █████╗  ██║  ██║                    ║
║  ██║   ╚██████╔╝██║██║     ██╔══╝  ██║  ██║                    ║
║  ╚═╝     ╚═════╝ ╚═╝╚═╝     ███████╗██████╔╝                    ║
║                     ╚══════╝ ╚══════╝                         ║
║                                                               ║
║     Advanced API Penetration Testing Tool - Version 2.0        ║
║                                                               ║
║                    Author: Re-xist                             ║
║               GitHub: https://github.com/Re-xist               ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
    """
    print(banner)


def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="TungkuApi v2.0 - Advanced API Penetration Testing Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
🔥 Contoh Penggunaan:
  # Full scan dengan semua fitur
  python tungkuapi.py -u https://api.example.com

  # Scan spesifik
  python tungkuapi.py -u https://api.example.com -s sqli,xss,xxe

  # Dengan autentikasi dan proxy
  python tungkuapi.py -u https://api.example.com -t "Bearer TOKEN" --proxy http://127.0.0.1:8080

  # Import OpenAPI spec
  python tungkuapi.py -u https://api.example.com --openapi swagger.json

  # Fuzzing mode
  python tungkuapi.py -u https://api.example.com --fuzz

  # Simpan dan load hasil
  python tungkuapi.py -u https://api.example.com --save results.json
  python tungkuapi.py --load results.json --diff previous.json

  # Multi-threaded scan
  python tungkuapi.py -u https://api.example.com --threads 10

  # Generate semua format laporan
  python tungkuapi.py -u https://api.example.com -f all
        """
    )

    # Target options
    parser.add_argument("-u", "--url", help="Target API URL")
    parser.add_argument("--openapi", metavar="FILE", help="Import OpenAPI/Swagger spec")

    # Scan options
    parser.add_argument("-s", "--scan",
                       help="Scan types (comma-separated): sqli,xss,ssrf,auth,headers,xxe,cmdi,dirtrav,massassign,parampoll,template,graphql,fileupload,cors,discovery,fuzz")
    parser.add_argument("--fuzz", action="store_true",
                       help="Enable API fuzzing")

    # Authentication & Headers
    parser.add_argument("-t", "--token", help="Authentication token")
    parser.add_argument("-H", "--header", action="append",
                       help="Custom headers (format: 'Name: Value')")

    # Network options
    parser.add_argument("--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--timeout", type=int, default=10,
                       help="Request timeout in seconds (default: 10)")
    parser.add_argument("--threads", type=int, default=5,
                       help="Number of threads (default: 5)")
    parser.add_argument("--delay", type=float, default=0,
                       help="Delay between requests in seconds (default: 0)")

    # Config & Output
    parser.add_argument("-c", "--config", help="Configuration file (JSON)")
    parser.add_argument("-o", "--output", default="reports",
                       help="Output directory (default: reports)")
    parser.add_argument("-f", "--format",
                       choices=["html", "json", "txt", "pdf", "all"],
                       default="html", help="Report format (default: html)")
    parser.add_argument("--save", metavar="FILE",
                       help="Save scan results to file")
    parser.add_argument("--load", metavar="FILE",
                       help="Load scan results from file")
    parser.add_argument("--diff", metavar="FILE",
                       help="Compare with previous scan results")

    # Behavior
    parser.add_argument("-v", "--verbose", action="store_true",
                       help="Verbose output")
    parser.add_argument("--no-report", action="store_true",
                       help="Skip report generation")
    parser.add_argument("--no-color", action="store_true",
                       help="Disable colored output")

    args = parser.parse_args()

    # Load or run scan
    if args.load:
        # Load previous results
        print(f"\n[📂] Loading results from: {args.load}")
        results = TungkuApi.load_results(args.load)

        if args.diff:
            print(f"\n[📊] Comparing with: {args.diff}")
            previous = TungkuApi.load_results(args.diff)
            # Diff logic here
            print(json.dumps(previous, indent=2))

        # Generate report from loaded results
        if not args.no_report:
            output_dir = Path(args.output)
            output_dir.mkdir(exist_ok=True)
            generator = ReportGenerator(results, Logger(args.verbose))

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_file = output_dir / f"report_{timestamp}"

            if args.format == "html" or args.format == "all":
                generator.generate_html(str(report_file) + ".html")
            if args.format == "json" or args.format == "all":
                generator.generate_json(str(report_file) + ".json")
            if args.format == "txt" or args.format == "all":
                generator.generate_text(str(report_file) + ".txt")
            if args.format == "pdf" or args.format == "all":
                generator.generate_pdf(str(report_file) + ".pdf")

        sys.exit(0)

    if not args.url and not args.openapi:
        parser.error("-u/--url or --openapi is required (unless using --load)")

    # Load config
    config = {}
    if args.config:
        try:
            with open(args.config, 'r') as f:
                config = json.load(f)
        except Exception as e:
            print(f"[ERROR] Error loading config: {e}")
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

    # Add proxy to config
    if args.proxy:
        config["proxy"] = args.proxy

    config["timeout"] = args.timeout
    config["delay"] = args.delay

    # Run scan
    tool = TungkuApi(args.url, args.output, args.verbose, args.threads)

    # Set proxy if configured
    if args.proxy:
        tool.client.set_proxy(args.proxy)

    try:
        if args.openapi:
            results = tool.import_openapi(args.openapi, config)
        else:
            scan_types = args.scan if args.scan else "all"
            results = tool.run_all_scans(config, scan_types, args.fuzz)

        # Save results if requested
        if args.save:
            tool.save_results(args.save)

        # Generate report
        if not args.no_report:
            tool.generate_report(args.format)

        # Exit with code based on findings
        critical_count = results["summary"].get("critical", 0)
        high_count = results["summary"].get("high", 0)
        if critical_count > 0 or high_count > 0:
            print("\n" + "=" * 80)
            print(f"[⚠️]  CRITICAL: {critical_count} | HIGH: {high_count}")
            print("=" * 80)
            sys.exit(1)

    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
