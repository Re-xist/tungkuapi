#!/usr/bin/env python3
"""
TungkuApi - Advanced API Penetration Testing CLI Tool
Comprehensive security scanner with detailed reporting

Author: Re-xist
GitHub: https://github.com/Re-xist
Version: 3.0
License: MIT
"""

import argparse
import sys
import json
import os
import uuid
import getpass
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

from scanners import (
    SQLScanner, XSSScanner, SSRFScanner, AuthScanner, HeaderScanner,
    XXEScanner, CommandInjectionScanner, DirectoryTraversalScanner,
    MassAssignmentScanner, ParameterPollutionScanner, TemplateInjectionScanner,
    GraphQLScanner, FileUploadScanner, CORSScanner,
    NucleiScanner, GhauriScanner, ExternalToolsScanner
)
from jwt_analyzer import JWTScanner
from ratelimit_scanner import RateLimitScanner
from reporter import ReportGenerator
from utils import APIClient, Logger, APIDiscovery, WAFDetector, Fuzzer, download_seclists
from database import ScanDatabase
from credentials import CredentialManager


class TungkuApi:
    """TungkuApi - API Pentest Tool Utama v3.0"""

    def __init__(self, target, output_dir="reports", verbose=False, threads=5, db_path=None):
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

        # Database (optional)
        self.db = None
        self.db_path = db_path
        if db_path:
            try:
                self.db = ScanDatabase(db_path)
                self.logger.info(f"✓ Database enabled: {db_path}")
            except Exception as e:
                self.logger.warning(f"Could not initialize database: {e}")

        self.results = {
            "target": target,
            "scan_date": datetime.now().isoformat(),
            "vulnerabilities": [],
            "info": [],
            "discovered_endpoints": [],
            "waf_detected": False,
            "summary": {},
            "scanners_used": []
        }

        # Generate unique scan ID
        self.scan_id = f"TUNGKU-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:8]}"

        self.lock = threading.Lock()
        self._scan_progress = {"completed": 0, "total": 0}

    def run_all_scans(self, config=None, scan_types="all", fuzzing=False, wordlist_file=None):
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
        discovered = self.api_discovery.discover(wordlist_file=wordlist_file)
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
            "cors": CORSScanner,
            "jwt": JWTScanner,
            "ratelimit": RateLimitScanner,
            "nuclei": NucleiScanner,
            "ghauri": GhauriScanner,
            "external": ExternalToolsScanner
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

    def generate_report(self, format="html", save_to_db=False):
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

        # Save to database if enabled
        if save_to_db and self.db:
            try:
                # Calculate scan duration
                scan_date = datetime.fromisoformat(self.results["scan_date"])
                duration = (datetime.now() - scan_date).total_seconds()

                self.db.save_scan(self.scan_id, self.results, duration)
                self.logger.success(f"[✓] Scan saved to database: {self.scan_id}")
            except Exception as e:
                self.logger.error(f"[✗] Failed to save to database: {e}")

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
    print(r"""
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║  █████╗ ███████╗ █████╗ ██████╗     ██████╗ ███████╗ █████╗ ███████╗          ║
║  ██╔══██╗██╔════╝██╔══██╗██╔══██╗    ██╔════╝██╔════╝██╔══██╗██╔════╝          ║
║  ███████║███████╗███████║██║  ██║    ██║     █████╗███████║███████╗          ║
║  ██╔══██║╚════██║██╔══██║██║  ██║    ██║     ██╔══╝██╔══██║██╔════╝          ║
║  ██║  ██║███████║██║  ██║██████╔╝    ╚██████╗███████╗██║  ██║███████╗          ║
║  ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝      ╚═════╝╚══════╝╚═╝  ╚═╝╚══════╝          ║
║                                                                           ║
║                    Advanced API Penetration Testing Tool                  ║
║                                 Version 2.0                               ║
║                                                                           ║
║                            Author: Re-xist                                ║
║                       GitHub: https://github.com/Re-xist                   ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
""")


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
                       help="Scan types (comma-separated): sqli,xss,ssrf,auth,headers,jwt,ratelimit,xxe,cmdi,dirtrav,massassign,parampoll,template,graphql,fileupload,cors,nuclei,ghauri,external,discovery,fuzz")
    parser.add_argument("--fuzz", action="store_true",
                       help="Enable API fuzzing")
    parser.add_argument("-w", "--wordlist", metavar="FILE",
                       help="Custom wordlist file for API discovery (one path per line)")
    parser.add_argument("--download-seclists", action="store_true",
                       help="Download SecLists wordlist for API discovery")

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

    # Database & History (NEW v3.0)
    parser.add_argument("--db", "--database", metavar="DB_FILE",
                       help="SQLite database path for historical tracking (default: tungkuapi.db)")
    parser.add_argument("--save-db", action="store_true",
                       help="Save scan results to database")
    parser.add_argument("--history", metavar="TARGET",
                       help="Show scan history for a target")
    parser.add_argument("--trend", "--trend-analysis", metavar="TARGET",
                       help="Show trend analysis for a target")
    parser.add_argument("--trend-days", type=int, default=30,
                       help="Days for trend analysis (default: 30)")
    parser.add_argument("--compare", nargs=2, metavar=("SCAN1", "SCAN2"),
                       help="Compare two scans by ID")
    parser.add_argument("--export-db", metavar="FILE",
                       help="Export database to JSON file")

    # Credential Management (NEW v3.0)
    cred_group = parser.add_argument_group("Credential Management")
    cred_group.add_argument("--set-cred", metavar="PROFILE",
                           help="Set/create credential profile interactively")
    cred_group.add_argument("--list-cred", action="store_true",
                           help="List all credential profiles")
    cred_group.add_argument("--show-cred", metavar="PROFILE",
                           help="Show credential profile details")
    cred_group.add_argument("--del-cred", metavar="PROFILE",
                           help="Delete a credential profile")
    cred_group.add_argument("--use-cred", metavar="PROFILE",
                           help="Use specific credential profile for scan")
    cred_group.add_argument("--set-default-cred", metavar="PROFILE",
                           help="Set default credential profile")

    # Behavior
    parser.add_argument("-v", "--verbose", action="store_true",
                       help="Verbose output")
    parser.add_argument("--no-report", action="store_true",
                       help="Skip report generation")
    parser.add_argument("--no-color", action="store_true",
                       help="Disable colored output")

    args = parser.parse_args()

    # Handle credential management commands (NEW v3.0)
    cred_manager = CredentialManager()

    if args.set_cred:
        # Set/create credential profile interactively
        profile_name = args.set_cred
        print(f"\n{'='*80}")
        print(f"🔐 Setting up credential profile: {profile_name}")
        print(f"{'='*80}\n")

        credentials = {}
        credentials['description'] = input("Description (optional): ").strip()

        print("\n--- Authentication Options ---")
        print("1. JWT Token")
        print("2. Username/Password")
        print("3. API Key")
        print("4. Session Token")
        print("5. Custom Headers")
        print("Select options (comma-separated, e.g., 1,3): ")

        choices = input().strip().split(',')

        # JWT Token
        if '1' in choices:
            jwt_token = input("JWT Token: ").strip()
            if jwt_token:
                credentials['jwt_token'] = jwt_token

        # Username/Password
        if '2' in choices:
            credentials['username'] = input("Username: ").strip()
            credentials['password'] = getpass.getpass("Password: ")

        # API Key
        if '3' in choices:
            api_key = input("API Key: ").strip()
            if api_key:
                credentials['api_key'] = api_key
                header_name = input("API Key Header Name (default: X-API-Key): ").strip()
                credentials['api_key_header'] = header_name if header_name else "X-API-Key"

        # Session Token
        if '4' in choices:
            session_token = input("Session Token: ").strip()
            if session_token:
                credentials['session_token'] = session_token

        # Custom Headers
        if '5' in choices:
            print("\nEnter custom headers (format: 'Name: Value', empty line to finish):")
            headers = {}
            while True:
                header_line = input("> ").strip()
                if not header_line:
                    break
                if ':' in header_line:
                    name, value = header_line.split(':', 1)
                    headers[name.strip()] = value.strip()
            if headers:
                credentials['headers'] = headers

        # Save profile
        if cred_manager.save_profile(profile_name, credentials):
            print(f"\n[✓] Credential profile '{profile_name}' saved successfully!")
            print(f"\n[💡] Usage:")
            print(f"  python tungkuapi.py -u https://api.example.com --use-cred {profile_name}")
        else:
            print(f"\n[✗] Failed to save profile.")

        # Ask if set as default
        set_default = input(f"\nSet '{profile_name}' as default profile? (y/N): ").strip().lower()
        if set_default == 'y':
            if cred_manager.set_default_profile(profile_name):
                print(f"[✓] '{profile_name}' set as default profile")

        sys.exit(0)

    if args.list_cred:
        # List all credential profiles
        profiles = cred_manager.list_profiles()

        print(f"\n{'='*80}")
        print(f"🔐 CREDENTIAL PROFILES")
        print(f"{'='*80}\n")

        if not profiles:
            print("No credential profiles found.")
            print(f"\n[💡] Create one with: --set-cred <profile_name>")
        else:
            default_profile = cred_manager.get_default_profile()

            for profile in profiles:
                is_default = " (DEFAULT)" if profile['name'] == default_profile else ""
                print(f"\n📌 {profile['name']}{is_default}")
                if profile['description']:
                    print(f"   Description: {profile['description']}")
                if profile['username']:
                    print(f"   Username: {profile['username']}")
                print(f"   Has Password: {'Yes' if profile['has_password'] else 'No'}")
                print(f"   Has JWT: {'Yes' if profile['has_jwt'] else 'No'}")
                print(f"   Has API Key: {'Yes' if profile['has_api_key'] else 'No'}")

        print(f"\n{'='*80}")
        sys.exit(0)

    if args.show_cred:
        # Show credential profile details
        profile_name = args.show_cred
        profile = cred_manager.load_profile(profile_name)

        if not profile:
            print(f"[ERROR] Profile '{profile_name}' not found.")
            sys.exit(1)

        print(f"\n{'='*80}")
        print(f"🔐 CREDENTIAL PROFILE: {profile_name}")
        print(f"{'='*80}\n")

        if profile.get('description'):
            print(f"Description: {profile['description']}")

        if profile.get('username'):
            print(f"Username: {profile['username']}")

        if profile.get('password'):
            print(f"Password: {'*' * len(profile['password'])}")

        if profile.get('jwt_token'):
            token = profile['jwt_token']
            print(f"JWT Token: {token[:20]}...{token[-20:]}")

        if profile.get('api_key'):
            key = profile['api_key']
            header = profile.get('api_key_header', 'X-API-Key')
            print(f"API Key ({header}): {key[:10]}...{key[-5:]}")

        if profile.get('session_token'):
            token = profile['session_token']
            print(f"Session Token: {token[:15]}...{token[-10:]}")

        if profile.get('headers'):
            print(f"\nCustom Headers:")
            for name, value in profile['headers'].items():
                print(f"  {name}: {value}")

        print(f"\n{'='*80}")
        sys.exit(0)

    if args.del_cred:
        # Delete credential profile
        profile_name = args.del_cred

        # Confirm
        confirm = input(f"Delete profile '{profile_name}'? (y/N): ").strip().lower()
        if confirm != 'y':
            print("Cancelled.")
            sys.exit(0)

        if cred_manager.delete_profile(profile_name):
            print(f"[✓] Profile '{profile_name}' deleted successfully.")
        else:
            print(f"[✗] Profile '{profile_name}' not found.")
        sys.exit(0)

    if args.set_default_cred:
        # Set default credential profile
        profile_name = args.set_default_cred

        if cred_manager.set_default_profile(profile_name):
            print(f"[✓] '{profile_name}' set as default profile.")
        else:
            print(f"[✗] Failed to set default. Profile '{profile_name}' not found.")
        sys.exit(0)

    # Handle database/history/trending commands (NEW v3.0)
    if args.history:
        # Show scan history
        db_path = args.db or "tungkuapi.db"
        try:
            with ScanDatabase(db_path) as db:
                history = db.get_scan_history(args.history, limit=20)
                print(f"\n{'='*80}")
                print(f"📜 SCAN HISTORY FOR: {args.history}")
                print(f"{'='*80}\n")

                if not history:
                    print("No scan history found.")
                else:
                    for scan in history:
                        print(f"\nScan ID: {scan['scan_id']}")
                        print(f"Date: {scan['scan_date']}")
                        print(f"Total Vulns: {scan['total_vulnerabilities']} "
                              f"(C:{scan['critical_count']} H:{scan['high_count']} "
                              f"M:{scan['medium_count']} L:{scan['low_count']})")
                        print(f"WAF Detected: {scan['waf_detected']}")
                        print(f"Endpoints: {scan['discovered_endpoints']}")
                print(f"\n{'='*80}")
        except Exception as e:
            print(f"[ERROR] {e}")
        sys.exit(0)

    if args.trend:
        # Show trend analysis
        db_path = args.db or "tungkuapi.db"
        try:
            with ScanDatabase(db_path) as db:
                trend = db.get_trend_analysis(args.trend, args.trend_days)
                print(f"\n{'='*80}")
                print(f"📈 TREND ANALYSIS: {trend['target_url']}")
                print(f"Period: Last {trend['period_days']} days")
                print(f"{'='*80}\n")

                if not trend["data"]:
                    print("No trend data available.")
                else:
                    # Summary
                    summary = trend["summary"]
                    print(f"\nTrend: {summary['trend'].upper()}")
                    print(f"Improvement: {summary['improvement_percent']:.1f}%")
                    print(f"First Half Avg: {summary['first_half_avg']:.2f} vulns/day")
                    print(f"Second Half Avg: {summary['second_half_avg']:.2f} vulns/day")

                    # Daily breakdown
                    print(f"\nDaily Breakdown:")
                    print(f"{'Date':<20} {'Critical':<10} {'High':<10} {'Medium':<10} {'Low':<10} {'Total':<10}")
                    print("-" * 70)
                    for day_data in trend["data"][:14]:  # Show last 14 days
                        date = day_data["scan_date"]
                        print(f"{date:<20} {day_data['critical']:<10} {day_data['high']:<10} "
                              f"{day_data['medium']:<10} {day_data['low']:<10} {day_data['total']:<10}")
                print(f"\n{'='*80}")
        except Exception as e:
            print(f"[ERROR] {e}")
        sys.exit(0)

    if args.compare:
        # Compare two scans
        db_path = args.db or "tungkuapi.db"
        try:
            with ScanDatabase(db_path) as db:
                comparison = db.get_scan_comparison(args.compare[0], args.compare[1])
                print(f"\n{'='*80}")
                print("📊 SCAN COMPARISON")
                print(f"{'='*80}\n")

                print(f"\nScan 1:")
                print(f"  ID: {comparison['scan1']['scan_id']}")
                print(f"  Date: {comparison['scan1']['scan_date']}")
                print(f"  Total: {comparison['scan1']['total_vulnerabilities']}")

                print(f"\nScan 2:")
                print(f"  ID: {comparison['scan2']['scan_id']}")
                print(f"  Date: {comparison['scan2']['scan_date']}")
                print(f"  Total: {comparison['scan2']['total_vulnerabilities']}")

                print(f"\nChanges:")
                print(f"  Fixed Vulnerabilities: {comparison['fixed_vulnerabilities']} ✓")
                print(f"  New Vulnerabilities: {comparison['new_vulnerabilities']} ⚠️")
                print(f"  Remaining Vulnerabilities: {comparison['remaining_vulnerabilities']}")
                print(f"  Net Improvement: {comparison['improvement']} {'✓ Improved' if comparison['improvement'] > 0 else '✗ Degraded' if comparison['improvement'] < 0 else '= No Change'}")
                print(f"\n{'='*80}")
        except Exception as e:
            print(f"[ERROR] {e}")
        sys.exit(0)

    if args.export_db:
        # Export database to JSON
        db_path = args.db or "tungkuapi.db"
        try:
            with ScanDatabase(db_path) as db:
                db.export_to_json(args.export_db)
                print(f"\n[✓] Database exported to: {args.export_db}")
        except Exception as e:
            print(f"[ERROR] {e}")
        sys.exit(0)

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

    # Download SecLists if requested
    if args.download_seclists:
        print("\n[📥] Downloading SecLists wordlists...")
        seclists_path = download_seclists(logger=Logger(args.verbose))
        if seclists_path:
            print(f"\n[✓] SecLists ready!")
            print(f"\n[💡] Usage examples:")
            print(f"  python tungkuapi.py -u https://api.example.com -w {seclists_path}/Discovery/Web-Content/api.txt")
            print(f"  python tungkuapi.py -u https://api.example.com -w {seclists_path}/Discovery/Web-Content/rest-api-endpoints.txt")
        sys.exit(0)

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

    # Load credential profile if specified
    if args.use_cred:
        profile_name = args.use_cred
        print(f"\n[🔐] Using credential profile: {profile_name}")

        profile_headers = cred_manager.get_headers_from_profile(profile_name)

        if profile_headers:
            if "headers" not in config:
                config["headers"] = {}

            # Merge profile headers with config headers (profile takes precedence)
            config["headers"].update(profile_headers)

            # Show loaded auth (without showing full tokens)
            if "Authorization" in profile_headers:
                auth = profile_headers["Authorization"]
                print(f"  ✓ Authorization: {auth[:30]}..." if len(auth) > 30 else f"  ✓ Authorization: {auth}")

            if "Cookie" in profile_headers:
                print(f"  ✓ Session: Configured")

            # Show API key headers
            for key in profile_headers:
                if key in ["X-API-Key", "API-Key", "apikey"]:
                    value = profile_headers[key]
                    print(f"  ✓ {key}: {value[:15]}..." if len(value) > 15 else f"  ✓ {key}: {value}")
        else:
            print(f"[ERROR] Profile '{profile_name}' not found or has no headers.")
            sys.exit(1)
    elif cred_manager.get_default_profile():
        # Use default profile if no specific profile requested
        profile_name = cred_manager.get_default_profile()
        print(f"\n[🔐] Using default credential profile: {profile_name}")

        profile_headers = cred_manager.get_headers_from_profile(profile_name)

        if profile_headers:
            if "headers" not in config:
                config["headers"] = {}

            # Merge profile headers with config headers (config takes precedence)
            for key, value in profile_headers.items():
                if key not in config["headers"]:
                    config["headers"][key] = value

            print(f"  ✓ Default profile loaded")

    # Add proxy to config
    if args.proxy:
        config["proxy"] = args.proxy

    config["timeout"] = args.timeout
    config["delay"] = args.delay

    # Run scan
    tool = TungkuApi(args.url, args.output, args.verbose, args.threads, args.db)

    # Set proxy if configured
    if args.proxy:
        tool.client.set_proxy(args.proxy)

    try:
        if args.openapi:
            results = tool.import_openapi(args.openapi, config)
        else:
            scan_types = args.scan if args.scan else "all"
            wordlist_file = args.wordlist if args.wordlist else None
            results = tool.run_all_scans(config, scan_types, args.fuzz, wordlist_file)

        # Save results if requested
        if args.save:
            tool.save_results(args.save)

        # Generate report
        if not args.no_report:
            tool.generate_report(args.format, save_to_db=args.save_db)

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
