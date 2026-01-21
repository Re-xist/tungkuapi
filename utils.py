"""
TungkuApi - Utility Functions & Modules

Author: Re-xist
GitHub: https://github.com/Re-xist
Version: 2.0
"""

import requests
from urllib.parse import urljoin, urlparse
from datetime import datetime
import json
import time
import re
import random
from pathlib import Path


class Logger:
    """Enhanced logger with file support"""

    def __init__(self, verbose=False, log_file=None):
        self.verbose = verbose
        self.log_file = log_file
        if log_file:
            Path(log_file).parent.mkdir(parents=True, exist_ok=True)

    def _log(self, message):
        """Write to log file if enabled"""
        if self.log_file:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open(self.log_file, 'a') as f:
                f.write(f"[{timestamp}] {message}\n")

    def info(self, message):
        """Print info message"""
        print(message)
        self._log(message)

    def error(self, message):
        """Print error message"""
        print(f"[ERROR] {message}")
        self._log(f"ERROR: {message}")

    def debug(self, message):
        """Print debug message if verbose"""
        if self.verbose:
            print(f"[DEBUG] {message}")
            self._log(f"DEBUG: {message}")

    def success(self, message):
        """Print success message"""
        print(f"[+] {message}")
        self._log(f"SUCCESS: {message}")

    def warning(self, message):
        """Print warning message"""
        print(f"[!] {message}")
        self._log(f"WARNING: {message}")


class APIClient:
    """Enhanced HTTP Client for API testing with proxy support"""

    def __init__(self, base_url, logger=None, timeout=10):
        self.base_url = base_url.rstrip("/")
        self.logger = logger or Logger()
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "TungkuApi/2.0 (Security Scanner)"
        })
        self.proxy = None

    def set_headers(self, headers):
        """Set custom headers"""
        self.session.headers.update(headers)

    def set_auth(self, token):
        """Set authentication token"""
        self.session.headers["Authorization"] = token

    def set_proxy(self, proxy_url):
        """Set proxy for all requests"""
        self.proxy = {
            "http": proxy_url,
            "https": proxy_url
        }
        self.session.proxies = self.proxy
        self.logger.info(f"Proxy set: {proxy_url}")

    def request(self, method, endpoint, **kwargs):
        """Make HTTP request"""
        url = urljoin(self.base_url + "/", endpoint.lstrip("/"))
        self.logger.debug(f"{method} {url}")

        # Add delay if configured
        if "delay" in kwargs:
            time.sleep(kwargs.pop("delay"))

        try:
            response = self.session.request(
                method,
                url,
                timeout=self.timeout,
                **kwargs
            )
            return response
        except requests.exceptions.Timeout:
            self.logger.error(f"Request timeout: {url}")
            return None
        except requests.exceptions.ConnectionError:
            self.logger.error(f"Connection error: {url}")
            return None
        except Exception as e:
            self.logger.error(f"Request failed: {e}")
            return None

    def get(self, endpoint, **kwargs):
        """GET request"""
        return self.request("GET", endpoint, **kwargs)

    def post(self, endpoint, **kwargs):
        """POST request"""
        return self.request("POST", endpoint, **kwargs)

    def put(self, endpoint, **kwargs):
        """PUT request"""
        return self.request("PUT", endpoint, **kwargs)

    def delete(self, endpoint, **kwargs):
        """DELETE request"""
        return self.request("DELETE", endpoint, **kwargs)

    def patch(self, endpoint, **kwargs):
        """PATCH request"""
        return self.request("PATCH", endpoint, **kwargs)

    def probe_endpoint(self, endpoint):
        """Probe endpoint to check if it exists"""
        response = self.get(endpoint)
        if response:
            return {
                "exists": True,
                "status_code": response.status_code,
                "content_length": len(response.content),
                "headers": dict(response.headers)
            }
        return {"exists": False}


class APIDiscovery:
    """API Endpoint Discovery Module"""

    COMMON_PATHS = [
        # API endpoints
        "api", "v1", "v2", "api/v1", "api/v2", "rest", "graphql",
        # Authentication
        "auth", "login", "logout", "register", "signin", "signup", "token", "oauth",
        # Users
        "users", "user", "profile", "account", "me", "members",
        # Data
        "data", "items", "products", "orders", "transactions", "payments",
        # Admin
        "admin", "dashboard", "settings", "config", "manage",
        # Files
        "files", "upload", "download", "media", "attachments",
        # Search
        "search", "query", "find", "filter",
        # Other
        "webhook", "callback", "notify", "status", "health", "ping"
    ]

    def __init__(self, client, logger=None):
        self.client = client
        self.logger = logger or Logger()
        self.discovered = []

    def load_wordlist(self, wordlist_file):
        """Load wordlist from file"""
        try:
            with open(wordlist_file, 'r') as f:
                wordlist = [line.strip() for line in f if line.strip()]
            self.logger.info(f"Loaded {len(wordlist)} paths from {wordlist_file}")
            return wordlist
        except FileNotFoundError:
            self.logger.error(f"Wordlist file not found: {wordlist_file}")
            return []
        except Exception as e:
            self.logger.error(f"Error loading wordlist: {e}")
            return []

    def discover(self, custom_wordlist=None, wordlist_file=None):
        """Discover API endpoints"""
        endpoints = []

        # Determine which wordlist to use
        if wordlist_file:
            wordlist = self.load_wordlist(wordlist_file)
        elif custom_wordlist:
            wordlist = custom_wordlist
        else:
            wordlist = self.COMMON_PATHS

        self.logger.info(f"Starting discovery with {len(wordlist)} paths...")

        for path in wordlist:
            # Test with and without leading /
            test_paths = [path, f"/{path}"]

            for test_path in test_paths:
                response = self.client.get(test_path)
                if response and response.status_code != 404:
                    endpoint_info = {
                        "path": f"/{path}" if not path.startswith("/") else path,
                        "status": response.status_code,
                        "method": "GET",
                        "content_type": response.headers.get("Content-Type", ""),
                        "length": len(response.content)
                    }
                    if endpoint_info not in endpoints:
                        endpoints.append(endpoint_info)
                        self.logger.debug(f"Found: {test_path} [{response.status_code}]")

        # Try to discover additional endpoints via common API patterns
        endpoints.extend(self._discover_api_patterns())

        self.discovered = endpoints
        return endpoints

    def _discover_api_patterns(self):
        """Discover API endpoints via common patterns"""
        patterns = []

        # Common REST API patterns
        rest_patterns = [
            "/api/users", "/api/users/{id}", "/api/products", "/api/products/{id}",
            "/api/orders", "/api/auth/login", "/api/auth/register",
            "/v1/users", "/v2/users", "/rest/users"
        ]

        for pattern in rest_patterns:
            response = self.client.get(pattern)
            if response and response.status_code != 404:
                patterns.append({
                    "path": pattern,
                    "status": response.status_code,
                    "method": "GET",
                    "content_type": response.headers.get("Content-Type", ""),
                    "length": len(response.content)
                })

        return patterns


class WAFDetector:
    """WAF (Web Application Firewall) Detector"""

    WAF_SIGNATURES = {
        "Cloudflare": ["cloudflare", "cf-ray", "__cfduid"],
        "AWS WAF": ["aws-waf", "x-amz-cf-id"],
        "Akamai": ["akamai", "akamaighost"],
        "Incapsula": ["incap_ses", "incap_cookie"],
        "Sucuri": ["sucuri"],
        "F5 BIG-IP": ["bigip", "f5"],
        "Barracuda": ["barracuda"],
        "ModSecurity": ["mod_security"],
        "Wordfence": ["wordfence"],
        "Google": ["gcp", "google"],
        "Azure": ["azure", "x-ms-"]
    }

    def __init__(self, client, logger=None):
        self.client = client
        self.logger = logger or Logger()

    def detect(self):
        """Detect WAF presence"""
        # Test with malicious payload to trigger WAF
        test_payloads = [
            "?id=1' OR 1=1--",
            "?script=<script>alert(1)</script>",
            "?file=../../../../etc/passwd",
            "?cmd=; ls -la"
        ]

        detected_waf = None

        for payload in test_payloads:
            response = self.client.get(f"/{payload}")

            if response:
                # Check headers for WAF signatures
                headers = dict(response.headers)
                detected_waf = self._check_waf_headers(headers)

                if detected_waf:
                    break

                # Check response for WAF indicators
                if response.status_code == 403 or response.status_code == 406:
                    if "waf" in response.text.lower() or "blocked" in response.text.lower():
                        detected_waf = {"name": "Unknown WAF", "reason": "Blocked malicious payload"}
                        break

        return detected_waf

    def _check_waf_headers(self, headers):
        """Check response headers for WAF signatures"""
        headers_str = json.dumps(headers, default=str).lower()

        for waf_name, signatures in self.WAF_SIGNATURES.items():
            for signature in signatures:
                if signature.lower() in headers_str:
                    return {"name": waf_name, "signature": signature}

        return None


class Fuzzer:
    """API Fuzzing Module"""

    FUZZ_STRINGS = [
        # SQL injection
        "' OR '1'='1", "1' ORDER BY 1--", "' UNION SELECT NULL--",
        # XSS
        "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
        # Path traversal
        "../../../../etc/passwd", "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        # Command injection
        "; ls -la", "| whoami", "$(cat /etc/passwd)",
        # XXE
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
        # SSTI
        "{{7*7}}", "${7*7}", "%7B%7B7*7%7D%7D",
        # Format strings
        "%s", "%n", "%x",
        # NULL bytes
        "%00", "\x00",
        # Overflow
        "A" * 1000, "A" * 10000,
        # Special chars
        "../../", "<>", "|", "&", ";", "$", "`",
        # Unicode
        "\u0000", "\uFEFF", "\u200B"
    ]

    def __init__(self, client, logger=None):
        self.client = client
        self.logger = logger or Logger()

    def fuzz_endpoints(self, endpoints, max_requests=50):
        """Fuzz discovered endpoints"""
        findings = []
        requests_made = 0

        for endpoint_info in endpoints[:10]:  # Limit to prevent excessive requests
            path = endpoint_info.get("path", "")

            if requests_made >= max_requests:
                break

            # Fuzz query parameters
            for fuzz_string in random.sample(self.FUZZ_STRINGS, min(5, len(self.FUZZ_STRINGS))):
                if requests_made >= max_requests:
                    break

                test_url = f"{path}?input={fuzz_string}"
                response = self.client.get(test_url)

                requests_made += 1

                if response:
                    # Check for interesting responses
                    if response.status_code >= 400:
                        findings.append({
                            "name": "Fuzz Finding",
                            "severity": "INFO",
                            "description": f"Fuzzing triggered {response.status_code} response",
                            "evidence": f"URL: {test_url}\nStatus: {response.status_code}",
                            "endpoint": path,
                            "timestamp": datetime.now().isoformat()
                        })

                    # Check for error reflection
                    if any(err in response.text.lower() for err in ["sql", "error", "exception", "fatal"]):
                        findings.append({
                            "name": "Error Message Disclosure",
                            "severity": "LOW",
                            "description": "Fuzzing triggered error message",
                            "evidence": f"URL: {test_url}\nError: {response.text[:200]}",
                            "endpoint": path,
                            "timestamp": datetime.now().isoformat()
                        })

        return findings


class Vulnerability:
    """Vulnerability finding"""

    SEVERITY_LEVELS = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

    @staticmethod
    def create(name, severity, description, evidence, endpoint, remediation=None,
               full_url=None, parameter=None, request_method="GET", payload=None,
               request_detail=None, response_detail=None):
        """Create a vulnerability finding with enhanced details"""
        if severity not in Vulnerability.SEVERITY_LEVELS:
            severity = "INFO"

        finding = {
            "name": name,
            "severity": severity,
            "description": description,
            "evidence": evidence,
            "endpoint": endpoint,
            "timestamp": datetime.now().isoformat()
        }

        # Enhanced fields
        if full_url:
            finding["full_url"] = full_url
        if parameter:
            finding["parameter"] = parameter
        if request_method:
            finding["request_method"] = request_method
        if payload:
            finding["payload"] = payload
        if request_detail:
            finding["request_detail"] = request_detail
        if response_detail:
            finding["response_detail"] = response_detail
        if remediation:
            finding["remediation"] = remediation

        return finding


def analyze_response(response, check_patterns):
    """Analyze response for specific patterns"""
    findings = []

    if not response:
        return findings

    for pattern_name, pattern_data in check_patterns.items():
        indicators = pattern_data.get("indicators", [])
        severity = pattern_data.get("severity", "MEDIUM")

        for indicator in indicators:
            if indicator in response.text:
                findings.append({
                    "pattern": pattern_name,
                    "severity": severity,
                    "match": indicator[:100],
                    "evidence": f"Found '{indicator[:50]}...' in response"
                })
                break

    return findings


def extract_params_from_url(url):
    """Extract parameters from URL"""
    parsed = urlparse(url)
    params = {}
    if parsed.query:
        for param in parsed.query.split("&"):
            if "=" in param:
                key, value = param.split("=", 1)
                params[key] = value
    return params


def is_valid_url(url):
    """Check if URL is valid"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False


def generate_random_string(length=10):
    """Generate random string for testing"""
    import string
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


def detect_technology(response):
    """Detect technology stack from response"""
    if not response:
        return {}

    headers = dict(response.headers)
    server = headers.get("Server", "").lower()
    x_powered_by = headers.get("X-Powered-By", "").lower()

    tech = {}

    # Detect server
    if "nginx" in server:
        tech["server"] = "nginx"
    elif "apache" in server:
        tech["server"] = "Apache"
    elif "iis" in server:
        tech["server"] = "IIS"

    # Detect framework
    if "express" in x_powered_by:
        tech["framework"] = "Express"
    elif "asp.net" in x_powered_by:
        tech["framework"] = "ASP.NET"
    elif "php" in x_powered_by:
        tech["framework"] = "PHP"

    return tech


def download_seclists(output_dir="wordlists", logger=None):
    """Download SecLists repository for wordlists"""
    import subprocess
    import os

    if logger is None:
        logger = Logger()

    wordlist_dir = Path(output_dir)
    wordlist_dir.mkdir(exist_ok=True)

    seclists_path = wordlist_dir / "SecLists"

    if seclists_path.exists():
        logger.info(f"SecLists already exists at: {seclists_path}")
        return str(seclists_path)

    logger.info("Downloading SecLists from GitHub...")

    try:
        # Clone SecLists repository
        subprocess.run(
            ["git", "clone", "https://github.com/danielmiessler/SecLists.git", str(seclists_path)],
            check=True,
            capture_output=True
        )

        logger.success(f"SecLists downloaded to: {seclists_path}")
        logger.info("")
        logger.info("Available API wordlists:")
        logger.info(f"  {seclists_path}/Discovery/Web-Content/api.txt")
        logger.info(f"  {seclists_path}/Discovery/Web-Content/api-controller.txt")
        logger.info(f"  {seclists_path}/Discovery/Web-Content/rest-api-endpoints.txt")
        logger.info(f"  {seclists_path}/Discovery/Web-Content/common-api.txt")
        logger.info("")

        return str(seclists_path)

    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to download SecLists: {e}")
        logger.info("Make sure git is installed")
        return None
    except Exception as e:
        logger.error(f"Error: {e}")
        return None
