"""
TungkuApi - Utility Functions

Author: Re-xist
GitHub: https://github.com/Re-xist
"""

import requests
from urllib.parse import urljoin, urlparse
from datetime import datetime
import json


class Logger:
    """Simple logger for the tool"""

    def __init__(self, verbose=False):
        self.verbose = verbose

    def info(self, message):
        """Print info message"""
        print(message)

    def error(self, message):
        """Print error message"""
        print(f"[ERROR] {message}")

    def debug(self, message):
        """Print debug message if verbose"""
        if self.verbose:
            print(f"[DEBUG] {message}")

    def success(self, message):
        """Print success message"""
        print(f"[+] {message}")

    def warning(self, message):
        """Print warning message"""
        print(f"[!] {message}")


class APIClient:
    """HTTP Client for API testing"""

    def __init__(self, base_url, logger=None, timeout=10):
        self.base_url = base_url.rstrip("/")
        self.logger = logger or Logger()
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "API-Pentest-Tool/1.0"
        })

    def set_headers(self, headers):
        """Set custom headers"""
        self.session.headers.update(headers)

    def set_auth(self, token):
        """Set authentication token"""
        self.session.headers["Authorization"] = token

    def request(self, method, endpoint, **kwargs):
        """Make HTTP request"""
        url = urljoin(self.base_url + "/", endpoint.lstrip("/"))
        self.logger.debug(f"{method} {url}")

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


class Vulnerability:
    """Vulnerability finding"""

    SEVERITY_LEVELS = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

    @staticmethod
    def create(name, severity, description, evidence, endpoint, remediation=None):
        """Create a vulnerability finding"""
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
