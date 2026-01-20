"""
TungkuApi - Vulnerability Scanners

Author: Re-xist
GitHub: https://github.com/Re-xist
"""

import re
import json
from utils import APIClient, Logger, Vulnerability, analyze_response


class BaseScanner:
    """Base scanner class"""

    def __init__(self, client, logger):
        self.client = client
        self.logger = logger
        self.name = self.__class__.__name__
        self.findings = []

    def scan(self, config=None):
        """Run scan - to be implemented by subclasses"""
        raise NotImplementedError

    def add_finding(self, vuln):
        """Add a vulnerability finding"""
        self.findings.append(vuln)


class SQLScanner(BaseScanner):
    """SQL Injection Scanner"""

    def __init__(self, client, logger):
        super().__init__(client, logger)
        self.name = "SQL Injection Scanner"

        # SQLi payloads
        self.payloads = [
            "' OR '1'='1",
            "' OR '1'='1'--",
            "' OR '1'='1'/*",
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "1' ORDER BY 1--",
            "'; DROP TABLE users--",
            "' OR 1=1#",
            "admin'--",
            "' OR 'x'='x",
            "1' AND 1=1--",
            "1' AND 1=2--"
        ]

        # Error patterns
        self.error_patterns = [
            "You have an error in your SQL syntax",
            "Warning: mysql_fetch_array()",
            "ORA-01756: quoted string not properly terminated",
            "Unclosed quotation mark after the character string",
            "Microsoft OLE DB Provider for ODBC Drivers",
            "PostgreSQL query failed",
            "SQLite3::SQLException"
        ]

    def scan(self, config=None):
        """Scan for SQL Injection vulnerabilities"""
        findings = []

        # Test common endpoints
        test_endpoints = self._get_test_endpoints(config)

        for endpoint in test_endpoints:
            self.logger.debug(f"Testing {endpoint}")

            for payload in self.payloads:
                # Test in query parameter
                response = self.client.get(
                    f"{endpoint}?id={payload}",
                    headers=config.get("headers", {}) if config else {}
                )

                if response:
                    # Check for error-based SQLi
                    for error in self.error_patterns:
                        if error.lower() in response.text.lower():
                            finding = Vulnerability.create(
                                "SQL Injection",
                                "CRITICAL",
                                f"SQL Injection vulnerability detected via error-based injection",
                                f"Payload: {payload}\nError: {error[:100]}",
                                endpoint,
                                remediation="Use parameterized queries/prepared statements. Validate and sanitize all user input."
                            )
                            findings.append(finding)
                            self.logger.success(f"SQLi found at {endpoint}")
                            break

                    # Check for time-based blind SQLi
                    time_payload = "1' AND (SELECT SLEEP(5))--"
                    import time
                    start = time.time()
                    resp = self.client.get(f"{endpoint}?id={time_payload}")
                    elapsed = time.time() - start

                    if elapsed > 4.5:
                        finding = Vulnerability.create(
                            "Blind SQL Injection (Time-Based)",
                            "HIGH",
                            "Time-based blind SQL injection detected",
                            f"Payload: {time_payload}\nResponse time: {elapsed:.2f}s",
                            endpoint,
                            remediation="Use parameterized queries. Implement server-side validation."
                        )
                        findings.append(finding)
                        self.logger.success(f"Blind SQLi found at {endpoint}")

        return findings

    def _get_test_endpoints(self, config):
        """Get endpoints to test"""
        common_paths = [
            "/api/users",
            "/api/user",
            "/api/products",
            "/api/items",
            "/api/search",
            "/api/login",
            "/api/auth",
            "/users",
            "/user",
            "/search",
            "/login"
        ]
        return common_paths


class XSSScanner(BaseScanner):
    """Cross-Site Scripting Scanner"""

    def __init__(self, client, logger):
        super().__init__(client, logger)
        self.name = "XSS Scanner"

        self.payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "'><script>alert(String.fromCharCode(88,83,83))</script>",
            "\"<script>alert('XSS')</script>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "'`\"><script>alert\\\"XSS\\\"</script>",
            "javascript:alert('XSS')",
            "<iframe src=\"javascript:alert('XSS')\">"
        ]

    def scan(self, config=None):
        """Scan for XSS vulnerabilities"""
        findings = []

        test_endpoints = self._get_test_endpoints(config)

        for endpoint in test_endpoints:
            for payload in self.payloads:
                # Test in query parameter
                response = self.client.get(
                    f"{endpoint}?q={payload}&search={payload}",
                    headers=config.get("headers", {}) if config else {}
                )

                if response:
                    # Check if payload is reflected unescaped
                    if payload in response.text:
                        finding = Vulnerability.create(
                            "Cross-Site Scripting (XSS)",
                            "HIGH",
                            f"Reflected XSS vulnerability detected. Payload is reflected unescaped in response.",
                            f"Payload: {payload}\nEndpoint: {endpoint}",
                            endpoint,
                            remediation="Encode all user-supplied data before rendering in HTML. Use Content Security Policy (CSP)."
                        )
                        findings.append(finding)
                        self.logger.success(f"XSS found at {endpoint}")
                        break

                    # Check for partial reflection
                    encoded_payload = payload.replace("<", "%3C").replace(">", "%3E")
                    if encoded_payload in response.text or payload.replace("<", "&lt;").replace(">", "&gt;") in response.text:
                        # This might be safe encoding, but worth noting
                        finding = Vulnerability.create(
                            "Potential XSS - Insufficient Encoding",
                            "LOW",
                            "User input reflected in response with partial encoding",
                            f"Payload: {payload}",
                            endpoint,
                            remediation="Ensure all user input is properly encoded using HTML entity encoding."
                        )
                        findings.append(finding)

        return findings

    def _get_test_endpoints(self, config):
        """Get endpoints to test"""
        return [
            "/api/search",
            "/api/users",
            "/search",
            "/find",
            "/api/query",
            "/api/products"
        ]


class SSRFScanner(BaseScanner):
    """Server-Side Request Forgery Scanner"""

    def __init__(self, client, logger):
        super().__init__(client, logger)
        self.name = "SSRF Scanner"

        self.test_urls = [
            "http://127.0.0.1",
            "http://localhost",
            "http://169.254.169.254",  # AWS metadata
            "http://192.168.1.1",
            "http://10.0.0.1",
            "file:///etc/passwd",
            "http://[::1]",
            "http://2130706433"  # 127.0.0.1 in decimal
        ]

    def scan(self, config=None):
        """Scan for SSRF vulnerabilities"""
        findings = []

        # Test URL parameters
        test_params = ["url", "target", "dest", "redirect", "uri", "path", "fetch", "link"]

        test_endpoints = self._get_test_endpoints(config)

        for endpoint in test_endpoints:
            for param in test_params:
                for test_url in self.test_urls:
                    # Test SSRF via URL parameter
                    response = self.client.get(
                        f"{endpoint}?{param}={test_url}",
                        headers=config.get("headers", {}) if config else {}
                    )

                    if response:
                        # Check for successful internal connection
                        if response.status_code in [200, 301, 302]:
                            # Check response content
                            if any(indicator in response.text.lower() for indicator in
                                   ["aws", "metadata", "localhost", "127.0.0.1", "root:", "bin/bash"]):

                                finding = Vulnerability.create(
                                    "Server-Side Request Forgery (SSRF)",
                                    "CRITICAL",
                                    f"SSRF vulnerability detected. Application can make requests to internal resources.",
                                    f"Parameter: {param}\nTest URL: {test_url}\nStatus: {response.status_code}",
                                    endpoint,
                                    remediation="Validate and whitelist all URLs. Use network segmentation. Disable internal URL access."
                                )
                                findings.append(finding)
                                self.logger.success(f"SSRF found at {endpoint} via {param}")

        return findings

    def _get_test_endpoints(self, config):
        """Get endpoints to test"""
        return [
            "/api/fetch",
            "/api/proxy",
            "/api/redirect",
            "/api/download",
            "/api/webhook",
            "/proxy",
            "/fetch",
            "/redirect"
        ]


class AuthScanner(BaseScanner):
    """Authentication & Authorization Scanner"""

    def __init__(self, client, logger):
        super().__init__(client, logger)
        self.name = "Authentication Scanner"

    def scan(self, config=None):
        """Scan for authentication issues"""
        findings = []

        # Test for broken authentication
        auth_tests = [
            self._test_broken_auth,
            self._test_session_fixation,
            self._test_jwt_issues,
            self._test_idor,
            self._test_rate_limiting
        ]

        for test in auth_tests:
            try:
                test_findings = test(config)
                findings.extend(test_findings)
            except Exception as e:
                self.logger.debug(f"Auth test error: {e}")

        return findings

    def _test_broken_auth(self, config):
        """Test for broken authentication"""
        findings = []

        # Test common paths
        auth_paths = [
            "/api/login",
            "/api/auth/login",
            "/login",
            "/auth",
            "/api/signin",
            "/signin"
        ]

        for path in auth_paths:
            response = self.client.post(
                path,
                json={"username": "test", "password": "test"},
                headers=config.get("headers", {}) if config else {}
            )

            if response and response.status_code == 200:
                # Check if response leaks info
                if "password" in response.text.lower() or "hash" in response.text.lower():
                    finding = Vulnerability.create(
                        "Information Disclosure - Auth Response",
                        "MEDIUM",
                        "Authentication endpoint may leak sensitive information",
                        f"Endpoint: {path}\nResponse contains password/hash references",
                        path,
                        remediation="Do not include sensitive data in auth responses. Return generic error messages."
                    )
                    findings.append(finding)

        return findings

    def _test_session_fixation(self, config):
        """Test for session fixation"""
        findings = []

        response = self.client.get(
            "/api/auth/session",
            headers=config.get("headers", {}) if config else {}
        )

        if response:
            cookies = response.cookies
            if cookies:
                for cookie in cookies:
                    # Check if cookie lacks secure/httponly flags
                    if not cookie.has_nonstandard_attr("Secure") or not cookie.has_nonstandard_attr("HttpOnly"):
                        finding = Vulnerability.create(
                            "Insecure Cookie Configuration",
                            "MEDIUM",
                            f"Session cookie '{cookie.name}' missing Secure or HttpOnly flags",
                            f"Cookie: {cookie.name}\nSecure: {cookie.has_nonstandard_attr('Secure')}\nHttpOnly: {cookie.has_nonstandard_attr('HttpOnly')}",
                            "/api/auth/session",
                            remediation="Set Secure and HttpOnly flags on all session cookies. Use SameSite attribute."
                        )
                        findings.append(finding)

        return findings

    def _test_jwt_issues(self, config):
        """Test for JWT security issues"""
        findings = []

        # Check for JWT in responses
        endpoints = ["/api/user", "/api/me", "/api/profile", "/api/auth/me"]

        for endpoint in endpoints:
            response = self.client.get(
                endpoint,
                headers=config.get("headers", {}) if config else {}
            )

            if response and response.status_code == 200:
                # Look for JWT in response
                jwt_pattern = r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'
                tokens = re.findall(jwt_pattern, response.text)

                for token in tokens:
                    # Check if token is signed with 'none' algorithm
                    try:
                        parts = token.split(".")
                        if len(parts) == 3:
                            header = json.loads(parts[0])
                            if header.get("alg", "").lower() == "none":
                                finding = Vulnerability.create(
                                    "JWT 'None' Algorithm",
                                    "CRITICAL",
                                    "JWT signed with 'none' algorithm - allows signature bypass",
                                    f"Token header: {header}",
                                    endpoint,
                                    remediation="Never use 'none' algorithm. Use strong algorithms like RS256."
                                )
                                findings.append(finding)
                    except:
                        pass

        return findings

    def _test_idor(self, config):
        """Test for Insecure Direct Object Reference"""
        findings = []

        # Test accessing different user IDs
        test_ids = [1, 2, 100, 9999]
        endpoints = ["/api/user/", "/api/users/", "/api/profile/", "/api/account/"]

        for endpoint in endpoints:
            for test_id in test_ids:
                response = self.client.get(
                    f"{endpoint}{test_id}",
                    headers=config.get("headers", {}) if config else {}
                )

                if response and response.status_code == 200:
                    # Check if we can access other users' data
                    if any(keyword in response.text.lower() for keyword in ["email", "password", "ssn", "credit"]):
                        finding = Vulnerability.create(
                            "Insecure Direct Object Reference (IDOR)",
                            "HIGH",
                            f"Can access other users' data by changing ID to {test_id}",
                            f"Endpoint: {endpoint}\nTest ID: {test_id}",
                            f"{endpoint}{test_id}",
                            remediation="Implement proper authorization checks. Use indirect reference maps. Verify ownership on every request."
                        )
                        findings.append(finding)
                        break

        return findings

    def _test_rate_limiting(self, config):
        """Test for rate limiting"""
        findings = []

        login_endpoint = "/api/login"
        failed_requests = 0

        for i in range(20):
            response = self.client.post(
                login_endpoint,
                json={"username": "test", "password": "wrong"},
                headers=config.get("headers", {}) if config else {}
            )

            if response:
                if response.status_code == 401 or response.status_code == 400:
                    failed_requests += 1
                elif response.status_code == 429:
                    # Rate limiting detected - this is good
                    return []

        if failed_requests >= 15:
            finding = Vulnerability.create(
                "Missing Rate Limiting",
                "MEDIUM",
                f"No rate limiting detected on authentication endpoint. Made {failed_requests} failed requests without throttling.",
                f"Endpoint: {login_endpoint}\nFailed attempts: {failed_requests}",
                login_endpoint,
                remediation="Implement rate limiting on authentication endpoints. Use progressive delays and account lockout."
            )
            findings.append(finding)

        return findings


class HeaderScanner(BaseScanner):
    """Security Headers Scanner"""

    def __init__(self, client, logger):
        super().__init__(client, logger)
        self.name = "Security Headers Scanner"

        self.required_headers = {
            "X-Frame-Options": {
                "severity": "MEDIUM",
                "description": "Missing clickjacking protection",
                "remediation": "Add X-Frame-Options: DENY or SAMEORIGIN"
            },
            "X-Content-Type-Options": {
                "severity": "LOW",
                "description": "Missing MIME-type sniffing protection",
                "remediation": "Add X-Content-Type-Options: nosniff"
            },
            "Strict-Transport-Security": {
                "severity": "HIGH",
                "description": "Missing HSTS header",
                "remediation": "Add Strict-Transport-Security: max-age=31536000; includeSubDomains"
            },
            "Content-Security-Policy": {
                "severity": "HIGH",
                "description": "Missing CSP header",
                "remediation": "Implement Content-Security-Policy header"
            },
            "X-XSS-Protection": {
                "severity": "LOW",
                "description": "Missing XSS filter",
                "remediation": "Add X-XSS-Protection: 1; mode=block"
            },
            "Referrer-Policy": {
                "severity": "LOW",
                "description": "Missing referrer policy",
                "remediation": "Add Referrer-Policy: strict-origin-when-cross-origin"
            },
            "Permissions-Policy": {
                "severity": "MEDIUM",
                "description": "Missing permissions policy",
                "remediation": "Add Permissions-Policy header to control browser features"
            }
        }

    def scan(self, config=None):
        """Scan for missing security headers"""
        findings = []

        # Test root endpoint
        response = self.client.get(
            "/",
            headers=config.get("headers", {}) if config else {}
        )

        if response:
            headers = dict(response.headers)

            for header_name, config in self.required_headers.items():
                if header_name not in headers:
                    finding = Vulnerability.create(
                        f"Missing Security Header: {header_name}",
                        config["severity"],
                        config["description"],
                        f"Header '{header_name}' not present in response",
                        "/",
                        remediation=config["remediation"]
                    )
                    findings.append(finding)
                    self.logger.warning(f"Missing header: {header_name}")

            # Check for information disclosure in headers
            info_headers = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]
            for header in info_headers:
                if header in headers:
                    finding = Vulnerability.create(
                        f"Information Disclosure: {header} Header",
                        "LOW",
                        f"Server reveals information via {header} header",
                        f"{header}: {headers[header]}",
                        "/",
                        remediation=f"Remove {header} header. Hide server version information."
                    )
                    findings.append(finding)

        return findings
