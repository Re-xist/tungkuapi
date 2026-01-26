"""
TungkuApi - Rate Limit Detection Scanner
Detects rate limiting and identifies bypass opportunities

Author: Re-xist
GitHub: https://github.com/Re-xist
Version: 3.0
"""

import time
import random
from utils import Vulnerability


class RateLimitDetector:
    """Rate limiting detector and tester"""

    def __init__(self, client, logger):
        self.client = client
        self.logger = logger
        self.name = "Rate Limit Detector"

    def detect_rate_limit(self, endpoint: str, config=None) -> dict:
        """Detect rate limiting on endpoint"""
        results = {
            "endpoint": endpoint,
            "has_rate_limit": False,
            "limit": None,
            "window": None,
            "thresholds": []
        }

        try:
            # Test with increasing request counts
            test_counts = [1, 5, 10, 20, 50, 100]

            for count in test_counts:
                status_codes = []

                for i in range(count):
                    response = self.client.get(
                        endpoint,
                        headers=config.get("headers", {}) if config else {}
                    )

                    if response:
                        status_codes.append(response.status_code)

                        # Check for rate limit indicators
                        if response.status_code == 429:
                            results["has_rate_limit"] = True
                            results["threshold"] = count

                            # Check rate limit headers
                            limit_header = response.headers.get("X-RateLimit-Limit")
                            remaining_header = response.headers.get("X-RateLimit-Remaining")
                            reset_header = response.headers.get("X-RateLimit-Reset")

                            if limit_header:
                                results["limit"] = limit_header
                            if remaining_header:
                                results["remaining"] = remaining_header
                            if reset_header:
                                results["reset"] = reset_header

                            self.logger.info(f"Rate limit detected at {count} requests")

                            # Extract retry-after
                            retry_after = response.headers.get("Retry-After")
                            if retry_after:
                                results["retry_after"] = retry_after

                            return results

                # Small delay between test batches
                time.sleep(0.5)

        except Exception as e:
            self.logger.error(f"Error detecting rate limit: {e}")

        return results

    def test_bypass_techniques(self, endpoint: str, config=None) -> list:
        """Test various rate limit bypass techniques"""
        findings = []

        # Get baseline rate limit
        baseline = self.detect_rate_limit(endpoint, config)

        if not baseline["has_rate_limit"]:
            findings.append({
                "technique": "No Rate Limit",
                "severity": "HIGH",
                "description": "No rate limiting detected",
                "endpoint": endpoint,
                "remediation": "Implement rate limiting on all authenticated endpoints"
            })
            return findings

        # Test 1: Header manipulation
        findings.extend(self._test_header_bypass(endpoint, config, baseline))

        # Test 2: IP rotation simulation (different X-Forwarded-For)
        findings.extend(self._test_ip_rotation(endpoint, config, baseline))

        # Test 3: User-Agent rotation
        findings.extend(self._test_user_agent_rotation(endpoint, config, baseline))

        return findings

    def _test_header_bypass(self, endpoint: str, config, baseline) -> list:
        """Test if rate limit can be bypassed with header manipulation"""
        findings = []

        # Test with different headers that might bypass rate limiting
        bypass_headers = [
            {"X-Real-IP": "127.0.0.1"},
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Original-For": "127.0.0.1"},
            {"CF-Connecting-IP": "127.0.0.1"},  # Cloudflare
            {"X-Forwarded-Host": "localhost"}
        ]

        for headers in bypass_headers:
            try:
                # Send request beyond rate limit
                for i in range(int(baseline.get("threshold", 20)) + 10):
                    response = self.client.get(
                        endpoint,
                        headers={**(config.get("headers", {}) if config else {}), **headers}
                    )

                    if response and response.status_code != 429:
                        findings.append({
                            "technique": "Header Bypass",
                            "severity": "HIGH",
                            "description": f"Rate limit bypassed using header: {list(headers.keys())[0]}",
                            "evidence": f"Status: {response.status_code} (expected 429)",
                            "endpoint": endpoint,
                            "bypass_header": list(headers.keys())[0],
                            "remediation": "Use consistent rate limiting based on user identity, not IP"
                        })
                        return findings

            except Exception as e:
                self.logger.debug(f"Error testing header bypass: {e}")

        return findings

    def _test_ip_rotation(self, endpoint: str, config, baseline) -> list:
        """Test if rate limit can be bypassed with IP rotation"""
        findings = []

        # Simulate IP rotation with X-Forwarded-For
        fake_ips = [
            "192.168.1.1",
            "10.0.0.1",
            "172.16.0.1",
            "203.0.113.1"
        ]

        for ip in fake_ips:
            try:
                # Send requests with different IPs
                for i in range(int(baseline.get("threshold", 20)) + 5):
                    response = self.client.get(
                        endpoint,
                        headers={
                            **(config.get("headers", {}) if config else {}),
                            "X-Forwarded-For": ip
                        }
                    )

                    if response and response.status_code != 429:
                        findings.append({
                            "technique": "IP Rotation Bypass",
                            "severity": "HIGH",
                            "description": "Rate limit bypassed using IP rotation",
                            "evidence": f"Used IP: {ip}, Status: {response.status_code} (expected 429)",
                            "endpoint": endpoint,
                            "remediation": "Implement rate limiting based on user ID, not IP address"
                        })
                        return findings

            except Exception as e:
                self.logger.debug(f"Error testing IP rotation: {e}")

        return findings

    def _test_user_agent_rotation(self, endpoint: str, config, baseline) -> list:
        """Test if rate limit can be bypassed with User-Agent rotation"""
        findings = []

        # Different User-Agents
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "curl/7.68.0",
            "PostmanRuntime/7.26.8"
        ]

        for ua in user_agents:
            try:
                # Send requests with different User-Agents
                for i in range(int(baseline.get("threshold", 20)) + 5):
                    response = self.client.get(
                        endpoint,
                        headers={
                            **(config.get("headers", {}) if config else {}),
                            "User-Agent": ua
                        }
                    )

                    if response and response.status_code != 429:
                        findings.append({
                            "technique": "User-Agent Rotation Bypass",
                            "severity": "MEDIUM",
                            "description": "Rate limit bypassed using User-Agent rotation",
                            "evidence": f"Status: {response.status_code} (expected 429)",
                            "endpoint": endpoint,
                            "remediation": "Implement rate limiting based on authentication, not User-Agent"
                        })
                        return findings

            except Exception as e:
                self.logger.debug(f"Error testing User-Agent rotation: {e}")

        return findings

    def analyze_rate_limit_quality(self, endpoint: str, config=None) -> dict:
        """Analyze the quality of rate limiting implementation"""
        results = {
            "endpoint": endpoint,
            "has_rate_limit": False,
            "score": 0,
            "findings": []
        }

        detection_result = self.detect_rate_limit(endpoint, config)

        if not detection_result["has_rate_limit"]:
            results["score"] = 0
            results["findings"].append("No rate limiting implemented")
            return results

        results["has_rate_limit"] = True

        # Check for proper headers
        try:
            response = self.client.get(
                endpoint,
                headers=config.get("headers", {}) if config else {}
            )

            if response:
                headers = response.headers

                # Check for rate limit headers
                score = 0
                max_score = 100

                if "X-RateLimit-Limit" in headers:
                    score += 20
                    results["findings"].append("✓ Has rate limit header")
                else:
                    results["findings"].append("✗ Missing X-RateLimit-Limit header")

                if "X-RateLimit-Remaining" in headers:
                    score += 20
                    results["findings"].append("✓ Has remaining requests header")
                else:
                    results["findings"].append("✗ Missing X-RateLimit-Remaining header")

                if "X-RateLimit-Reset" in headers:
                    score += 20
                    results["findings"].append("✓ Has reset time header")
                else:
                    results["findings"].append("✗ Missing X-RateLimit-Reset header")

                if "Retry-After" in headers or response.status_code == 429:
                    score += 20
                    results["findings"].append("✓ Sends Retry-After header")
                else:
                    results["findings"].append("✗ Missing Retry-After header")

                # Check for status code 429 when rate limited
                if response.status_code == 429:
                    score += 20
                    results["findings"].append("✓ Returns 429 Too Many Requests")
                else:
                    results["findings"].append("? Verify 429 status code is used")

                results["score"] = score

        except Exception as e:
            self.logger.error(f"Error analyzing rate limit quality: {e}")

        return results


class RateLimitScanner:
    """Rate limiting security scanner"""

    def __init__(self, client, logger):
        self.client = client
        self.logger = logger
        self.name = "Rate Limit Scanner"
        self.detector = RateLimitDetector(client, logger)

    def scan(self, config=None, discovered_endpoints=None) -> list:
        """Scan for rate limiting issues"""
        findings = []

        # Get endpoints to test
        test_endpoints = self._get_test_endpoints(discovered_endpoints)

        for endpoint in test_endpoints:
            self.logger.info(f"Testing rate limit on: {endpoint}")

            # Test bypass techniques
            bypass_results = self.detector.test_bypass_techniques(endpoint, config)

            if bypass_results:
                for result in bypass_results:
                    finding = Vulnerability.create(
                        f"Rate Limit: {result['technique']}",
                        result["severity"],
                        result["description"],
                        result.get("evidence", ""),
                        endpoint,
                        remediation=result.get("remediation", "")
                    )
                    findings.append(finding)

            # Analyze rate limit quality
            quality = self.detector.analyze_rate_limit_quality(endpoint, config)

            if quality["score"] < 60:
                finding = Vulnerability.create(
                    "Weak Rate Limiting Implementation",
                    "MEDIUM" if quality["score"] > 0 else "HIGH",
                    f"Rate limiting score: {quality['score']}/100",
                    "\n".join(quality["findings"]),
                    endpoint,
                    remediation="Implement proper rate limiting with 429 responses and rate limit headers"
                )
                findings.append(finding)

        return findings

    def _get_test_endpoints(self, discovered_endpoints):
        """Get endpoints to test for rate limiting"""
        endpoints = []

        if discovered_endpoints:
            # Test API endpoints (not static files)
            for ep in discovered_endpoints:
                path = ep.get("path", "")
                # Focus on authenticated endpoints
                if any(keyword in path for keyword in ["/api/", "/auth", "/user", "/admin"]):
                    endpoints.append(path)

        # Default endpoints if none discovered
        if not endpoints:
            endpoints = ["/api/users", "/api/login", "/auth/token"]

        return endpoints
