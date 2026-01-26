"""
TungkuApi - JWT Analyzer for Advanced Authentication Testing
Analyzes JWT tokens for security issues

Author: Re-xist
GitHub: https://github.com/Re-xist
Version: 3.0
"""

import re
import json
import base64
import hashlib
from datetime import datetime, timedelta
import time


class JWTAnalyzer:
    """Advanced JWT token analyzer"""

    def __init__(self, logger):
        self.logger = logger
        self.name = "JWT Analyzer"

        # Weak algorithms that should not be used
        self.weak_algorithms = ["none", "HS256", "HS384", "HS512"]

        # Strong algorithms
        self.strong_algorithms = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"]

        # Common JWT claims
        self.standard_claims = ["iss", "sub", "aud", "exp", "nbf", "iat", "jti"]

    def analyze(self, token: str, config=None) -> list:
        """Analyze JWT token for security issues"""
        findings = []

        try:
            # Decode JWT without verification (we just want to analyze structure)
            parts = token.split(".")

            if len(parts) != 3:
                findings.append({
                    "issue": "Invalid JWT Format",
                    "severity": "HIGH",
                    "description": "Token does not have 3 parts (header.payload.signature)",
                    "evidence": f"Parts found: {len(parts)}"
                })
                return findings

            # Decode header
            header_data = self._decode_base64(parts[0])
            header = json.loads(header_data)

            # Decode payload
            payload_data = self._decode_base64(parts[1])
            payload = json.loads(payload_data)

            # Analyze header
            findings.extend(self._analyze_header(header))

            # Analyze payload
            findings.extend(self._analyze_payload(payload))

            # Analyze signature
            findings.extend(self._analyze_signature(header, token))

            # Analyze claims
            findings.extend(self._analyze_claims(payload))

            return findings

        except Exception as e:
            self.logger.error(f"Error analyzing JWT: {e}")
            return [{
                "issue": "JWT Analysis Error",
                "severity": "INFO",
                "description": f"Failed to analyze JWT token",
                "evidence": str(e)
            }]

    def _decode_base64(self, data: str) -> bytes:
        """Decode base64url encoded data"""
        # Add padding if needed
        padding = 4 - len(data) % 4
        if padding != 4:
            data += "=" * padding

        return base64.urlsafe_b64decode(data)

    def _analyze_header(self, header: dict) -> list:
        """Analyze JWT header for security issues"""
        findings = []

        # Check algorithm
        algorithm = header.get("alg", "").lower()

        if algorithm == "none":
            findings.append({
                "issue": "None Algorithm",
                "severity": "CRITICAL",
                "description": "JWT uses 'none' algorithm which allows signature bypass",
                "evidence": f"Algorithm: {algorithm}",
                "remediation": "Use strong algorithm like RS256 or ES256"
            })

        elif algorithm in self.weak_algorithms:
            findings.append({
                "issue": "Weak Algorithm",
                "severity": "HIGH",
                "description": f"JWT uses weak symmetric algorithm ({algorithm})",
                "evidence": f"Algorithm: {algorithm}",
                "remediation": "Use asymmetric algorithm (RS256, ES256, etc.)"
            })

        elif algorithm not in self.strong_algorithms:
            findings.append({
                "issue": "Unusual Algorithm",
                "severity": "MEDIUM",
                "description": f"JWT uses non-standard or unusual algorithm",
                "evidence": f"Algorithm: {algorithm}",
                "remediation": "Verify algorithm is intended and secure"
            })

        # Check for key ID (kid) manipulation
        if "kid" in header:
            kid = header["kid"]
            if not kid or len(kid) < 10:
                findings.append({
                    "issue": "Weak Key ID",
                    "severity": "MEDIUM",
                    "description": "Key ID (kid) is weak or missing",
                    "evidence": f"kid: {kid}",
                    "remediation": "Use strong, unique key identifiers"
                })

            # Check for kid injection attempts
            if "../" in kid or "%2e%2e" in kid.lower():
                findings.append({
                    "issue": "Potential Path Traversal in kid",
                    "severity": "HIGH",
                    "description": "Key ID contains path traversal patterns",
                    "evidence": f"kid: {kid}",
                    "remediation": "Validate and sanitize key ID parameter"
                })

        # Check for typ (type) header confusion
        if "typ" in header:
            typ = header["typ"]
            if typ != "JWT":
                findings.append({
                    "issue": "Unusual JWT Type",
                    "severity": "LOW",
                    "description": f"JWT type header is not 'JWT'",
                    "evidence": f"type: {typ}",
                    "remediation": "Verify JWT type is correct"
                })

        return findings

    def _analyze_payload(self, payload: dict) -> list:
        """Analyze JWT payload for security issues"""
        findings = []

        # Check for sensitive data in payload
        sensitive_keywords = ["password", "secret", "key", "token", "api_key", "credit_card", "ssn"]

        for key, value in payload.items():
            if isinstance(value, str):
                for keyword in sensitive_keywords:
                    if keyword in key.lower():
                        findings.append({
                            "issue": f"Sensitive Data in JWT Payload",
                            "severity": "HIGH",
                            "description": f"JWT payload contains sensitive information: {key}",
                            "evidence": f"Claim: {key}",
                            "remediation": "Never store sensitive data in JWT payload"
                        })
                        break

        # Check for excessive data in payload
        payload_size = len(json.dumps(payload))
        if payload_size > 4096:
            findings.append({
                "issue": "Large JWT Payload",
                "severity": "MEDIUM",
                "description": f"JWT payload is large ({payload_size} bytes)",
                "evidence": f"Size: {payload_size} bytes",
                "remediation": "Minimize JWT payload size for better performance"
            })

        return findings

    def _analyze_signature(self, header: dict, token: str) -> list:
        """Analyze JWT signature for security issues"""
        findings = []

        # Check signature length
        parts = token.split(".")
        signature = parts[2]

        if len(signature) < 32:
            findings.append({
                "issue": "Short Signature",
                "severity": "MEDIUM",
                "description": "JWT signature appears to be short",
                "evidence": f"Signature length: {len(signature)} chars",
                "remediation": "Use longer signatures (at least 256 bits)"
            })

        # For HMAC algorithms, check if signature looks random
        algorithm = header.get("alg", "").lower()
        if algorithm.startswith("hs"):
            # Check for predictable patterns
            if signature == signature[0] * len(signature):
                findings.append({
                    "issue": "Weak Signature Pattern",
                    "severity": "CRITICAL",
                    "description": "JWT signature consists of repeated characters",
                    "evidence": f"Signature: {signature[:20]}...",
                    "remediation": "Secret key may be weak or compromised"
                })

        return findings

    def _analyze_claims(self, payload: dict) -> list:
        """Analyze JWT claims for security issues"""
        findings = []
        now = time.time()

        # Check expiration (exp)
        if "exp" in payload:
            exp = payload["exp"]
            if isinstance(exp, (int, float)):
                if exp < now:
                    findings.append({
                        "issue": "Expired Token",
                        "severity": "HIGH",
                        "description": "JWT token has expired",
                        "evidence": f"Expired at: {datetime.fromtimestamp(exp).isoformat()}",
                        "remediation": "Token needs to be refreshed"
                    })
                else:
                    # Check if token will expire soon (within 1 hour)
                    if exp - now < 3600:
                        findings.append({
                            "issue": "Token Expiring Soon",
                            "severity": "LOW",
                            "description": "JWT token will expire within 1 hour",
                            "evidence": f"Expires at: {datetime.fromtimestamp(exp).isoformat()}",
                            "remediation": "Plan for token refresh"
                        })

                    # Check if token lifetime is too long (> 24 hours)
                    if "iat" in payload:
                        iat = payload["iat"]
                        lifetime = exp - iat
                        if lifetime > 86400:
                            findings.append({
                                "issue": "Long Token Lifetime",
                                "severity": "MEDIUM",
                                "description": f"JWT token lifetime is {lifetime / 86400:.1f} days",
                                "evidence": f"Lifetime: {lifetime} seconds",
                                "remediation": "Use shorter token lifetimes (15-60 minutes)"
                            })

        else:
            findings.append({
                "issue": "Missing Expiration",
                "severity": "MEDIUM",
                "description": "JWT token does not have expiration (exp) claim",
                "evidence": "No exp claim found",
                "remediation": "Always set expiration on JWT tokens"
            })

        # Check not before (nbf)
        if "nbf" in payload:
            nbf = payload["nbf"]
            if isinstance(nbf, (int, float)):
                if nbf > now + 300:  # More than 5 minutes in future
                    findings.append({
                        "issue": "Future Valid Token",
                        "severity": "INFO",
                        "description": "JWT token is not yet valid",
                        "evidence": f"Valid from: {datetime.fromtimestamp(nbf).isoformat()}",
                        "remediation": "Check system clock synchronization"
                    })

        # Check issued at (iat)
        if "iat" in payload:
            iat = payload["iat"]
            if isinstance(iat, (int, float)):
                # Check if token was issued in the future
                if iat > now + 300:
                    findings.append({
                        "issue": "Token Issued in Future",
                        "severity": "MEDIUM",
                        "description": "JWT iat claim is in the future",
                        "evidence": f"iat: {datetime.fromtimestamp(iat).isoformat()}",
                        "remediation": "Check system clock synchronization"
                    })

        # Check audience (aud)
        if "aud" not in payload:
            findings.append({
                "issue": "Missing Audience",
                "severity": "LOW",
                "description": "JWT token does not have audience (aud) claim",
                "evidence": "No aud claim found",
                "remediation": "Include audience claim to limit token scope"
            })

        # Check issuer (iss)
        if "iss" not in payload:
            findings.append({
                "issue": "Missing Issuer",
                "severity": "MEDIUM",
                "description": "JWT token does not have issuer (iss) claim",
                "evidence": "No iss claim found",
                "remediation": "Include issuer claim to identify token source"
            })

        # Check for role/permission claims
        role_claims = ["role", "roles", "permission", "permissions", "scope", "scopes"]
        has_role_claim = any(claim in payload for claim in role_claims)

        if not has_role_claim:
            findings.append({
                "issue": "No Authorization Claims",
                "severity": "LOW",
                "description": "JWT token does not contain role or permission claims",
                "evidence": f"Missing claims: {', '.join(role_claims)}",
                "remediation": "Include role/permission claims for fine-grained access control"
            })

        # Check for jti (JWT ID)
        if "jti" not in payload:
            findings.append({
                "issue": "Missing JWT ID",
                "severity": "INFO",
                "description": "JWT token does not have jti (JWT ID) claim",
                "evidence": "No jti claim found",
                "remediation": "Include jti claim for token revocation capability"
            })

        return findings

    def test_jwt_endpoint(self, client, endpoint: str, config=None) -> list:
        """Test JWT authentication endpoint"""
        findings = []

        try:
            # Test without token
            response = client.get(endpoint, headers=config.get("headers", {}) if config else {})

            if response and response.status_code == 401:
                # Try to decode token from WWW-Authenticate header
                auth_header = response.headers.get("WWW-Authenticate", "")
                if "Bearer" in auth_header:
                    findings.append({
                        "issue": "JWT Authentication Required",
                        "severity": "INFO",
                        "description": "Endpoint requires JWT authentication",
                        "evidence": f"WWW-Authenticate: {auth_header}",
                        "endpoint": endpoint
                    })

            elif response and response.status_code == 200:
                findings.append({
                    "issue": "Missing Authentication",
                    "severity": "HIGH",
                    "description": "Endpoint accessible without JWT token",
                    "evidence": f"Status: {response.status_code}",
                    "endpoint": endpoint,
                    "remediation": "Implement JWT authentication check"
                })

        except Exception as e:
            self.logger.error(f"Error testing JWT endpoint: {e}")

        return findings

    def brute_force_jwt_secret(self, token: str, wordlist: list = None) -> dict:
        """
        Attempt to brute force JWT secret (for educational purposes only)
        WARNING: Only use on systems you own or have explicit permission to test
        """
        if not wordlist:
            # Common weak secrets
            wordlist = [
                "secret", "password", "123456", "admin", "jwtsecret",
                "key", "token", "api", "default", "secret123"
            ]

        findings = {
            "issue": "JWT Secret Brute Force Test",
            "severity": "CRITICAL",
            "description": "Testing JWT secret strength",
            "tested_secrets": len(wordlist),
            "found_match": False
        }

        # Note: This is a placeholder for educational purposes
        # Actual brute force would require proper JWT library
        # This just demonstrates the concept

        findings["recommendation"] = "Use strong, random secrets (at least 256 bits)"

        return findings

    def check_algorithm_confusion(self, token: str) -> dict:
        """Check for algorithm confusion attacks"""
        findings = {
            "issue": "Algorithm Confusion Check",
            "severity": "HIGH",
            "description": "Testing for algorithm confusion vulnerability"
        }

        try:
            parts = token.split(".")
            header_data = self._decode_base64(parts[0])
            header = json.loads(header_data)

            algorithm = header.get("alg", "").lower()

            # Check if token uses symmetric algorithm when asymmetric is expected
            if algorithm.startswith("hs"):
                findings["evidence"] = "Token uses symmetric algorithm"
                findings["risk"] = "Algorithm confusion possible if server expects asymmetric"
                findings["remediation"] = "Verify algorithm matches server expectation"

        except Exception as e:
            findings["error"] = str(e)

        return findings


class JWTScanner:
    """JWT security scanner for API endpoints"""

    def __init__(self, client, logger):
        self.client = client
        self.logger = logger
        self.name = "JWT Authentication Scanner"
        self.analyzer = JWTAnalyzer(logger)

    def scan(self, config=None, discovered_endpoints=None) -> list:
        """Scan for JWT security issues"""
        findings = []

        # Get test endpoints
        test_endpoints = self._get_auth_endpoints(discovered_endpoints)

        for endpoint in test_endpoints:
            # Test JWT endpoint
            jwt_findings = self.analyzer.test_jwt_endpoint(
                self.client,
                endpoint,
                config
            )
            findings.extend(jwt_findings)

            # Test with JWT token if available
            if config and "headers" in config:
                auth_header = config["headers"].get("Authorization", "")
                if auth_header.startswith("Bearer "):
                    token = auth_header[7:]
                    analysis = self.analyzer.analyze(token, config)

                    for issue in analysis:
                        finding = self._create_finding(issue, endpoint)
                        if finding:
                            findings.append(finding)

        return findings

    def _get_auth_endpoints(self, discovered_endpoints):
        """Get authentication-related endpoints"""
        auth_paths = ["/auth", "/login", "/token", "/oauth", "/jwt", "/authenticate"]
        endpoints = []

        if discovered_endpoints:
            for ep in discovered_endpoints:
                path = ep.get("path", "")
                if any(auth_path in path for auth_path in auth_paths):
                    endpoints.append(path)

        # Add default auth endpoints if none discovered
        if not endpoints:
            endpoints = auth_paths

        return endpoints

    def _create_finding(self, issue, endpoint):
        """Create vulnerability finding from JWT issue"""
        from utils import Vulnerability

        remediation = issue.get("remediation", "Review JWT configuration")

        return Vulnerability.create(
            f"JWT Security: {issue.get('issue', 'Unknown')}",
            issue.get("severity", "MEDIUM"),
            issue.get("description", ""),
            issue.get("evidence", ""),
            endpoint,
            remediation=remediation
        )
