# 🔥 TungkuApi v2.0

> **Advanced API Penetration Testing CLI Tool** - Comprehensive security scanner with detailed reporting

[![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-2.0-orange.svg)](https://github.com/Re-xist/tungkuapi)
[![Author](https://img.shields.io/badge/Author-Re--xist-red.svg)](https://github.com/Re-xist)

**TungkuApi v2.0** is an advanced command-line interface tool for API penetration testing. It automatically scans APIs for security vulnerabilities and generates comprehensive, professional reports in multiple formats.

## 🎉 What's New in v2.0

### New Scanners
- **XXE (XML External Entity) Scanner** - Detect XXE injection vulnerabilities
- **Command Injection Scanner** - Find OS command execution flaws
- **Directory Traversal Scanner** - Detect path traversal vulnerabilities
- **Mass Assignment Scanner** - Identify object property injection
- **Parameter Pollution Scanner** - Find HTTP parameter pollution issues
- **Template Injection Scanner** - Detect SSTI (Server-Side Template Injection)
- **GraphQL Scanner** - Test GraphQL-specific vulnerabilities
- **File Upload Scanner** - Check for malicious file upload vulnerabilities
- **CORS Scanner** - Detect CORS misconfigurations

### New Features
- **API Discovery** - Automatically discover API endpoints
- **WAF Detection** - Detect and handle Web Application Firewalls
- **Multi-threading** - Faster parallel scanning
- **Proxy Support** - Integrate with Burp Suite, Zap, etc.
- **API Fuzzing** - Advanced fuzzing capabilities
- **OpenAPI/Swagger Import** - Test from API specifications
- **Enhanced JWT Testing** - More comprehensive JWT security checks
- **Save/Load Results** - Save and compare scan results
- **PDF Export** - Generate professional PDF reports
- **Better Logging** - File logging support

## ✨ Features

### 🔍 Vulnerability Scanners (14 Total)

#### Injection Scanners
- **SQL Injection Scanner** - Error-based, blind, union-based SQLi
- **XSS Scanner** - Reflected, stored, DOM-based XSS
- **XXE Scanner** - XML External Entity injection
- **Command Injection Scanner** - OS command execution
- **Template Injection Scanner** - SSTI detection (Jinja2, Twig, Freemarker, etc.)
- **Directory Traversal Scanner** - Path traversal detection

#### API-Specific Scanners
- **SSRF Scanner** - Server-Side Request Forgery
- **GraphQL Scanner** - GraphQL introspection & query depth
- **Mass Assignment Scanner** - Object property injection
- **Parameter Pollution Scanner** - HTTP parameter pollution
- **File Upload Scanner** - Malicious file detection
- **CORS Scanner** - CORS misconfiguration

#### Authentication & Security
- **Authentication Scanner** - JWT analysis, rate limiting, auth bypass
- **Security Headers Scanner** - Missing security headers detection

### 🚀 Advanced Features

- **API Discovery** - Automatic endpoint enumeration
- **WAF Detection** - Cloudflare, AWS WAF, Akamai, etc.
- **Multi-threading** - Configurable parallel scanning (default: 5 threads)
- **Proxy Support** - HTTP/HTTPS proxy for Burp/Zap integration
- **API Fuzzing** - Smart payload generation
- **OpenAPI Import** - Test from Swagger/OpenAPI specs
- **Save/Load/Diff** - Save results and compare scans

### 📊 Report Formats

- **HTML Report** - Interactive, professional with severity colors
- **JSON Report** - Machine-readable for CI/CD integration
- **TXT Report** - Human-readable plain text
- **PDF Report** - Professional PDF format (requires weasyprint)

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/Re-xist/tungkuapi.git
cd tungkuapi

# Install dependencies
pip install -r requirements.txt

# (Optional) For PDF reports
pip install weasyprint

# Make it executable (Linux/Mac)
chmod +x tungkuapi.py
```

### Requirements

- Python 3.7 or higher
- pip
- Optional: weasyprint (for PDF reports)

## 🚀 Quick Start

```bash
# Full scan with all features
python3 tungkuapi.py -u https://api.example.com

# With verbose output
python3 tungkuapi.py -u https://api.example.com -v

# Generate all report formats
python3 tungkuapi.py -u https://api.example.com -f all

# Multi-threaded scan (10 threads)
python3 tungkuapi.py -u https://api.example.com --threads 10
```

## 💡 Usage Examples

### Basic Scan

```bash
# Full scan on target API
python3 tungkuapi.py -u https://api.example.com

# Specific scanners only
python3 tungkuapi.py -u https://api.example.com -s sqli,xss,xxe
```

### With Authentication

```bash
# Using Bearer token
python3 tungkuapi.py -u https://api.example.com -t "Bearer eyJhbGc..."

# Using custom headers
python3 tungkuapi.py -u https://api.example.com \
  -H "Authorization: Bearer TOKEN" \
  -H "X-API-Key: key123"
```

### Advanced Features

```bash
# With proxy (Burp Suite)
python3 tungkuapi.py -u https://api.example.com --proxy http://127.0.0.1:8080

# Import OpenAPI spec
python3 tungkuapi.py -u https://api.example.com --openapi swagger.json

# Enable fuzzing
python3 tungkuapi.py -u https://api.example.com --fuzz

# Save and load results
python3 tungkuapi.py -u https://api.example.com --save scan1.json
python3 tungkuapi.py --load scan1.json --diff scan2.json

# Multi-threaded with delay
python3 tungkuapi.py -u https://api.example.com --threads 10 --delay 0.5
```

### API Discovery

```bash
# Run only API discovery
python3 tungkuapi.py -u https://api.example.com -s discovery

# Run fuzzing on discovered endpoints
python3 tungkuapi.py -u https://api.example.com -s fuzz
```

### Using SecLists Wordlists

**Download SecLists:**
```bash
# Download SecLists from GitHub
python3 tungkuapi.py --download-seclists
```

**Use SecLists API Discovery:**
```bash
# API endpoints discovery
python3 tungkuapi.py -u https://api.example.com \
  -w wordlists/SecLists/Discovery/Web-Content/api.txt

# REST API endpoints
python3 tungkuapi.py -u https://api.example.com \
  -w wordlists/SecLists/Discovery/Web-Content/rest-api-endpoints.txt

# API controller discovery
python3 tungkuapi.py -u https://api.example.com \
  -w wordlists/SecLists/Discovery/Web-Content/api-controller.txt
```

**Use SecLists for Fuzzing:**
```bash
# Payment API fuzzing with payment payloads
python3 tungkuapi.py -u https://api.example.com \
  -w wordlists/SecLists/Fuzzing/api-payment-fuzz.txt \
  --fuzz

# General API fuzzing
python3 tungkuapi.py -u https://api.example.com \
  -w wordlists/SecLists/Fuzzing/api-fuzz.txt \
  --fuzz
```

**Test with Credit Card Payloads (Authorized Testing Only):**
```bash
# Payment API security testing with CC payloads
python3 tungkuapi.py -u https://api.example.com/api/payment \
  -w wordlists/SecLists/Fuzzing/api-payment-fuzz.txt \
  -s sqli,xss

# E-commerce API testing
python3 tungkuapi.py -u https://shop.example.com/api/checkout \
  -w wordlists/SecLists/Fuzzing/E-commerce/e-commerce-payloads.txt
```

**Available SecLists Categories:**
- `Discovery/Web-Content/` - API endpoint discovery
- `Fuzzing/` - API fuzzing payloads
- `Fuzzing/api-payment-fuzz.txt` - Payment API fuzzing
- `Fuzzing/e-commerce-payloads.txt` - E-commerce payloads
- `Discovery/Web-Content/common-api.txt` - Common API paths

## 🔧 Command Line Options

```
usage: tungkuapi.py [-h] -u URL [-s SCAN_TYPES] [--fuzz] [-t TOKEN]
                    [-H HEADER] [--proxy PROXY] [--timeout TIMEOUT]
                    [--threads THREADS] [--delay DELAY] [-c CONFIG]
                    [-o OUTPUT] [-f {html,json,txt,pdf,all}]
                    [-w WORDLIST] [--download-seclists]
                    [--save FILE] [--load FILE] [--diff FILE]
                    [-v] [--no-report]

Target Options:
  -u, --url URL             Target API URL
  --openapi FILE            Import OpenAPI/Swagger spec

Scan Options:
  -s, --scan SCAN_TYPES     Scan types (comma-separated):
                           sqli, xss, ssrf, auth, headers, xxe, cmdi,
                           dirtrav, massassign, parampoll, template,
                           graphql, fileupload, cors, discovery, fuzz
  --fuzz                    Enable API fuzzing
  -w, --wordlist WORDLIST   Custom wordlist file for API discovery

SecLists Integration:
  --download-seclists       Download SecLists wordlists from GitHub

Authentication & Headers:
  -t, --token TOKEN         Authentication token
  -H, --header HEADER       Custom headers (format: 'Name: Value')

Network Options:
  --proxy PROXY             Proxy URL (e.g., http://127.0.0.1:8080)
  --timeout SECONDS         Request timeout (default: 10)
  --threads NUM             Number of threads (default: 5)
  --delay SECONDS           Delay between requests (default: 0)

Config & Output:
  -c, --config FILE         Configuration file (JSON)
  -o, --output DIR          Output directory (default: reports)
  -f, --format FORMAT       Report format: html, json, txt, pdf, all
  --save FILE               Save scan results to file
  --load FILE               Load scan results from file
  --diff FILE               Compare with previous scan results

Behavior:
  -v, --verbose             Verbose output
  --no-report               Skip report generation
```

## 📋 Scan Types

| Type | Description |
|------|-------------|
| `sqli` | SQL Injection Scanner |
| `xss` | Cross-Site Scripting Scanner |
| `ssrf` | Server-Side Request Forgery Scanner |
| `xxe` | XML External Entity Scanner |
| `cmdi` | Command Injection Scanner |
| `dirtrav` | Directory Traversal Scanner |
| `massassign` | Mass Assignment Scanner |
| `parampoll` | Parameter Pollution Scanner |
| `template` | Template Injection Scanner (SSTI) |
| `graphql` | GraphQL Security Scanner |
| `fileupload` | File Upload Scanner |
| `cors` | CORS Misconfiguration Scanner |
| `auth` | Authentication & Authorization Scanner |
| `headers` | Security Headers Scanner |
| `discovery` | API Discovery Only |
| `fuzz` | API Fuzzing Only |
| `all` | Run all scanners (default) |

## 📁 Project Structure

```
tungkuapi/
├── tungkuapi.py          # Main entry point (v2.0)
├── scanners.py           # All vulnerability scanners
├── reporter.py           # Report generators (HTML, JSON, TXT, PDF)
├── utils.py              # Utility functions, API discovery, WAF detection, Fuzzer
├── demo.py               # Demo script
├── requirements.txt      # Dependencies
├── config.example.json   # Configuration template
├── README.md            # This file
├── PANDUAN.md           # Complete guide (Indonesian)
├── CHEATSHEET.md        # Quick reference
└── reports/             # Generated reports directory
```

## 🎯 Workflow

```
1. WAF Detection
   ↓
2. API Discovery
   ↓
3. Multi-threaded Scanning (All scanners in parallel)
   ↓
4. Fuzzing (if enabled)
   ↓
5. Report Generation
```

## 🛡️ Disclaimer

This tool is created for educational purposes and authorized security testing only. Users are fully responsible for how they use this tool. Only use it on systems you have permission to test.

**IMPORTANT:**
- Only test APIs you own or have explicit permission to test
- Respect rate limits and avoid causing service disruption
- Follow responsible disclosure practices for vulnerabilities found
- This tool may trigger security alerts and WAF rules

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👨‍💻 Author

**Re-xist**

- GitHub: [@Re-xist](https://github.com/Re-xist)

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## ⭐ Show Your Support

If you find this tool useful, please consider giving it a star!

## 📚 Documentation

- **[PANDUAN.md](PANDUAN.md)** - Complete guide in Indonesian
- **[CHEATSHEET.md](CHEATSHEET.md)** - Quick reference commands

## 🔗 Related Tools

- [OWASP ZAP](https://www.zaproxy.org/) - Web application security scanner
- [Burp Suite](https://portswigger.net/burp) - Web security testing tool
- [SQLMap](http://sqlmap.org/) - Automated SQL injection tool

---

**Happy Hunting! 🔥**

> Made with ❤️ by [Re-xist](https://github.com/Re-xist)
> Version 2.0 - Advanced API Penetration Testing Tool
