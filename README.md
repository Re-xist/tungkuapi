# 🔥 TungkuApi

> **Powerful API Penetration Testing CLI Tool** - Comprehensive security scanner with detailed reporting

[![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Author](https://img.shields.io/badge/Author-Re--xist-red.svg)](https://github.com/Re-xist)

**TungkuApi** is a command-line interface tool designed for API penetration testing. It automatically scans APIs for security vulnerabilities and generates comprehensive, professional reports in multiple formats.

## ✨ Features

### 🔍 Vulnerability Scanners

- **SQL Injection Scanner**
  - Error-based SQL Injection detection
  - Blind SQL Injection (time-based)
  - Union-based SQL Injection

- **XSS (Cross-Site Scripting) Scanner**
  - Reflected XSS detection
  - Stored XSS indicators
  - DOM-based XSS patterns

- **SSRF (Server-Side Request Forgery) Scanner**
  - Internal network access detection
  - AWS metadata endpoint testing
  - Local file access via file:// protocol

- **Authentication & Authorization Scanner**
  - Broken authentication detection
  - Session fixation testing
  - JWT security issues
  - IDOR (Insecure Direct Object Reference)
  - Rate limiting verification

- **Security Headers Scanner**
  - Missing security headers detection
  - Information disclosure via headers analysis
  - Best practices recommendations

### 📊 Report Formats

- **HTML Report** - Interactive, professional HTML report with color-coded severity indicators
- **JSON Report** - Machine-readable format for integration with other tools
- **TXT Report** - Human-readable plain text format

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/Re-xist/tungkuapi.git
cd tungkuapi

# Install dependencies
pip install -r requirements.txt

# Make it executable (Linux/Mac)
chmod +x tungkuapi.py
```

### Requirements

- Python 3.7 or higher
- pip

## 🚀 Quick Start

```bash
# Run demo to see sample reports
python3 demo.py

# Full scan on target API
python3 tungkuapi.py -u https://api.example.com

# With verbose output
python3 tungkuapi.py -u https://api.example.com -v

# Generate all report formats
python3 tungkuapi.py -u https://api.example.com -f all
```

## 💡 Usage Examples

### Basic Scan

```bash
# Scan without authentication
python3 tungkuapi.py -u https://api.example.com
```

### Scan with Authentication

```bash
# Using Bearer token
python3 tungkuapi.py -u https://api.example.com -t "Bearer eyJhbGc..."

# Using custom headers
python3 tungkuapi.py -u https://api.example.com \
  -H "Authorization: Bearer TOKEN" \
  -H "X-API-Key: key123"
```

### Specific Scanner

```bash
# SQL Injection only
python3 tungkuapi.py -u https://api.example.com -s sqli

# XSS only
python3 tungkuapi.py -u https://api.example.com -s xss

# Authentication issues only
python3 tungkuapi.py -u https://api.example.com -s auth
```

### Configuration File

```bash
# Create config from template
cp config.example.json myconfig.json

# Run with config
python3 tungkuapi.py -u https://api.example.com -c myconfig.json
```

## 🔧 Command Line Options

```
usage: tungkuapi.py [-h] -u URL [-s {sqli,xss,ssrf,auth,headers,all}]
                    [-t TOKEN] [-H HEADER] [-o OUTPUT]
                    [-f {html,json,txt,all}] [-c CONFIG] [-v]
                    [--no-report]

Arguments:
  -u, --url              Target API URL (required)
  -s, --scan             Scan type: sqli, xss, ssrf, auth, headers, all (default: all)
  -t, --token            Authentication token (e.g., 'Bearer TOKEN')
  -H, --header           Custom headers (format: 'Name: Value')
  -o, --output           Output directory for reports (default: reports)
  -f, --format           Report format: html, json, txt, all (default: html)
  -c, --config           Configuration file (JSON)
  -v, --verbose          Verbose output
  --no-report            Skip report generation
```

## 📋 Scan Types

| Type | Description |
|------|-------------|
| `sqli` | SQL Injection Scanner |
| `xss` | Cross-Site Scripting Scanner |
| `ssrf` | Server-Side Request Forgery Scanner |
| `auth` | Authentication & Authorization Scanner |
| `headers` | Security Headers Scanner |
| `all` | Run all scanners (default) |

## 📝 Report Sample

### Executive Summary

```
================================================================================
                   TUNGKUAPI - API SECURITY ASSESSMENT REPORT
================================================================================

Target URL     : https://api.example.com
Scan Date      : 2026-01-20T14:30:00
Total Issues   : 8

SEVERITY BREAKDOWN
--------------------------------------------------------------------------------
  CRITICAL : 2
  HIGH     : 3
  MEDIUM   : 2
  LOW      : 1
```

### HTML Report Features

- 📊 Visual dashboard with severity breakdown
- 🎨 Color-coded vulnerability cards
- 🔍 Detailed exploitation evidence
- 🛡️ Remediation recommendations
- 📱 Responsive design
- 🖨️ Print-ready format

## 📁 Project Structure

```
tungkuapi/
├── tungkuapi.py          # Main entry point
├── scanners.py           # Vulnerability scanners
├── reporter.py           # Report generators
├── utils.py              # Utility functions
├── demo.py               # Demo script
├── requirements.txt      # Dependencies
├── config.example.json   # Configuration template
├── README.md            # This file
├── PANDUAN.md           # Complete guide (Indonesian)
├── CHEATSHEET.md        # Quick reference
└── reports/             # Generated reports directory
```

## 🛡️ Disclaimer

This tool is created for educational purposes and authorized security testing only. Users are fully responsible for how they use this tool. Only use it on systems you have permission to test.

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

---

**Happy Hunting! 🔥**

> Made with ❤️ by [Re-xist](https://github.com/Re-xist)
