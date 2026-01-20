# 🎯 TungkuApi - Cheatsheet

## Command Dasar

```bash
# Scan lengkap
python3 tungkuapi.py -u https://api.target.com

# Dengan verbose
python3 tungkuapi.py -u https://api.target.com -v

# Dengan auth token
python3 tungkuapi.py -u https://api.target.com -t "Bearer TOKEN"

# Generate semua report
python3 tungkuapi.py -u https://api.target.com -f all
```

## Scan Spesifik

| Command | Deskripsi |
|---------|-----------|
| `-s sqli` | SQL Injection only |
| `-s xss` | XSS only |
| `-s ssrf` | SSRF only |
| `-s auth` | Authentication only |
| `-s headers` | Security Headers only |
| `-s all` | Semua scanner (default) |

## Examples

```bash
# SQL Injection scan
python3 tungkuapi.py -u https://api.target.com -s sqli -v

# Bug bounty style
python3 tungkuapi.py -u https://api.target.com -v -f all

# With custom headers
python3 tungkuapi.py -u https://api.target.com \
  -H "Authorization: Bearer TOKEN" \
  -H "X-API-Key: key123"

# Using config file
python3 tungkuapi.py -u https://api.target.com -c config.json

# Custom output directory
python3 tungkuapi.py -u https://api.target.com -o /tmp/reports
```

## Report Formats

| Format | Command | Output |
|--------|---------|--------|
| HTML | `-f html` | reports/report_*.html |
| JSON | `-f json` | reports/report_*.json |
| TXT | `-f txt` | reports/report_*.txt |
| All | `-f all` | Semua format |

## Severity Prioritas

1. **CRITICAL** 🔴 - Segera perbaiki
2. **HIGH** 🟠 - Minggu ini
3. **MEDIUM** 🟡 - Bulan ini
4. **LOW** 🟢 - Saat available
5. **INFO** 🔵 - Informasi

## Exit Codes

| Code | Arti |
|------|------|
| 0 | No critical/high findings |
| 1 | Critical or HIGH findings found |
| 130 | Interrupted by user (Ctrl+C) |

## Quick Reference

```bash
# Help
python3 tungkuapi.py --help

# Demo
python3 demo.py

# View report
xdg-open reports/report_*.html  # Linux
open reports/report_*.html      # macOS
```

## Tips

- ✅ Selalu test di staging dulu
- ✅ Validasi manual semua findings
- ✅ Gunakan config file untuk complex setup
- ✅ Scan per bagian jika ada rate limit
- ⚠️ Dapatkan permission sebelum scan production
