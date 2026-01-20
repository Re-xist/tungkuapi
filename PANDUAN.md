# 📘 Panduan Penggunaan TungkuApi

## Daftar Isi
1. [Instalasi](#instalasi)
2. [Quick Start](#quick-start)
3. [Contoh Penggunaan](#contoh-penggunaan)
4. [Penjelasan Scanner](#penjelasan-scanner)
5. [Memahami Report](#memahami-report)
6. [Tips & Best Practices](#tips--best-practices)

---

## 📦 Instalasi

### Step 1: Download/Clone

```bash
cd /path/to/your/folder
# Jika dari git
git clone <repo-url> tungkuapi
cd tungkuapi
```

### Step 2: Install Dependencies

```bash
# Install Python dependencies
pip3 install -r requirements.txt

# Atau install satu per satu
pip3 install requests urllib3
```

### Step 3: Verify Installation

```bash
# Test help command
python3 tungkuapi.py --help

# Run demo
python3 demo.py
```

---

## 🚀 Quick Start

### Scan Basic (Tanpa Authentication)

```bash
# Scan API yang tidak butuh login
python3 tungkuapi.py -u https://api.example.com

# Dengan verbose output
python3 tungkuapi.py -u https://api.example.com -v

# Scan specific endpoint
python3 tungkuapi.py -u https://api.test.com/v1/api
```

### Scan dengan Authentication

```bash
# 1. Bearer Token
python3 tungkuapi.py -u https://api.example.com -t "Bearer eyJhbGciOiJU..."

# 2. API Key di header
python3 tungkuapi.py -u https://api.example.com -H "X-API-Key: abc123"

# 3. Basic Auth (perlu encode manual)
python3 tungkuapi.py -u https://api.example.com -H "Authorization: Basic base64(user:pass)"

# 4. Multiple headers
python3 tungkuapi.py -u https://api.example.com \
  -H "Authorization: Bearer TOKEN" \
  -H "X-CSRF-Token: xyz" \
  -H "Content-Type: application/json"
```

### Menggunakan Configuration File

```bash
# 1. Copy template
cp config.example.json my-scan.json

# 2. Edit my-scan.json
{
  "headers": {
    "Authorization": "Bearer YOUR_TOKEN",
    "X-API-Key": "your-key"
  }
}

# 3. Jalankan dengan config
python3 tungkuapi.py -u https://api.example.com -c my-scan.json
```

---

## 💡 Contoh Penggunaan

### Scenario 1: Testing API Bug Bounty

```bash
# Full scan pada target bug bounty
python3 tungkuapi.py -u https://api.target.com -v -f all

# Output akan ada di:
# reports/report_20260120_143011.html
# reports/report_20260120_143011.json
# reports/report_20260120_143011.txt
```

### Scenario 2: Testing Development API

```bash
# API di localhost dengan auth
python3 tungkuapi.py -u http://localhost:8000/api \
  -t "Bearer dev-token-123" \
  -o /tmp/reports \
  -f html
```

### Scenario 3: Specific Vulnerability Check

```bash
# Cuma cek SQL Injection
python3 tungkuapi.py -u https://api.example.com -s sqli

# Cuma cek XSS
python3 tungkuapi.py -u https://api.example.com -s xss

# Cuma cek Authentication issues
python3 tungkuapi.py -u https://api.example.com -s auth

# Cuma cek Security Headers
python3 tungkuapi.py -u https://api.example.com -s headers
```

### Scenario 4: Continuous Integration (CI)

```bash
#!/bin/bash
# ci-scan.sh

# Run scan dan cek exit code
python3 tungkuapi.py -u $API_URL \
  -t "$API_TOKEN" \
  --no-report

if [ $? -eq 1 ]; then
  echo "❌ Critical/High vulnerabilities found!"
  exit 1
else
  echo "✅ No critical issues found"
  exit 0
fi
```

### Scenario 5: Multiple Targets

```bash
#!/bin/bash
# scan-all.sh

TARGETS=(
  "https://api1.example.com"
  "https://api2.example.com"
  "https://api3.example.com"
)

for target in "${TARGETS[@]}"; do
  echo "Scanning $target..."
  python3 tungkuapi.py -u "$target" -f json
done
```

---

## 🔍 Penjelasan Scanner

### 1. SQL Injection Scanner

Mendeteksi kerentanan SQL Injection dengan:

**Payloads yang di-test:**
```sql
' OR '1'='1
' OR '1'='1'--
' UNION SELECT NULL--
'; DROP TABLE users--
admin'--
```

**Jenis yang dideteksi:**
- Error-based SQLi (dari error message database)
- Blind SQLi time-based (menggunakan SLEEP/delay)
- Union-based SQLi

**Contoh output:**
```
[CRITICAL] SQL Injection
Endpoint: /api/users?id=1' OR '1'='1
Evidence: You have an error in your SQL syntax
```

---

### 2. XSS Scanner

Mendeteksi Cross-Site Scripting dengan:

**Payloads yang di-test:**
```html
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
```

**Parameter yang di-test:**
- Query parameters (?q=, ?search=, ?find=)
- Form fields
- URL parameters

**Contoh output:**
```
[HIGH] Cross-Site Scripting (XSS)
Endpoint: /api/search?q=<script>alert('XSS')</script>
Evidence: Payload reflected unescaped in response
```

---

### 3. SSRF Scanner

Mendeteksi Server-Side Request Forgery dengan:

**URLs yang di-test:**
```
http://127.0.0.1         (localhost)
http://169.254.169.254  (AWS metadata)
http://192.168.1.1       (internal network)
file:///etc/passwd      (local file)
```

**Parameters yang di-test:**
- `url`, `target`, `dest`, `redirect`
- `uri`, `path`, `fetch`, `link`

**Contoh output:**
```
[CRITICAL] Server-Side Request Forgery (SSRF)
Endpoint: /api/proxy?url=http://169.254.169.254
Evidence: Response contains AWS metadata
```

---

### 4. Authentication Scanner

Mendeteksi berbagai issue authentication/authorization:

**a) Broken Authentication**
- Test login endpoint dengan credential berbagai
- Cek information disclosure di response

**b) Session Fixation**
- Cek cookie flags (Secure, HttpOnly, SameSite)

**c) JWT Issues**
- Cek penggunaan algorithm "none"
- Cek weak signing algorithms

**d) IDOR (Insecure Direct Object Reference)**
- Test akses resource dengan ID berbeda
- Cek bisa access data user lain

**e) Rate Limiting**
- Test brute force protection
- Kirim 20+ request gagal berurutan

**Contoh output:**
```
[HIGH] Insecure Direct Object Reference (IDOR)
Endpoint: /api/user/999
Evidence: Can access other users' data by changing ID

[MEDIUM] Missing Rate Limiting
Endpoint: /api/login
Evidence: Made 20 failed requests without throttling
```

---

### 5. Security Headers Scanner

Menganalisis security headers:

**Headers yang di-check:**
| Header | Severity | Description |
|--------|----------|-------------|
| X-Frame-Options | MEDIUM | Clickjacking protection |
| X-Content-Type-Options | LOW | MIME sniffing protection |
| Strict-Transport-Security | HIGH | HSTS enforcement |
| Content-Security-Policy | HIGH | XSS protection |
| X-XSS-Protection | LOW | XSS filter |
| Referrer-Policy | LOW | Referrer control |
| Permissions-Policy | MEDIUM | Feature policy |

**Contoh output:**
```
[HIGH] Missing Security Header: Content-Security-Policy
Endpoint: /
Evidence: Header 'Content-Security-Policy' not present in response
Remediation: Implement Content-Security-Policy header
```

---

## 📊 Memahami Report

### HTML Report

**Fitur:**
- 🎨 Color-coded severity (CRITICAL=merah, HIGH=orange, etc)
- 📊 Summary dashboard
- 🔍 Detail bukti eksploitasi
- 🛡️ Rekomendasi perbaikan
- 📱 Responsive design
- 🖨️ Print-ready

**Cara buka:**
```bash
# Di Linux
xdg-open reports/report_20260120_143011.html

# Di macOS
open reports/report_20260120_143011.html

# Atau langsung di browser
firefox reports/report_20260120_143011.html
chromium reports/report_20260120_143011.html
```

### JSON Report

Format untuk integrasi dengan tools lain:

```json
{
  "target": "https://api.example.com",
  "scan_date": "2026-01-20T14:30:00",
  "vulnerabilities": [
    {
      "name": "SQL Injection",
      "severity": "CRITICAL",
      "endpoint": "/api/users",
      "evidence": "...",
      "remediation": "..."
    }
  ],
  "summary": {
    "critical": 2,
    "high": 3,
    "medium": 2,
    "low": 1,
    "total": 8
  }
}
```

**Contoh parsing:**
```bash
# Count critical vulnerabilities
jq '.summary.critical' reports/report_*.json

# Get all critical findings
jq '.vulnerabilities[] | select(.severity == "CRITICAL")' reports/report_*.json
```

### TXT Report

Format plain text yang mudah dibaca:

```
================================================================================
                   TUNGKUAPI - API SECURITY ASSESSMENT REPORT
================================================================================

LAPORAN EKSEKUTIF
--------------------------------------------------------------------------------
Target URL     : https://api.example.com
Tanggal Scan   : 2026-01-20T14:30:00
Total Issue    : 8

RINGKASAN KERENTANAN BERDASARKAN SEVERITY
--------------------------------------------------------------------------------
  CRITICAL : 2
  HIGH     : 3
  MEDIUM   : 2
  LOW      : 1

DETAIL TEMUAN KERENTANAN
...
```

---

## 🎯 Tips & Best Practices

### 1. Sebelum Scan

```bash
✅ DO:
- Test di staging/development environment dulu
- Dapatkan permission tertulis sebelum scan production
- Backup data penting
- Setup proper authentication

❌ DON'T:
- Scan tanpa permission
- Scan saat peak traffic
- Gunakan data production untuk testing
```

### 2. Konfigurasi yang Baik

```json
{
  "headers": {
    "Authorization": "Bearer TOKEN",
    "X-API-Key": "key-123",
    "User-Agent": "TungkuApi/1.0"
  },
  "scan_options": {
    "timeout": 30,
    "max_depth": 3
  },
  "exclude_paths": [
    "/api/health",
    "/api/metrics",
    "/api/monitoring"
  ]
}
```

### 3. Interpretasi Hasil

**Prioritas Perbaikan:**
1. **CRITICAL** - Segera perbaiki (hari ini)
2. **HIGH** - Perbaiki minggu ini
3. **MEDIUM** - Perbaiki bulan ini
4. **LOW** - Perbaiki saat available
5. **INFO** - Informasi saja, opsional

**Validasi Manual:**
Selalu validasi findings dengan manual testing:
```bash
# Test SQL Injection manual
curl "https://api.example.com/users?id=1' OR '1'='1"

# Test XSS manual
curl "https://api.example.com/search?q=<script>alert(1)</script>"

# Test SSRF manual
curl "https://api.example.com/proxy?url=http://127.0.0.1"
```

### 4. Rate Limiting & Throttling

Jika API punya rate limit:

```bash
# Scan per bagian
python3 tungkuapi.py -u https://api.example.com -s sqli
sleep 60  # Tunggu 1 menit
python3 tungkuapi.py -u https://api.example.com -s xss
sleep 60
python3 tungkuapi.py -u https://api.example.com -s ssrf
```

### 5. False Positives

Beberapa findings mungkin false positive:

- **Error messages** yang mengandung SQL tapi bukan error asli
- **XSS payloads** yang ter-encode dengan benar
- **SSRF tests** yang diblock oleh firewall

Selalu lakukan verifikasi manual!

### 6. Integration dengan Tools Lain

**Dengan Jenkins/GitLab CI:**
```bash
# .gitlab-ci.yml
security-scan:
  script:
    - pip3 install -r requirements.txt
    - python3 tungkuapi.py -u $API_URL -t $API_TOKEN -f json
    - jq -e '.summary.critical == 0' reports/report_*.json
```

**D dengan Slack/Email:**
```bash
# Send report ke Slack
curl -X POST $SLACK_WEBHOOK \
  -H 'Content-Type: application/json' \
  -d "{\"text\": \"Scan Complete: $(jq '.summary' reports/report_*.json)\"}"
```

---

## 🆘 Troubleshooting

### Error: Connection refused

```bash
# Cek koneksi
curl -I https://api.example.com

# Cek firewall
ping api.example.com

# Try dari network berbeda
```

### Error: SSL Certificate

```bash
# Bypass SSL check (HATI-HATI - hanya untuk testing)
export PYTHONHTTPSVERIFY=0
python3 tungkuapi.py -u https://api.example.com
```

### Timeout errors

```bash
# Tambah timeout di config
echo '{"scan_options": {"timeout": 60}}' > config.json
python3 tungkuapi.py -u https://api.example.com -c config.json
```

---

## 📚 Referensi

- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger API Testing](https://portswigger.net/web-security/api-testing)

---

**Happy Hunting! 🔥**
