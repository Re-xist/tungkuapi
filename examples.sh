#!/bin/bash
# TungkuApi - Contoh Penggunaan

echo "🔥 TungkuApi - Contoh Penggunaan"
echo "================================"
echo ""

# Contoh 1: Demo
echo "1. Jalankan Demo Report"
echo "   Command: python3 demo.py"
echo ""

# Contoh 2: Basic scan
echo "2. Basic Scan (tanpa auth)"
echo "   Command: python3 tungkuapi.py -u https://api.example.com"
echo ""

# Contoh 3: Scan dengan auth
echo "3. Scan dengan Authentication"
echo "   Command: python3 tungkuapi.py -u https://api.example.com -t 'Bearer TOKEN'"
echo ""

# Contoh 4: Scan specific
echo "4. Scan Spesifik (SQL Injection)"
echo "   Command: python3 tungkuapi.py -u https://api.example.com -s sqli"
echo ""

# Contoh 5: Multiple headers
echo "5. Scan dengan Multiple Headers"
echo "   Command: python3 tungkuapi.py -u https://api.example.com \\"
echo "            -H 'Authorization: Bearer TOKEN' \\"
echo "            -H 'X-API-Key: key123'"
echo ""

# Contoh 6: Config file
echo "6. Scan dengan Config File"
echo "   Command: python3 tungkuapi.py -u https://api.example.com -c config.json"
echo ""

# Contoh 7: All reports
echo "7. Generate Semua Format Report"
echo "   Command: python3 tungkuapi.py -u https://api.example.com -f all"
echo ""

# Contoh 8: CI/CD integration
echo "8. CI/CD Integration (check exit code)"
echo "   Command: python3 tungkuapi.py -u https://api.example.com --no-report"
echo "   Exit code 0 = No critical issues"
echo "   Exit code 1 = Critical/High findings"
echo ""

echo "================================"
echo "Untuk detail lebih lanjut, lihat:"
echo "  - README.md (Quick start)"
echo "  - PANDUAN.md (Panduan lengkap)"
echo "  - CHEATSHEET.md (Quick reference)"
echo ""
echo "Happy Hunting! 🔥"
