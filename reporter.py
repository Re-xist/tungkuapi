"""
TungkuApi - Enhanced Report Generator
Generates detailed security reports in HTML, JSON, TXT, and PDF formats

Author: Re-xist
GitHub: https://github.com/Re-xist
Version: 2.0
"""

import json
from datetime import datetime
from pathlib import Path


class ReportGenerator:
    """Generate security assessment reports"""

    def __init__(self, results, logger=None):
        self.results = results
        self.logger = logger

        # Severity colors for HTML
        self.severity_colors = {
            "CRITICAL": "#d32f2f",
            "HIGH": "#f57c00",
            "MEDIUM": "#fbc02d",
            "LOW": "#388e3c",
            "INFO": "#1976d2"
        }

        self.severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

    def generate_html(self, filename):
        """Generate HTML report"""
        html_content = self._get_html_template()

        # Populate template
        html_content = html_content.replace("{{TARGET_URL}}", self.results.get("target", "Unknown"))
        html_content = html_content.replace("{{SCAN_DATE}}", self.results.get("scan_date", "Unknown"))
        html_content = html_content.replace("{{TOTAL_VULNS}}", str(self.results.get("summary", {}).get("total", 0)))
        html_content = html_content.replace("{{CRITICAL_COUNT}}", str(self.results.get("summary", {}).get("critical", 0)))
        html_content = html_content.replace("{{HIGH_COUNT}}", str(self.results.get("summary", {}).get("high", 0)))
        html_content = html_content.replace("{{MEDIUM_COUNT}}", str(self.results.get("summary", {}).get("medium", 0)))
        html_content = html_content.replace("{{LOW_COUNT}}", str(self.results.get("summary", {}).get("low", 0)))
        html_content = html_content.replace("{{INFO_COUNT}}", str(self.results.get("summary", {}).get("info", 0)))

        # Add discovered endpoints info
        discovered_count = len(self.results.get("discovered_endpoints", []))
        html_content = html_content.replace("{{DISCOVERED_ENDPOINTS}}", str(discovered_count))

        # Add WAF info
        waf_info = self.results.get("waf_detected", False)
        waf_text = f"Yes - {self.results.get('waf_info', {}).get('name', 'Unknown')}" if waf_info else "No"
        html_content = html_content.replace("{{WAF_DETECTED}}", waf_text)

        # Add vulnerabilities
        vulns_html = ""
        sorted_vulns = sorted(
            self.results.get("vulnerabilities", []),
            key=lambda x: self.severity_order.index(x.get("severity", "INFO"))
        )

        for vuln in sorted_vulns:
            vulns_html += self._create_vuln_html(vuln)

        html_content = html_content.replace("{{VULNERABILITIES}}", vulns_html)

        # Write to file
        with open(filename, "w", encoding="utf-8") as f:
            f.write(html_content)

    def generate_json(self, filename):
        """Generate JSON report"""
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)

    def generate_text(self, filename):
        """Generate text report"""
        lines = []

        lines.append("=" * 80)
        lines.append("TUNGKUAPI v2.0 - API SECURITY ASSESSMENT REPORT".center(80))
        lines.append("=" * 80)
        lines.append("")

        # Executive Summary
        lines.append("LAPORAN EKSEKUTIF")
        lines.append("-" * 80)
        lines.append(f"Target URL           : {self.results.get('target', 'Unknown')}")
        lines.append(f"Tanggal Scan         : {self.results.get('scan_date', 'Unknown')}")
        lines.append(f"Total Issue          : {self.results.get('summary', {}).get('total', 0)}")
        
        # WAF info
        waf_detected = self.results.get("waf_detected", False)
        if waf_detected:
            waf_name = self.results.get("waf_info", {}).get("name", "Unknown")
            lines.append(f"WAF Terdeteksi       : Yes ({waf_name})")
        else:
            lines.append("WAF Terdeteksi       : No")
        
        # Discovered endpoints
        discovered_count = len(self.results.get("discovered_endpoints", []))
        lines.append(f"Endpoint Ditemukan   : {discovered_count}")
        lines.append("")

        lines.append("RINGKASAN KERENTANAN")
        lines.append("-" * 80)
        summary = self.results.get("summary", {})
        lines.append(f"  CRITICAL : {summary.get('critical', 0)}")
        lines.append(f"  HIGH     : {summary.get('high', 0)}")
        lines.append(f"  MEDIUM   : {summary.get('medium', 0)}")
        lines.append(f"  LOW      : {summary.get('low', 0)}")
        lines.append(f"  INFO     : {summary.get('info', 0)}")
        lines.append("")

        # Discovered endpoints list
        if discovered_count > 0:
            lines.append("ENDPOINT YANG DITEMUKAN")
            lines.append("-" * 80)
            for endpoint in self.results.get("discovered_endpoints", [])[:20]:  # Limit to 20
                lines.append(f"  [{endpoint.get('status', 'N/A')}] {endpoint.get('method', 'GET')} {endpoint.get('path', '')}")
            lines.append("")

        # Detailed Findings
        lines.append("DETAIL TEMUAN KERENTANAN")
        lines.append("=" * 80)
        lines.append("")

        sorted_vulns = sorted(
            self.results.get("vulnerabilities", []),
            key=lambda x: self.severity_order.index(x.get("severity", "INFO"))
        )

        for i, vuln in enumerate(sorted_vulns, 1):
            lines.append(f"#{i} - {vuln.get('name', 'Unknown').upper()}")
            lines.append("-" * 80)
            lines.append(f"Severity    : {vuln.get('severity', 'INFO')}")
            lines.append(f"Endpoint    : {vuln.get('endpoint', '')}")
            lines.append(f"Timestamp   : {vuln.get('timestamp', '')}")
            lines.append("")
            lines.append("Deskripsi:")
            lines.append(f"  {vuln.get('description', '')}")
            lines.append("")
            lines.append("Bukti:")
            for line in vuln.get('evidence', '').split('\n'):
                lines.append(f"  {line}")
            lines.append("")
            if 'remediation' in vuln:
                lines.append("Rekomendasi Perbaikan:")
                lines.append(f"  {vuln['remediation']}")
            lines.append("")
            lines.append("")

        # Footer
        lines.append("=" * 80)
        lines.append("Dibuat oleh TungkuApi v2.0".center(80))
        lines.append("Advanced API Penetration Testing Tool".center(80))
        lines.append("Author: Re-xist | https://github.com/Re-xist".center(80))
        lines.append("=" * 80)

        with open(filename, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

    def generate_pdf(self, filename):
        """Generate PDF report"""
        try:
            from weasyprint import HTML
            
            # Generate HTML first
            html_file = filename.replace('.pdf', '_temp.html')
            self.generate_html(html_file)
            
            # Convert to PDF
            HTML(filename=html_file).write_pdf(filename)
            
            # Remove temp HTML file
            import os
            os.remove(html_file)
            
            if self.logger:
                self.logger.success(f"PDF generated: {filename}")
        except ImportError:
            if self.logger:
                self.logger.error("weasyprint not installed. Install with: pip install weasyprint")
        except Exception as e:
            if self.logger:
                self.logger.error(f"Failed to generate PDF: {e}")

    def _get_html_template(self):
        """Get enhanced HTML template"""
        return """<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TungkuApi v2.0 - Security Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .header {
            text-align: center;
            border-bottom: 3px solid #2196F3;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        .header h1 {
            color: #2196F3;
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        .header p {
            color: #666;
            font-size: 1.1em;
        }
        .version {
            display: inline-block;
            background: #2196F3;
            color: white;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.9em;
            margin-top: 10px;
        }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }
        .summary-card {
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            color: white;
        }
        .summary-card h3 {
            font-size: 2.5em;
            margin-bottom: 5px;
        }
        .summary-card p {
            font-size: 0.9em;
            opacity: 0.9;
        }
        .critical { background: #d32f2f; }
        .high { background: #f57c00; }
        .medium { background: #fbc02d; color: white; }
        .low { background: #388e3c; }
        .info { background: #1976d2; }
        .target-info {
            background: #f9f9f9;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 30px;
        }
        .target-info h2 {
            color: #2196F3;
            margin-bottom: 15px;
        }
        .target-info p {
            margin: 5px 0;
        }
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }
        .info-item {
            background: white;
            padding: 10px 15px;
            border-radius: 5px;
            border-left: 3px solid #2196F3;
        }
        .info-item strong {
            display: block;
            color: #666;
            font-size: 0.85em;
            margin-bottom: 5px;
        }
        .findings {
            margin-top: 30px;
        }
        .findings h2 {
            color: #2196F3;
            border-bottom: 2px solid #2196F3;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }
        .vuln-card {
            border: 1px solid #ddd;
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
        }
        .vuln-header {
            padding: 15px 20px;
            color: white;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .vuln-header h3 {
            margin: 0;
            font-size: 1.2em;
        }
        .vuln-body {
            padding: 20px;
        }
        .vuln-meta {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 15px;
            padding: 15px;
            background: #f9f9f9;
            border-radius: 5px;
        }
        .vuln-meta-item strong {
            color: #666;
            font-size: 0.85em;
            margin-bottom: 5px;
        }
        .vuln-section {
            margin-bottom: 15px;
        }
        .vuln-section h4 {
            color: #333;
            margin-bottom: 8px;
            font-size: 1em;
        }
        .vuln-section p, .vuln-section pre {
            margin: 0;
            padding: 10px;
            background: #f5f5f5;
            border-left: 3px solid #2196F3;
            border-radius: 3px;
            white-space: pre-wrap;
            word-wrap: break-word;
        }
        .remediation {
            background: #e8f5e9;
            border-left-color: #4caf50;
        }
        .footer {
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            color: #666;
        }
        .severity-badge {
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.9em;
        }
        @media print {
            body { background: white; padding: 0; }
            .container { box-shadow: none; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔥 TungkuApi v2.0</h1>
            <p>Advanced API Penetration Testing Tool</p>
            <span class="version">Version 2.0</span>
        </div>

        <div class="target-info">
            <h2>Informasi Target</h2>
            <p><strong>URL:</strong> {{TARGET_URL}}</p>
            <p><strong>Tanggal Scan:</strong> {{SCAN_DATE}}</p>
            <p><strong>Total Kerentanan:</strong> {{TOTAL_VULNS}}</p>
            
            <div class="info-grid">
                <div class="info-item">
                    <strong>Endpoint Ditemukan</strong>
                    {{DISCOVERED_ENDPOINTS}}
                </div>
                <div class="info-item">
                    <strong>WAF Terdeteksi</strong>
                    {{WAF_DETECTED}}
                </div>
                <div class="info-item">
                    <strong>Scanner Used</strong>
                    All v2.0 Scanners
                </div>
            </div>
        </div>

        <div class="summary">
            <div class="summary-card critical">
                <h3>{{CRITICAL_COUNT}}</h3>
                <p>CRITICAL</p>
            </div>
            <div class="summary-card high">
                <h3>{{HIGH_COUNT}}</h3>
                <p>HIGH</p>
            </div>
            <div class="summary-card medium">
                <h3>{{MEDIUM_COUNT}}</h3>
                <p>MEDIUM</p>
            </div>
            <div class="summary-card low">
                <h3>{{LOW_COUNT}}</h3>
                <p>LOW</p>
            </div>
            <div class="summary-card info">
                <h3>{{INFO_COUNT}}</h3>
                <p>INFO</p>
            </div>
        </div>

        <div class="findings">
            <h2>🔍 Detail Temuan Kerentanan</h2>
            {{VULNERABILITIES}}
        </div>

        <div class="footer">
            <p>Dibuat oleh <strong>TungkuApi v2.0</strong></p>
            <p>Advanced API Penetration Testing Tool untuk Security Assessment</p>
            <p>Author: <strong>Re-xist</strong> | GitHub: <a href="https://github.com/Re-xist">@Re-xist</a></p>
            <p>Generated on {{SCAN_DATE}}</p>
        </div>
    </div>
</body>
</html>"""

    def _create_vuln_html(self, vuln):
        """Create HTML for a single vulnerability"""
        color = self.severity_colors.get(vuln.get("severity", "INFO"), "#666")

        remediation_html = ""
        if "remediation" in vuln:
            remediation_html = f"""
            <div class="vuln-section remediation">
                <h4>🛡️ Rekomendasi Perbaikan</h4>
                <p>{self._escape_html(vuln.get('remediation', ''))}</p>
            </div>"""

        # Build meta info with enhanced fields
        meta_html = ""
        if vuln.get('full_url'):
            meta_html += f"""
                    <div class="vuln-meta-item">
                        <strong>Full URL</strong>
                        <span style="word-break: break-all;">{self._escape_html(vuln.get('full_url', ''))}</span>
                    </div>"""
        if vuln.get('parameter'):
            meta_html += f"""
                    <div class="vuln-meta-item">
                        <strong>Vulnerable Parameter</strong>
                        <span>{self._escape_html(vuln.get('parameter', ''))}</span>
                    </div>"""
        if vuln.get('request_method'):
            meta_html += f"""
                    <div class="vuln-meta-item">
                        <strong>Method</strong>
                        <span>{vuln.get('request_method', 'GET')}</span>
                    </div>"""
        if vuln.get('payload'):
            meta_html += f"""
                    <div class="vuln-meta-item">
                        <strong>Payload</strong>
                        <span style="word-break: break-all; font-family: monospace; font-size: 0.9em;">{self._escape_html(vuln.get('payload', ''))}</span>
                    </div>"""

        return f"""
        <div class="vuln-card">
            <div class="vuln-header" style="background: {color}">
                <h3>{self._escape_html(vuln.get('name', 'Unknown'))}</h3>
                <span class="severity-badge" style="background: rgba(255,255,255,0.3);">
                    {vuln.get('severity', 'INFO')}
                </span>
            </div>
            <div class="vuln-body">
                <div class="vuln-meta">
                    <div class="vuln-meta-item">
                        <strong>Endpoint Path</strong>
                        <span>{self._escape_html(vuln.get('endpoint', ''))}</span>
                    </div>
                    <div class="vuln-meta-item">
                        <strong>Timestamp</strong>
                        <span>{vuln.get('timestamp', '')}</span>
                    </div>
{meta_html}
                </div>

                <div class="vuln-section">
                    <h4>📝 Deskripsi</h4>
                    <p>{self._escape_html(vuln.get('description', ''))}</p>
                </div>

                <div class="vuln-section">
                    <h4>🔎 Bukti</h4>
                    <pre>{self._escape_html(vuln.get('evidence', ''))}</pre>
                </div>
                {remediation_html}
            </div>
        </div>"""

    def _escape_html(self, text):
        """Escape HTML special characters"""
        if not text:
            return ""
        return (str(text)
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
                .replace("'", "&#39;"))
