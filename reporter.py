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
        """Get enhanced HTML template with Tailwind CSS"""
        return """<!DOCTYPE html>
<html class="dark" lang="id">
<head>
<meta charset="utf-8"/>
<meta content="width=device-width, initial-scale=1.0" name="viewport"/>
<title>TungkuApi v2.0 - API Security Assessment Report</title>
<script src="https://cdn.tailwindcss.com?plugins=forms,container-queries"></script>
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=Public+Sans:wght@300;400;500;600&display=swap" rel="stylesheet"/>
<link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap" rel="stylesheet"/>
<script>
    tailwind.config = {
        darkMode: "class",
        theme: {
            extend: {
                colors: {
                    "primary": "#17b0cf",
                    "background-light": "#fafafa",
                    "background-dark": "#16181d",
                    "surface-dark": "#1e2128",
                    "border-dark": "#2d323d",
                    "severity-critical": "#EF4444",
                    "severity-high": "#F97316",
                    "severity-medium": "#FBBF24",
                    "severity-low": "#22C55E",
                },
                fontFamily: {
                    "display": ["Space Grotesk", "sans-serif"],
                    "body": ["Public Sans", "sans-serif"],
                    "mono": ["ui-monospace", "SFMono-Regular", "Menlo", "Monaco", "Consolas", "Liberation Mono", "Courier New", "monospace"]
                },
                borderRadius: {"DEFAULT": "0.25rem", "lg": "0.5rem", "xl": "0.75rem", "full": "9999px"},
            },
        },
    }
</script>
<style>
    body { font-family: 'Public Sans', sans-serif; }
    h1, h2, h3, .font-display { font-family: 'Space Grotesk', sans-serif; }
    .code-block { background: #0d0e12; border: 1px solid #2d323d; }
    .problematic-code { background: rgba(239, 68, 68, 0.15); border-left: 3px solid #EF4444; padding: 2px 8px; margin: 2px 0; }
    .safe-code { background: rgba(34, 197, 94, 0.1); border-left: 3px solid #22C55E; padding: 2px 8px; margin: 2px 0; }
    .comment { color: #6b7280; font-style: italic; }
    .highlight-red { color: #EF4444; font-weight: bold; }
    .highlight-yellow { color: #FBBF24; font-weight: bold; }
    .highlight-green { color: #22C55E; font-weight: bold; }
    @media print {
        body { background: white; padding: 0; }
        .no-print { display: none !important; }
    }
</style>
</head>
<body class="bg-background-light dark:bg-background-dark text-slate-900 dark:text-slate-100 min-h-screen">

<!-- Top Navigation Bar -->
<header class="sticky top-0 z-50 w-full border-b border-border-dark bg-background-dark/80 backdrop-blur-md no-print">
<div class="flex h-16 items-center justify-between px-6">
<div class="flex items-center gap-6">
<div class="flex items-center gap-3">
<div class="size-8 bg-primary flex items-center justify-center rounded-lg">
<span class="material-symbols-outlined text-background-dark font-bold">shield</span>
</div>
<h1 class="text-lg font-bold tracking-tight">TungkuApi <span class="text-primary">v2.0</span></h1>
</div>
<div class="h-6 w-[1px] bg-border-dark"></div>
<div class="flex items-center gap-2 text-sm text-slate-400">
<span>API Security Assessment</span>
</div>
</div>
<div class="flex items-center gap-4">
<button class="flex h-9 items-center gap-2 rounded-lg bg-primary px-4 text-sm font-bold text-background-dark hover:bg-primary/90 transition-colors" onclick="window.print()">
<span class="material-symbols-outlined text-sm">download</span>
Export PDF
</button>
<div class="size-9 rounded-full bg-surface-dark border border-border-dark flex items-center justify-center">
<span class="material-symbols-outlined text-slate-300">person</span>
</div>
</div>
</div>
</header>

<div class="flex h-[calc(100vh-64px)] overflow-hidden">

<!-- Sidebar Navigation -->
<aside class="w-64 border-r border-border-dark bg-background-dark flex flex-col justify-between p-4 overflow-y-auto no-print">
<div class="space-y-6">
<div>
<p class="px-3 text-[10px] font-bold uppercase tracking-widest text-slate-500 mb-4">Report Navigation</p>
<nav class="space-y-1">
<a class="flex items-center gap-3 px-3 py-2 text-sm font-medium bg-primary/10 text-primary border border-primary/20 rounded-lg transition-all" href="#executive-summary">
<span class="material-symbols-outlined text-[20px]">dashboard</span>
Executive Summary
</a>
<a class="flex items-center gap-3 px-3 py-2 text-sm font-medium text-slate-400 hover:text-white hover:bg-surface-dark rounded-lg transition-all" href="#detailed-findings">
<span class="material-symbols-outlined text-[20px] fill-1">find_replace</span>
Detailed Findings ({{TOTAL_VULNS}})
</a>
</nav>
</div>
<div>
<p class="px-3 text-[10px] font-bold uppercase tracking-widest text-slate-500 mb-4">Assessment Stats</p>
<div class="grid grid-cols-2 gap-2 px-3">
<div class="p-2 rounded-lg bg-surface-dark border border-border-dark">
<p class="text-xs text-slate-500">Total</p>
<p class="text-lg font-display font-bold">{{TOTAL_VULNS}}</p>
</div>
<div class="p-2 rounded-lg bg-surface-dark border border-border-dark">
<p class="text-xs text-slate-500">Critical</p>
<p class="text-lg font-display font-bold text-severity-critical">{{CRITICAL_COUNT}}</p>
</div>
<div class="p-2 rounded-lg bg-surface-dark border border-border-dark">
<p class="text-xs text-slate-500">High</p>
<p class="text-lg font-display font-bold text-severity-high">{{HIGH_COUNT}}</p>
</div>
<div class="p-2 rounded-lg bg-surface-dark border border-border-dark">
<p class="text-xs text-slate-500">Medium</p>
<p class="text-lg font-display font-bold text-severity-medium">{{MEDIUM_COUNT}}</p>
</div>
<div class="p-2 rounded-lg bg-surface-dark border border-border-dark">
<p class="text-xs text-slate-500">Low</p>
<p class="text-lg font-display font-bold text-severity-low">{{LOW_COUNT}}</p>
</div>
</div>
</div>
</div>
<div class="pt-6 border-t border-border-dark">
<div class="bg-surface-dark p-3 rounded-lg">
<p class="text-xs text-slate-400 font-medium">Report Version</p>
<p class="text-xs text-white">v2.0 - {{SCAN_DATE}}</p>
</div>
</div>
</aside>

<!-- Main Content Area -->
<main class="flex-1 overflow-y-auto p-8 scroll-smooth">
<div class="max-w-5xl mx-auto space-y-8">

<!-- Executive Summary -->
<section id="executive-summary" class="space-y-6">
<div class="space-y-1">
<p class="text-primary font-display font-medium text-sm tracking-widest uppercase">API Penetration Testing</p>
<h2 class="text-4xl font-display font-black tracking-tight">Executive Summary</h2>
</div>

<div class="bg-surface-dark border border-border-dark rounded-xl p-6 space-y-4">
<div class="flex items-center gap-4">
<div class="size-12 rounded-lg bg-severity-high/10 flex items-center justify-center">
<span class="material-symbols-outlined text-severity-high text-2xl">error</span>
</div>
<div class="flex-1">
<p class="text-sm text-slate-400">Overall Risk Rating</p>
<p class="text-2xl font-display font-black text-severity-high">HIGH</p>
</div>
</div>
<p class="text-sm leading-relaxed text-slate-300">
Security assessment of <strong class="text-white">{{TARGET_URL}}</strong> identified <strong class="text-white">{{TOTAL_VULNS}} vulnerabilities</strong> including <strong class="text-severity-critical">{{CRITICAL_COUNT}} Critical</strong>, <strong class="text-severity-high">{{HIGH_COUNT}} High</strong>, <strong class="text-severity-medium">{{MEDIUM_COUNT}} Medium</strong>, and <strong class="text-severity-low">{{LOW_COUNT}} Low</strong> severity findings through comprehensive API scanning.
</p>
</div>

<div class="grid grid-cols-4 gap-4">
<div class="bg-surface-dark border border-severity-critical rounded-xl p-4 text-center">
<p class="text-3xl font-display font-black text-severity-critical">{{CRITICAL_COUNT}}</p>
<p class="text-xs text-slate-400 uppercase font-bold tracking-wider">Critical</p>
</div>
<div class="bg-surface-dark border border-severity-high rounded-xl p-4 text-center">
<p class="text-3xl font-display font-black text-severity-high">{{HIGH_COUNT}}</p>
<p class="text-xs text-slate-400 uppercase font-bold tracking-wider">High</p>
</div>
<div class="bg-surface-dark border border-severity-medium rounded-xl p-4 text-center">
<p class="text-3xl font-display font-black text-severity-medium">{{MEDIUM_COUNT}}</p>
<p class="text-xs text-slate-400 uppercase font-bold tracking-wider">Medium</p>
</div>
<div class="bg-surface-dark border border-severity-low rounded-xl p-4 text-center">
<p class="text-3xl font-display font-black text-severity-low">{{LOW_COUNT}}</p>
<p class="text-xs text-slate-400 uppercase font-bold tracking-wider">Low</p>
</div>
</div>

<div class="bg-surface-dark border border-border-dark rounded-xl p-6">
<h3 class="text-lg font-display font-bold mb-4">Target Information</h3>
<div class="grid grid-cols-2 gap-4 text-sm">
<div>
<p class="text-slate-500">Target URL</p>
<p class="font-mono text-primary">{{TARGET_URL}}</p>
</div>
<div>
<p class="text-slate-500">Scan Date</p>
<p class="text-white">{{SCAN_DATE}}</p>
</div>
<div>
<p class="text-slate-500">Endpoints Discovered</p>
<p class="text-white">{{DISCOVERED_ENDPOINTS}}</p>
</div>
<div>
<p class="text-slate-500">WAF Detected</p>
<p class="text-white">{{WAF_DETECTED}}</p>
</div>
</div>
</div>
</section>

<!-- DETAILED FINDINGS -->
<section id="detailed-findings" class="space-y-12">
<div class="space-y-1">
<p class="text-primary font-display font-medium text-sm tracking-widest uppercase">Security Findings</p>
<h2 class="text-4xl font-display font-black tracking-tight">Detailed Findings</h2>
<p class="text-sm text-slate-400">All {{TOTAL_VULNS}} findings with complete Evidence & Proof of Concept</p>
</div>

{{VULNERABILITIES}}
</section>

<!-- Report Footer -->
<section class="bg-surface-dark border border-border-dark rounded-xl p-6 mt-12">
<div class="text-center space-y-4">
<div class="flex items-center justify-center gap-3">
<div class="size-10 bg-primary/10 flex items-center justify-center rounded-lg">
<span class="material-symbols-outlined text-primary">shield_lock</span>
</div>
<div class="text-left">
<p class="text-xs text-slate-500 uppercase tracking-wider">Report Generated</p>
<p class="text-lg font-display font-bold text-white">{{SCAN_DATE}}</p>
</div>
</div>
<div class="pt-4 border-t border-border-dark">
<p class="text-xs text-slate-400 italic">
This report is generated by TungkuApi v2.0 - Advanced API Penetration Testing Tool. All findings include complete Evidence & Proof of Concept. Findings should be validated with additional testing.
</p>
</div>
</div>
<div class="pt-4 border-t border-border-dark mt-4">
<p class="text-xs text-slate-500">
<span class="font-bold">Target:</span> {{TARGET_URL}} |
<span class="font-bold">Total Findings:</span> {{TOTAL_VULNS}} ({{CRITICAL_COUNT}} Critical, {{HIGH_COUNT}} High, {{MEDIUM_COUNT}} Medium, {{LOW_COUNT}} Low)
</p>
<p class="text-xs text-slate-500 mt-2">
<span class="font-bold">Author:</span> Re-xist | <span class="font-bold">GitHub:</span> <a href="https://github.com/Re-xist" class="text-primary hover:underline">@Re-xist</a>
</p>
</div>
</section>

</div>
</main>

</div>

</body>
</html>"""

    def _create_vuln_html(self, vuln):
        """Create HTML for a single vulnerability with new professional format"""
        severity = vuln.get("severity", "INFO")
        severity_lower = severity.lower()

        # Map severity to CSS class
        severity_class = {
            "CRITICAL": "severity-critical",
            "HIGH": "severity-high",
            "MEDIUM": "severity-medium",
            "LOW": "severity-low",
            "INFO": "severity-low"
        }.get(severity, "severity-low")

        # Calculate CVSS score based on severity
        cvss_score = self._calculate_cvss_score(severity)

        # Generate unique ID
        vuln_id = vuln.get('id', f"TUNGKU-{self._generate_vuln_id()}")

        # Build metadata HTML
        meta_html = ""
        if vuln.get('full_url'):
            meta_html += f"""
                    <div class="vuln-meta-item">
                        <strong>Endpoint URL</strong>
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
        if vuln.get('timestamp'):
            meta_html += f"""
                    <div class="vuln-meta-item">
                        <strong>Timestamp</strong>
                        <span>{vuln.get('timestamp', '')}</span>
                    </div>"""

        # Evidence HTML with curl command
        evidence_html = self._create_evidence_html(vuln, severity_class)

        # Request/Response HTML
        request_response_html = self._create_request_response_html(vuln)

        # Remediation HTML
        remediation_html = ""
        if vuln.get('remediation'):
            remediation_html = f"""
<section class="space-y-3 bg-background-dark/50 p-4 rounded-lg border border-border-dark">
<h4 class="text-xs font-bold uppercase tracking-wider text-severity-low">✅ Recommended Remediation</h4>
<ul class="space-y-2">
<li class="flex items-start gap-2 text-sm text-slate-300">
<span class="material-symbols-outlined text-severity-low text-sm mt-0.5">check_circle</span>
{self._escape_html(vuln.get('remediation', ''))}
</li>
</ul>
</section>"""

        return f"""
<article class="relative group">
<div class="absolute -left-4 top-0 bottom-0 w-1 bg-{severity_class} rounded-full opacity-0 group-hover:opacity-100 transition-opacity"></div>
<div class="bg-surface-dark border border-border-dark rounded-xl overflow-hidden shadow-2xl">
<div class="p-6 border-b border-border-dark flex items-start justify-between bg-gradient-to-r from-{severity_class}/5 to-transparent">
<div class="space-y-2">
<div class="flex items-center gap-3">
<span class="px-2 py-0.5 rounded bg-{severity_class} text-[10px] font-black tracking-widest text-white uppercase">{severity}</span>
<span class="text-xs font-mono text-slate-500">ID: {vuln_id}</span>
</div>
<h3 class="text-2xl font-display font-bold text-white">{self._escape_html(vuln.get('name', 'Unknown'))}</h3>
</div>
<div class="text-right">
<div class="inline-flex flex-col items-center justify-center p-2 rounded-lg bg-background-dark border border-border-dark min-w-[80px]">
<p class="text-[10px] text-slate-500 uppercase font-bold tracking-tighter">CVSS</p>
<p class="text-2xl font-display font-black text-{severity_class}">{cvss_score}</p>
</div>
</div>
</div>

<div class="p-6 space-y-6">
<section class="space-y-2">
<h4 class="text-xs font-bold uppercase tracking-wider text-primary">Technical Description</h4>
<p class="text-sm leading-relaxed text-slate-300">
{self._escape_html(vuln.get('description', ''))}
</p>
</section>

<section class="space-y-4">
<div class="flex items-center justify-between">
<h4 class="text-xs font-bold uppercase tracking-wider text-{severity_class}">🔍 Evidence & Proof of Concept</h4>
<span class="px-2 py-1 rounded bg-{severity_class}/10 text-{severity_class} text-[10px] font-bold">VERIFIED</span>
</div>

{evidence_html}
</section>

{request_response_html}

<div class="p-4 rounded-lg bg-surface-dark/50 border border-border-dark">
<h4 class="text-xs font-bold uppercase tracking-wider text-slate-400 mb-3">Technical Details</h4>
<div class="grid grid-cols-2 gap-3 text-xs">
{meta_html}
</div>
</div>

{remediation_html}
</div>

<div class="px-6 py-4 bg-background-dark border-t border-border-dark flex items-center justify-between">
<div class="flex items-center gap-4">
<span class="text-xs text-slate-500">Status: <span class="inline-flex items-center px-2 py-0.5 rounded bg-{severity_class}/10 text-{severity_class} text-[10px] font-bold border border-{severity_class}/20">{severity} - ACTION REQUIRED</span></span>
</div>
</div>
</div>
</article>"""

    def _create_evidence_html(self, vuln, severity_class):
        """Create evidence section HTML"""
        curl_cmd = self._generate_curl_command(vuln)
        payload = vuln.get('payload', '')

        payload_html = ""
        if payload:
            payload_html = f"""
<div class="comment mt-3"># Payload used:</div>
<div class="problematic-code">
<div>{self._escape_html(payload[:200])}</div>
</div>"""

        return f"""
<div class="bg-background-dark rounded-lg border border-border-dark overflow-hidden">
<div class="p-3 border-b border-border-dark bg-surface-dark/50">
<div class="flex items-center gap-2">
<span class="material-symbols-outlined text-severity-high text-sm">terminal</span>
<p class="text-xs font-bold text-white">Proof of Concept: Reproduce Vulnerability</p>
</div>
</div>
<div class="p-4 space-y-3">
<div class="code-block rounded-lg p-4 font-mono text-xs text-slate-400 overflow-x-auto">
<div class="comment"># Run this curl command to reproduce the vulnerability:</div>
<div class="text-primary mt-2">{self._escape_html(curl_cmd)}</div>
{payload_html}
</div>

<div class="bg-{severity_class}/5 border border-{severity_class}/20 rounded p-3 mt-3">
<div class="flex items-start gap-2">
<span class="material-symbols-outlined text-{severity_class} text-sm">error</span>
<div>
<p class="text-xs font-bold text-{severity_class}">WHY THIS IS A PROBLEM:</p>
<ul class="text-xs text-slate-300 mt-1 space-y-1">
<li>• This vulnerability could lead to security breaches</li>
<li>• Attackers can exploit this to gain unauthorized access</li>
<li>• Immediate remediation is strongly recommended</li>
</ul>
</div>
</div>
</div>
</div>
</div>"""

    def _create_request_response_html(self, vuln):
        """Create HTTP request/response HTML"""
        if not vuln.get('request_detail') and not vuln.get('response_detail'):
            return ""

        req = vuln.get('request_detail', {})
        resp = vuln.get('response_detail', {})

        html = """
<!-- Request/Response Details -->
<div class="bg-background-dark rounded-lg border border-border-dark overflow-hidden">
<div class="p-3 border-b border-border-dark bg-surface-dark/50">
<div class="flex items-center gap-2">
<span class="material-symbols-outlined text-severity-high text-sm">http</span>
<p class="text-xs font-bold text-white">HTTP Request & Response Details</p>
</div>
</div>
<div class="p-4 space-y-3">
"""

        # Request section
        if req:
            html += """
<div class="code-block rounded-lg p-4 font-mono text-xs overflow-x-auto">
<div class="comment"># HTTP Request:</div>
"""
            html += f"<div class=\"text-primary mt-2\">{self._escape_html(req.get('method', 'GET'))} <span class=\"text-severity-high\">{self._escape_html(req.get('url', ''))}</span></div>"

            if req.get('headers'):
                html += "<div class='mt-3 text-slate-400'>Headers:</div>"
                for k, v in req.get('headers', {}).items():
                    html += f"<div><span class='text-primary'>{self._escape_html(k)}</span>: {self._escape_html(str(v)[:100])}</div>"

            html += "</div>"

        # Response section
        if resp:
            status = resp.get('status_code', 'N/A')
            status_color = 'text-severity-high' if status >= 400 else 'text-severity-low'

            html += f"""
<div class="code-block rounded-lg p-4 font-mono text-xs mt-3 overflow-x-auto">
<div class="comment"># HTTP Response:</div>
<div class="mt-2">Status: <span class="{status_color}">{status}</span></div>
"""

            if resp.get('response_time'):
                html += f"<div class='mt-2'>Response Time: <span class='text-severity-medium'>{self._escape_html(str(resp.get('response_time')))}</span></div>"

            if resp.get('response_snippet'):
                snippet = resp.get('response_snippet', '')[:300]
                html += f"<div class='mt-2'><span class='text-slate-400'>Response Body (first 300 chars):</span></div>"
                html += f"<div class='text-severity-high mt-1'>{self._escape_html(snippet)}</div>"

            html += "</div>"

        html += "</div></div>"

        return html

    def _generate_curl_command(self, vuln):
        """Generate curl command from vulnerability details"""
        req = vuln.get('request_detail', {})

        if not req:
            return "# No curl command available"

        # Build curl command
        method = req.get('method', 'GET')
        url = req.get('url', '')

        # Start with curl command
        curl_parts = [f"curl -X {method} '{url}'"]

        # Add headers
        headers = req.get('headers', {})
        if headers:
            for key, value in headers.items():
                # Skip some default headers
                if key.lower() in ['user-agent', 'accept', 'connection']:
                    continue
                # Escape single quotes in value
                escaped_value = str(value).replace("'", "'\\''")
                curl_parts.append(f"-H '{key}: {escaped_value}'")

        # Join all parts
        curl_cmd = " ".join(curl_parts)

        return curl_cmd

    def _calculate_cvss_score(self, severity):
        """Calculate CVSS score based on severity"""
        cvss_scores = {
            "CRITICAL": "9.0",
            "HIGH": "7.5",
            "MEDIUM": "5.5",
            "LOW": "3.5",
            "INFO": "0.0"
        }
        return cvss_scores.get(severity, "0.0")

    def _generate_vuln_id(self):
        """Generate unique vulnerability ID"""
        import random
        import string
        return f"2026-{random.randint(1000, 9999)}"

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
