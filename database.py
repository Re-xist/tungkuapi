"""
TungkuApi - Database Layer for Historical Tracking
SQLite database for storing scan results and trend analysis

Author: Re-xist
GitHub: https://github.com/Re-xist
Version: 3.0
"""

import sqlite3
import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional


class ScanDatabase:
    """SQLite database for storing and managing scan results"""

    def __init__(self, db_path="tungkuapi.db"):
        self.db_path = db_path
        self.conn = None
        self._init_database()

    def _init_database(self):
        """Initialize database and create tables"""
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row

        # Create tables
        self._create_tables()
        self._create_indexes()

    def _create_tables(self):
        """Create all necessary tables"""
        cursor = self.conn.cursor()

        # Scans table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT UNIQUE NOT NULL,
                target_url TEXT NOT NULL,
                scan_date TEXT NOT NULL,
                total_vulnerabilities INTEGER DEFAULT 0,
                critical_count INTEGER DEFAULT 0,
                high_count INTEGER DEFAULT 0,
                medium_count INTEGER DEFAULT 0,
                low_count INTEGER DEFAULT 0,
                info_count INTEGER DEFAULT 0,
                discovered_endpoints INTEGER DEFAULT 0,
                waf_detected TEXT,
                scanners_used TEXT,
                duration_seconds REAL,
                config_json TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Vulnerabilities table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                vuln_id TEXT,
                name TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT,
                evidence TEXT,
                endpoint TEXT,
                full_url TEXT,
                parameter TEXT,
                payload TEXT,
                remediation TEXT,
                cvss_score TEXT,
                request_json TEXT,
                response_json TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans (scan_id)
            )
        """)

        # Discovered endpoints table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS discovered_endpoints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                path TEXT NOT NULL,
                method TEXT NOT NULL,
                status_code INTEGER,
                content_type TEXT,
                response_time REAL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans (scan_id)
            )
        """)

        # Trends table (for aggregate statistics)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS daily_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_url TEXT NOT NULL,
                scan_date TEXT NOT NULL,
                critical_count INTEGER DEFAULT 0,
                high_count INTEGER DEFAULT 0,
                medium_count INTEGER DEFAULT 0,
                low_count INTEGER DEFAULT 0,
                info_count INTEGER DEFAULT 0,
                total_vulnerabilities INTEGER DEFAULT 0,
                UNIQUE(target_url, scan_date)
            )
        """)

        self.conn.commit()

    def _create_indexes(self):
        """Create indexes for better query performance"""
        cursor = self.conn.cursor()

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_scans_target_url
            ON scans(target_url)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_scans_scan_date
            ON scans(scan_date)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_vulnerabilities_scan_id
            ON vulnerabilities(scan_id)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity
            ON vulnerabilities(severity)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_vulnerabilities_endpoint
            ON vulnerabilities(endpoint)
        """)

        self.conn.commit()

    def save_scan(self, scan_id: str, results: Dict, duration: float = None):
        """Save scan results to database"""
        cursor = self.conn.cursor()

        # Extract scan metadata
        summary = results.get("summary", {})
        vulns = results.get("vulnerabilities", [])
        endpoints = results.get("discovered_endpoints", [])

        # Insert scan record
        try:
            cursor.execute("""
                INSERT INTO scans (
                    scan_id, target_url, scan_date,
                    total_vulnerabilities, critical_count, high_count,
                    medium_count, low_count, info_count,
                    discovered_endpoints, waf_detected, scanners_used,
                    duration_seconds, config_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_id,
                results.get("target", ""),
                results.get("scan_date", datetime.now().isoformat()),
                summary.get("total", len(vulns)),
                summary.get("critical", 0),
                summary.get("high", 0),
                summary.get("medium", 0),
                summary.get("low", 0),
                summary.get("info", 0),
                len(endpoints),
                "Yes" if results.get("waf_detected") else "No",
                json.dumps(results.get("scanners_used", [])),
                duration,
                json.dumps(results.get("config", {}))
            ))

            # Insert vulnerabilities
            for vuln in vulns:
                self._save_vulnerability(cursor, scan_id, vuln)

            # Insert discovered endpoints
            for endpoint in endpoints:
                self._save_endpoint(cursor, scan_id, endpoint)

            # Update daily stats
            self._update_daily_stats(cursor, results)

            self.conn.commit()
            return True

        except sqlite3.IntegrityError:
            self.conn.rollback()
            return False

    def _save_vulnerability(self, cursor, scan_id: str, vuln: Dict):
        """Save a single vulnerability to database"""
        cursor.execute("""
            INSERT INTO vulnerabilities (
                scan_id, vuln_id, name, severity, description,
                evidence, endpoint, full_url, parameter, payload,
                remediation, cvss_score, request_json, response_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_id,
            vuln.get("id", ""),
            vuln.get("name", ""),
            vuln.get("severity", "INFO"),
            vuln.get("description", ""),
            vuln.get("evidence", ""),
            vuln.get("endpoint", ""),
            vuln.get("full_url", ""),
            vuln.get("parameter", ""),
            vuln.get("payload", ""),
            vuln.get("remediation", ""),
            vuln.get("cvss_score", ""),
            json.dumps(vuln.get("request_detail", {})),
            json.dumps(vuln.get("response_detail", {}))
        ))

    def _save_endpoint(self, cursor, scan_id: str, endpoint: Dict):
        """Save a discovered endpoint to database"""
        cursor.execute("""
            INSERT INTO discovered_endpoints (
                scan_id, path, method, status_code, content_type, response_time
            ) VALUES (?, ?, ?, ?, ?, ?)
        """, (
            scan_id,
            endpoint.get("path", ""),
            endpoint.get("method", "GET"),
            endpoint.get("status", 200),
            endpoint.get("content_type", ""),
            endpoint.get("response_time", 0)
        ))

    def _update_daily_stats(self, cursor, results: Dict):
        """Update daily statistics for trend analysis"""
        summary = results.get("summary", {})
        target_url = results.get("target", "")
        scan_date = results.get("scan_date", datetime.now().isoformat())

        # Extract date part only (YYYY-MM-DD)
        date_part = scan_date.split("T")[0]

        cursor.execute("""
            INSERT OR REPLACE INTO daily_stats (
                target_url, scan_date, critical_count, high_count,
                medium_count, low_count, info_count, total_vulnerabilities
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            target_url,
            date_part,
            summary.get("critical", 0),
            summary.get("high", 0),
            summary.get("medium", 0),
            summary.get("low", 0),
            summary.get("info", 0),
            summary.get("total", 0)
        ))

    def get_scan_history(self, target_url: str = None, limit: int = 10) -> List[Dict]:
        """Get scan history for a target"""
        cursor = self.conn.cursor()

        if target_url:
            cursor.execute("""
                SELECT * FROM scans
                WHERE target_url = ?
                ORDER BY scan_date DESC
                LIMIT ?
            """, (target_url, limit))
        else:
            cursor.execute("""
                SELECT * FROM scans
                ORDER BY scan_date DESC
                LIMIT ?
            """, (limit,))

        return [dict(row) for row in cursor.fetchall()]

    def get_trend_analysis(self, target_url: str, days: int = 30) -> Dict:
        """Get trend analysis for a target over specified days"""
        cursor = self.conn.cursor()

        cursor.execute("""
            SELECT
                scan_date,
                SUM(critical_count) as critical,
                SUM(high_count) as high,
                SUM(medium_count) as medium,
                SUM(low_count) as low,
                SUM(total_vulnerabilities) as total
            FROM daily_stats
            WHERE target_url = ?
                AND scan_date >= date('now', '-' || ? || ' days')
            GROUP BY scan_date
            ORDER BY scan_date ASC
        """, (target_url, days))

        rows = cursor.fetchall()

        return {
            "target_url": target_url,
            "period_days": days,
            "data": [dict(row) for row in rows],
            "summary": self._calculate_trend_summary(rows)
        }

    def _calculate_trend_summary(self, rows: List) -> Dict:
        """Calculate trend summary from daily stats"""
        if not rows:
            return {"trend": "no_data", "improvement": 0}

        first_half = rows[:len(rows)//2] if len(rows) > 1 else rows
        second_half = rows[len(rows)//2:]

        first_avg = sum(row["total"] for row in first_half) / len(first_half)
        second_avg = sum(row["total"] for row in second_half) / len(second_half)

        improvement = ((first_avg - second_avg) / first_avg * 100) if first_avg > 0 else 0

        return {
            "trend": "improving" if improvement > 0 else "degrading" if improvement < 0 else "stable",
            "improvement_percent": round(improvement, 2),
            "first_half_avg": round(first_avg, 2),
            "second_half_avg": round(second_avg, 2)
        }

    def get_vulnerability_by_type(self, target_url: str = None) -> Dict:
        """Get vulnerability statistics by type"""
        cursor = self.conn.cursor()

        if target_url:
            cursor.execute("""
                SELECT name, severity, COUNT(*) as count
                FROM vulnerabilities v
                JOIN scans s ON v.scan_id = s.scan_id
                WHERE s.target_url = ?
                GROUP BY name, severity
                ORDER BY count DESC
            """, (target_url,))
        else:
            cursor.execute("""
                SELECT name, severity, COUNT(*) as count
                FROM vulnerabilities
                GROUP BY name, severity
                ORDER BY count DESC
            """)

        return [dict(row) for row in cursor.fetchall()]

    def get_top_vulnerable_endpoints(self, target_url: str = None, limit: int = 10) -> List[Dict]:
        """Get endpoints with most vulnerabilities"""
        cursor = self.conn.cursor()

        if target_url:
            cursor.execute("""
                SELECT endpoint, COUNT(*) as vuln_count,
                       SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical,
                       SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) as high
                FROM vulnerabilities v
                JOIN scans s ON v.scan_id = s.scan_id
                WHERE s.target_url = ? AND endpoint != ''
                GROUP BY endpoint
                ORDER BY vuln_count DESC
                LIMIT ?
            """, (target_url, limit))
        else:
            cursor.execute("""
                SELECT endpoint, COUNT(*) as vuln_count,
                       SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical,
                       SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) as high
                FROM vulnerabilities
                WHERE endpoint != ''
                GROUP BY endpoint
                ORDER BY vuln_count DESC
                LIMIT ?
            """, (limit,))

        return [dict(row) for row in cursor.fetchall()]

    def get_scan_comparison(self, scan_id_1: str, scan_id_2: str) -> Dict:
        """Compare two scans"""
        cursor = self.conn.cursor()

        # Get both scans
        cursor.execute("""
            SELECT * FROM scans WHERE scan_id = ?
        """, (scan_id_1,))
        scan1 = cursor.fetchone()

        cursor.execute("""
            SELECT * FROM scans WHERE scan_id = ?
        """, (scan_id_2,))
        scan2 = cursor.fetchone()

        if not scan1 or not scan2:
            return {"error": "One or both scans not found"}

        # Get vulnerabilities for both scans
        cursor.execute("""
            SELECT * FROM vulnerabilities WHERE scan_id = ?
        """, (scan_id_1,))
        vulns1 = [dict(row) for row in cursor.fetchall()]

        cursor.execute("""
            SELECT * FROM vulnerabilities WHERE scan_id = ?
        """, (scan_id_2,))
        vulns2 = [dict(row) for row in cursor.fetchall()]

        # Calculate differences
        vuln_ids1 = {v["endpoint"] + v["name"] for v in vulns1}
        vuln_ids2 = {v["endpoint"] + v["name"] for v in vulns2}

        fixed = vuln_ids1 - vuln_ids2
        new = vuln_ids2 - vuln_ids1
        remaining = vuln_ids1 & vuln_ids2

        return {
            "scan1": dict(scan1),
            "scan2": dict(scan2),
            "fixed_vulnerabilities": len(fixed),
            "new_vulnerabilities": len(new),
            "remaining_vulnerabilities": len(remaining),
            "improvement": len(vulns1) - len(vulns2)
        }

    def export_to_json(self, output_file: str):
        """Export database to JSON file"""
        cursor = self.conn.cursor()

        # Get all scans with vulnerabilities
        cursor.execute("""
            SELECT * FROM scans ORDER BY scan_date DESC
        """)
        scans = [dict(row) for row in cursor.fetchall()]

        for scan in scans:
            scan_id = scan["scan_id"]
            cursor.execute("""
                SELECT * FROM vulnerabilities WHERE scan_id = ?
            """, (scan_id,))
            scan["vulnerabilities"] = [dict(row) for row in cursor.fetchall()]

            cursor.execute("""
                SELECT * FROM discovered_endpoints WHERE scan_id = ?
            """, (scan_id,))
            scan["endpoints"] = [dict(row) for row in cursor.fetchall()]

        with open(output_file, 'w') as f:
            json.dump(scans, f, indent=2, default=str)

        return True

    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()
