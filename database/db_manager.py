"""
Database manager for SOC-SIM SIEM platform.
Handles SQLite operations for events, alerts, analyst notes, and incidents.
"""

import os
import json
import sqlite3
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional


class DatabaseManager:
    """Manages the SQLite database for storing normalized events, alerts, and investigations."""

    DEFAULT_DB_PATH = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "database",
        "soc_sim.db"
    )

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or self.DEFAULT_DB_PATH
        os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        self.init_db()

    def get_connection(self) -> sqlite3.Connection:
        """Create and return a database connection with dict-like row access."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def init_db(self) -> None:
        """Initialize tables and indexes if they do not exist."""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Normalized Events table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    hostname TEXT NOT NULL,
                    username TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    event_category TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    action TEXT NOT NULL,
                    result TEXT NOT NULL,
                    metadata TEXT,
                    scenario TEXT NOT NULL,
                    raw_json TEXT,
                    ingested_at TEXT NOT NULL
                )
            """)

            # Indexes for fast querying & correlation
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_category ON events(event_category)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_scenario ON events(scenario)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_type_result ON events(event_type, result)")

            # Alerts table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    rule_id TEXT NOT NULL,
                    rule_name TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT NOT NULL,
                    mitre_technique_id TEXT NOT NULL,
                    mitre_technique_name TEXT NOT NULL,
                    mitre_tactic TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    affected_user TEXT NOT NULL,
                    affected_host TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    supporting_event_ids TEXT NOT NULL,
                    recommended_steps TEXT,
                    status TEXT NOT NULL DEFAULT 'New',
                    created_at TEXT NOT NULL
                )
            """)

            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts(rule_id)")

            # Analyst investigation notes
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS analyst_notes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id TEXT NOT NULL,
                    analyst_name TEXT NOT NULL,
                    note TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (alert_id) REFERENCES alerts(alert_id) ON DELETE CASCADE
                )
            """)

            # Incidents table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    alert_id TEXT,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'Open',
                    report_markdown TEXT,
                    created_at TEXT NOT NULL
                )
            """)

            conn.commit()

    def insert_events(self, events: List[Dict[str, Any]]) -> int:
        """
        Insert a batch of normalized events.
        Prevents duplicate ingestion via PRIMARY KEY constraint on event_id.
        Returns the number of newly inserted events.
        """
        if not events:
            return 0

        inserted_count = 0
        now_utc = datetime.now(timezone.utc).isoformat()

        with self.get_connection() as conn:
            cursor = conn.cursor()
            for evt in events:
                metadata_str = json.dumps(evt.get("metadata", {}))
                raw_json_str = evt.get("raw_json") or json.dumps(evt)

                try:
                    cursor.execute("""
                        INSERT INTO events (
                            event_id, timestamp, hostname, username, source_ip,
                            event_category, event_type, action, result,
                            metadata, scenario, raw_json, ingested_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        evt["event_id"],
                        evt["timestamp"],
                        evt.get("hostname", "unknown-host"),
                        evt.get("username", "unknown-user"),
                        evt.get("source_ip", "0.0.0.0"),
                        evt.get("event_category", "system"),
                        evt.get("event_type", "unknown"),
                        evt.get("action", "unknown"),
                        evt.get("result", "unknown"),
                        metadata_str,
                        evt.get("scenario", "baseline"),
                        raw_json_str,
                        now_utc
                    ))
                    inserted_count += 1
                except sqlite3.IntegrityError:
                    # Duplicate event_id skipped
                    continue

            conn.commit()

        return inserted_count

    def get_events(
        self,
        limit: int = 1000,
        offset: int = 0,
        source_ip: Optional[str] = None,
        username: Optional[str] = None,
        category: Optional[str] = None,
        scenario: Optional[str] = None,
        result: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        search_query: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Retrieve events with optional multi-attribute filters."""
        query = "SELECT * FROM events WHERE 1=1"
        params: List[Any] = []

        if source_ip:
            query += " AND source_ip = ?"
            params.append(source_ip)
        if username:
            query += " AND username = ?"
            params.append(username)
        if category:
            query += " AND event_category = ?"
            params.append(category)
        if scenario:
            query += " AND scenario = ?"
            params.append(scenario)
        if result:
            query += " AND result = ?"
            params.append(result)
        if start_time:
            query += " AND timestamp >= ?"
            params.append(start_time)
        if end_time:
            query += " AND timestamp <= ?"
            params.append(end_time)
        if search_query:
            query += " AND (event_id LIKE ? OR hostname LIKE ? OR username LIKE ? OR source_ip LIKE ? OR metadata LIKE ?)"
            wildcard = f"%{search_query}%"
            params.extend([wildcard, wildcard, wildcard, wildcard, wildcard])

        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()

            result_list = []
            for row in rows:
                d = dict(row)
                if d.get("metadata"):
                    try:
                        d["metadata"] = json.loads(d["metadata"])
                    except Exception:
                        pass
                result_list.append(d)
            return result_list

    def get_event_by_id(self, event_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a single event by ID."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM events WHERE event_id = ?", (event_id,))
            row = cursor.fetchone()
            if not row:
                return None
            d = dict(row)
            if d.get("metadata"):
                try:
                    d["metadata"] = json.loads(d["metadata"])
                except Exception:
                    pass
            return d

    def insert_alert(self, alert: Dict[str, Any]) -> bool:
        """
        Insert an alert with sliding-window deduplication check.
        Returns True if inserted, False if duplicate skipped.
        """
        now_utc = datetime.now(timezone.utc).isoformat()
        supporting_events = json.dumps(alert.get("supporting_event_ids", []))

        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Prevent duplicate alert if same rule, source_ip, and affected_user within last hour exists
            cursor.execute("""
                SELECT alert_id FROM alerts
                WHERE rule_id = ? AND source_ip = ? AND affected_user = ?
                AND timestamp = ?
            """, (
                alert["rule_id"],
                alert.get("source_ip", ""),
                alert.get("affected_user", ""),
                alert.get("timestamp", "")
            ))
            if cursor.fetchone():
                return False

            try:
                cursor.execute("""
                    INSERT INTO alerts (
                        alert_id, rule_id, rule_name, severity, description,
                        mitre_technique_id, mitre_technique_name, mitre_tactic,
                        source_ip, affected_user, affected_host, timestamp,
                        supporting_event_ids, recommended_steps, status, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    alert["alert_id"],
                    alert["rule_id"],
                    alert["rule_name"],
                    alert["severity"],
                    alert["description"],
                    alert.get("mitre_technique_id", "T0000"),
                    alert.get("mitre_technique_name", "Unknown"),
                    alert.get("mitre_tactic", "Unknown"),
                    alert.get("source_ip", "0.0.0.0"),
                    alert.get("affected_user", "unknown"),
                    alert.get("affected_host", "unknown"),
                    alert.get("timestamp", now_utc),
                    supporting_events,
                    alert.get("recommended_steps", ""),
                    alert.get("status", "New"),
                    now_utc
                ))
                conn.commit()
                return True
            except sqlite3.IntegrityError:
                return False

    def get_alerts(
        self,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        rule_id: Optional[str] = None,
        limit: int = 500
    ) -> List[Dict[str, Any]]:
        """Fetch alerts with filtering."""
        query = "SELECT * FROM alerts WHERE 1=1"
        params: List[Any] = []

        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if status:
            query += " AND status = ?"
            params.append(status)
        if rule_id:
            query += " AND rule_id = ?"
            params.append(rule_id)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            alerts = []
            for row in rows:
                d = dict(row)
                if d.get("supporting_event_ids"):
                    try:
                        d["supporting_event_ids"] = json.loads(d["supporting_event_ids"])
                    except Exception:
                        d["supporting_event_ids"] = []
                alerts.append(d)
            return alerts

    def get_alert_by_id(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a single alert by ID."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,))
            row = cursor.fetchone()
            if not row:
                return None
            d = dict(row)
            if d.get("supporting_event_ids"):
                try:
                    d["supporting_event_ids"] = json.loads(d["supporting_event_ids"])
                except Exception:
                    d["supporting_event_ids"] = []
            return d

    def update_alert_status(self, alert_id: str, new_status: str) -> bool:
        """Update the status of an alert (e.g. New -> In Progress -> Closed - True Positive)."""
        valid_statuses = {"New", "In Progress", "Closed - True Positive", "Closed - False Positive"}
        if new_status not in valid_statuses:
            raise ValueError(f"Invalid alert status: {new_status}. Must be one of {valid_statuses}")

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE alerts SET status = ? WHERE alert_id = ?", (new_status, alert_id))
            conn.commit()
            return cursor.rowcount > 0

    def add_analyst_note(self, alert_id: str, analyst_name: str, note: str) -> int:
        """Record an analyst investigation observation."""
        now_utc = datetime.now(timezone.utc).isoformat()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO analyst_notes (alert_id, analyst_name, note, created_at)
                VALUES (?, ?, ?, ?)
            """, (alert_id, analyst_name, note, now_utc))
            conn.commit()
            return cursor.lastrowid

    def get_analyst_notes(self, alert_id: str) -> List[Dict[str, Any]]:
        """Retrieve notes for a given alert."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM analyst_notes WHERE alert_id = ? ORDER BY created_at ASC
            """, (alert_id,))
            return [dict(row) for row in cursor.fetchall()]

    def save_incident(self, incident: Dict[str, Any]) -> None:
        """Insert or replace a security incident record."""
        now_utc = datetime.now(timezone.utc).isoformat()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO incidents (
                    incident_id, alert_id, title, severity, summary,
                    status, report_markdown, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                incident["incident_id"],
                incident.get("alert_id"),
                incident["title"],
                incident["severity"],
                incident["summary"],
                incident.get("status", "Open"),
                incident.get("report_markdown", ""),
                incident.get("created_at", now_utc)
            ))
            conn.commit()

    def get_incidents(self) -> List[Dict[str, Any]]:
        """Retrieve all incidents."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM incidents ORDER BY created_at DESC")
            return [dict(row) for row in cursor.fetchall()]

    def get_incident_by_id(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a specific incident."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_stats(self) -> Dict[str, Any]:
        """Aggregate statistical metrics for SOC dashboard overview."""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("SELECT COUNT(*) FROM events")
            total_events = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM alerts")
            total_alerts = cursor.fetchone()[0]

            cursor.execute("""
                SELECT severity, COUNT(*) FROM alerts GROUP BY severity
            """)
            severity_counts = {row[0]: row[1] for row in cursor.fetchall()}

            cursor.execute("""
                SELECT scenario, COUNT(*) FROM events GROUP BY scenario
            """)
            scenario_counts = {row[0]: row[1] for row in cursor.fetchall()}

            cursor.execute("""
                SELECT status, COUNT(*) FROM alerts GROUP BY status
            """)
            alert_status_counts = {row[0]: row[1] for row in cursor.fetchall()}

            return {
                "total_events": total_events,
                "total_alerts": total_alerts,
                "critical_alerts": severity_counts.get("Critical", 0),
                "high_alerts": severity_counts.get("High", 0),
                "medium_alerts": severity_counts.get("Medium", 0),
                "low_alerts": severity_counts.get("Low", 0),
                "info_alerts": severity_counts.get("Informational", 0),
                "severity_breakdown": severity_counts,
                "scenario_breakdown": scenario_counts,
                "status_breakdown": alert_status_counts
            }

    def clear_all_data(self) -> None:
        """Reset and purge all simulated events, alerts, notes, and incidents."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM analyst_notes")
            cursor.execute("DELETE FROM incidents")
            cursor.execute("DELETE FROM alerts")
            cursor.execute("DELETE FROM events")
            conn.commit()
            cursor.execute("VACUUM")
            conn.commit()
