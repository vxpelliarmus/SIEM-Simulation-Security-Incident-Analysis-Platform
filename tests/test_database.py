"""
Unit tests for SQLite database operations and persistence.
"""

import os
import tempfile
import pytest

from database.db_manager import DatabaseManager


class TestDatabase:

    def setup_method(self):
        self.temp_db_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db = DatabaseManager(db_path=self.temp_db_file.name)

    def teardown_method(self):
        self.temp_db_file.close()
        if os.path.exists(self.temp_db_file.name):
            os.unlink(self.temp_db_file.name)

    def test_database_initialization(self):
        """Verify tables and connection work properly."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {row[0] for row in cursor.fetchall()}
            assert "events" in tables
            assert "alerts" in tables
            assert "analyst_notes" in tables
            assert "incidents" in tables

    def test_event_crud_and_filtering(self):
        """Test event batch insertion and filtered retrieval."""
        sample_events = [
            {
                "event_id": f"EVT-DB-{i}",
                "timestamp": f"2026-11-16T08:0{i}:00Z",
                "hostname": "srv-app-01" if i % 2 == 0 else "srv-db-01",
                "username": "root" if i % 2 == 0 else "jdoe",
                "source_ip": "198.51.100.45" if i % 2 == 0 else "10.0.1.5",
                "event_category": "authentication" if i % 2 == 0 else "process",
                "event_type": "ssh_login" if i % 2 == 0 else "sudo_exec",
                "action": "login_attempt",
                "result": "failure" if i % 2 == 0 else "success",
                "metadata": {"attempt": i},
                "scenario": "ssh_bruteforce" if i % 2 == 0 else "baseline",
                "raw_json": "{}"
            }
            for i in range(10)
        ]

        inserted = self.db.insert_events(sample_events)
        assert inserted == 10

        # Filter by category
        auth_events = self.db.get_events(category="authentication")
        assert len(auth_events) == 5

        # Filter by source IP
        ip_events = self.db.get_events(source_ip="198.51.100.45")
        assert len(ip_events) == 5

        # Search query
        searched = self.db.get_events(search_query="srv-db-01")
        assert len(searched) == 5

    def test_alert_lifecycle_and_status_update(self):
        """Test alert insertion, retrieval, and status lifecycle."""
        alert = {
            "alert_id": "ALT-TEST-001",
            "rule_id": "RULE-001",
            "rule_name": "SSH Brute Force",
            "severity": "High",
            "description": "Test alert",
            "mitre_technique_id": "T1110",
            "mitre_technique_name": "Brute Force",
            "mitre_tactic": "Credential Access",
            "source_ip": "198.51.100.45",
            "affected_user": "root",
            "affected_host": "srv-app-01",
            "timestamp": "2026-11-16T08:00:00Z",
            "supporting_event_ids": ["EVT-1", "EVT-2"],
            "status": "New"
        }
        inserted = self.db.insert_alert(alert)
        assert inserted is True

        # Fetch alert
        retrieved = self.db.get_alert_by_id("ALT-TEST-001")
        assert retrieved is not None
        assert retrieved["status"] == "New"
        assert retrieved["supporting_event_ids"] == ["EVT-1", "EVT-2"]

        # Update status
        updated = self.db.update_alert_status("ALT-TEST-001", "In Progress")
        assert updated is True

        retrieved_updated = self.db.get_alert_by_id("ALT-TEST-001")
        assert retrieved_updated["status"] == "In Progress"

    def test_analyst_notes(self):
        """Test recording analyst notes for an alert."""
        alert = {
            "alert_id": "ALT-NOTE-01",
            "rule_id": "RULE-001",
            "rule_name": "Test",
            "severity": "Low",
            "description": "Test",
            "mitre_technique_id": "T1110",
            "mitre_technique_name": "Brute Force",
            "mitre_tactic": "Credential Access",
            "source_ip": "198.51.100.45",
            "affected_user": "root",
            "affected_host": "srv-app-01",
            "timestamp": "2026-11-16T08:00:00Z",
            "supporting_event_ids": []
        }
        self.db.insert_alert(alert)

        self.db.add_analyst_note("ALT-NOTE-01", "Alice", "Investigating IP reputation.")
        self.db.add_analyst_note("ALT-NOTE-01", "Bob", "Firewall block enacted.")

        notes = self.db.get_analyst_notes("ALT-NOTE-01")
        assert len(notes) == 2
        assert notes[0]["analyst_name"] == "Alice"
        assert notes[1]["analyst_name"] == "Bob"

    def test_stats_and_clear_data(self):
        """Test stats aggregation and clear all data."""
        alert = {
            "alert_id": "ALT-STAT-01",
            "rule_id": "RULE-001",
            "rule_name": "Test",
            "severity": "Critical",
            "description": "Test",
            "mitre_technique_id": "T1110",
            "mitre_technique_name": "Brute Force",
            "mitre_tactic": "Credential Access",
            "source_ip": "198.51.100.45",
            "affected_user": "root",
            "affected_host": "srv-app-01",
            "timestamp": "2026-11-16T08:00:00Z",
            "supporting_event_ids": []
        }
        self.db.insert_alert(alert)

        stats = self.db.get_stats()
        assert stats["total_alerts"] == 1
        assert stats["critical_alerts"] == 1

        # Clear data
        self.db.clear_all_data()
        cleared_stats = self.db.get_stats()
        assert cleared_stats["total_events"] == 0
        assert cleared_stats["total_alerts"] == 0
