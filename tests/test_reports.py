"""
Unit tests for incident report generation.
"""

import os
import tempfile
import pytest

from incident_reports.report_generator import IncidentReportGenerator


class TestReportGenerator:

    def setup_method(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.reporter = IncidentReportGenerator(output_dir=self.temp_dir.name)

    def teardown_method(self):
        self.temp_dir.cleanup()

    def test_report_generation_with_success(self):
        """Report for compromised account properly reflects telemetry evidence of breach."""
        alert = {
            "alert_id": "ALT-1234",
            "rule_id": "RULE-002",
            "rule_name": "Successful Login Following Repeated Failures",
            "severity": "Critical",
            "description": "Suspicious login after brute force.",
            "mitre_technique_id": "T1110.001",
            "mitre_technique_name": "Password Guessing",
            "mitre_tactic": "Initial Access",
            "source_ip": "198.51.100.45",
            "affected_user": "root",
            "affected_host": "srv-app-01",
            "timestamp": "2026-11-16T08:00:00Z"
        }
        supporting_events = [
            {
                "event_id": "EVT-1",
                "timestamp": "2026-11-16T07:59:00Z",
                "event_category": "authentication",
                "event_type": "ssh_login",
                "result": "failure",
                "metadata": {}
            },
            {
                "event_id": "EVT-2",
                "timestamp": "2026-11-16T08:00:00Z",
                "event_category": "authentication",
                "event_type": "ssh_login",
                "result": "success",
                "metadata": {}
            }
        ]
        notes = [{"analyst_name": "John", "created_at": "2026-11-16T08:05:00Z", "note": "Confirmed root compromised."}]

        report_md = self.reporter.generate_report(
            incident_id="INC-999",
            alert=alert,
            supporting_events=supporting_events,
            analyst_notes=notes,
            analyst_name="John"
        )

        assert "# Security Incident Report: INC-999" in report_md
        assert "CRITICAL" in report_md
        assert "T1110.001" in report_md
        assert "John" in report_md
        assert "Confirmed root compromised." in report_md
        assert "Telemetry indicates that unauthorized actions or authenticated access were achieved." in report_md
        assert "EVT-1" not in report_md or "EVT-2" not in report_md or "Timeline" in report_md

    def test_report_generation_blocked_attack(self):
        """Report for blocked attacks does NOT falsely claim successful breach."""
        alert = {
            "alert_id": "ALT-5678",
            "rule_id": "RULE-001",
            "rule_name": "SSH Brute Force",
            "severity": "High",
            "description": "Multiple failed attempts.",
            "mitre_technique_id": "T1110",
            "mitre_technique_name": "Brute Force",
            "mitre_tactic": "Credential Access",
            "source_ip": "198.51.100.45",
            "affected_user": "root",
            "affected_host": "srv-app-01",
            "timestamp": "2026-11-16T08:00:00Z"
        }
        supporting_events = [
            {
                "event_id": "EVT-1",
                "timestamp": "2026-11-16T07:59:00Z",
                "event_category": "authentication",
                "event_type": "ssh_login",
                "result": "failure",
                "metadata": {}
            }
        ]

        report_md = self.reporter.generate_report(
            incident_id="INC-555",
            alert=alert,
            supporting_events=supporting_events
        )

        assert "Telemetry demonstrates unauthorized access attempts were blocked or denied; no compromise confirmed." in report_md

    def test_save_report_file(self):
        """Ensure file is written to output directory."""
        saved_path = self.reporter.save_report("INC-TEST", "# Test Report Content")
        assert os.path.exists(saved_path)
        with open(saved_path, "r") as f:
            content = f.read()
        assert content == "# Test Report Content"
