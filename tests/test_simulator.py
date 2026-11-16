"""
Unit tests for event simulation and schema validation.
"""

import pytest
from datetime import datetime, timezone
from simulator.event_generator import SecurityEventGenerator
from simulator.ssh_simulator import SSHSimulator
from simulator.login_simulator import LoginSimulator
from simulator.network_simulator import NetworkSimulator
from simulator.system_simulator import SystemSimulator


class TestSimulator:

    def setup_method(self):
        self.generator = SecurityEventGenerator()

    def test_schema_validation_positive(self):
        """Verify schema validator accepts conforming event."""
        valid_event = {
            "event_id": "EVT-TEST-001",
            "timestamp": "2026-11-16T08:00:00Z",
            "hostname": "srv-app-01",
            "username": "root",
            "source_ip": "198.51.100.45",
            "event_category": "authentication",
            "event_type": "ssh_login",
            "action": "login_attempt",
            "result": "failure",
            "metadata": {"port": 22},
            "scenario": "ssh_bruteforce"
        }
        assert self.generator.validate_event_schema(valid_event) is True

    def test_schema_validation_negative(self):
        """Verify schema validator rejects events missing required fields or having wrong types."""
        # Missing event_id
        invalid_1 = {
            "timestamp": "2026-11-16T08:00:00Z",
            "hostname": "srv-app-01",
            "username": "root"
        }
        assert self.generator.validate_event_schema(invalid_1) is False

        # Metadata is not a dict
        invalid_2 = {
            "event_id": "EVT-002",
            "timestamp": "2026-11-16T08:00:00Z",
            "hostname": "srv-app-01",
            "username": "root",
            "source_ip": "198.51.100.45",
            "event_category": "authentication",
            "event_type": "ssh_login",
            "action": "login_attempt",
            "result": "failure",
            "metadata": "not-a-dict",
            "scenario": "ssh_bruteforce"
        }
        assert self.generator.validate_event_schema(invalid_2) is False

    def test_ssh_bruteforce_generation(self):
        """Ensure SSH simulator produces expected count, realistic sequence, and RFC documentation IP."""
        events = SSHSimulator.generate_brute_force(attempts=6, include_success=True)
        assert len(events) == 7
        assert events[0]["source_ip"] == "198.51.100.45"
        assert events[0]["event_category"] == "authentication"
        assert events[0]["result"] == "failure"
        assert events[-1]["result"] == "success"

        # Verify all validate against schema
        for e in events:
            assert self.generator.validate_event_schema(e) is True

    def test_network_port_scan_generation(self):
        """Ensure port scanner produces sequential multi-port probes."""
        events = NetworkSimulator.generate_port_scan()
        assert len(events) >= 10
        ports = [e["metadata"]["dest_port"] for e in events]
        assert len(set(ports)) == len(ports)
        assert events[0]["source_ip"] == "203.0.113.88"
        for e in events:
            assert self.generator.validate_event_schema(e) is True

    def test_system_simulator_scenarios(self):
        """Verify privilege escalation, file tampering, and reverse shell generators."""
        priv_events = SystemSimulator.generate_privilege_escalation()
        assert len(priv_events) == 2
        assert priv_events[0]["event_type"] == "sudo_exec"
        assert priv_events[0]["result"] == "denied"

        file_events = SystemSimulator.generate_file_modification()
        assert len(file_events) == 1
        assert file_events[0]["metadata"]["filepath"] == "/etc/shadow"

        proc_events = SystemSimulator.generate_suspicious_process()
        assert len(proc_events) == 1
        assert "/dev/tcp/" in proc_events[0]["metadata"]["command_line"]

    def test_baseline_generation(self):
        """Ensure baseline generator creates benign events marked with 'baseline' scenario."""
        baseline_events = self.generator.generate_baseline_events(count=30)
        assert len(baseline_events) == 30
        for e in baseline_events:
            assert e["scenario"] == "baseline"
            assert self.generator.validate_event_schema(e) is True

    def test_multi_stage_attack_generation(self):
        """Verify coordinated multi-stage attack generates comprehensive sequence across all domains."""
        events = self.generator.generate_scenario("multi_stage_attack")
        scenarios = {e["scenario"] for e in events}
        assert "port_scan" in scenarios
        assert "ssh_bruteforce" in scenarios
        assert "privilege_escalation" in scenarios
        assert "file_modification" in scenarios
        assert "suspicious_process" in scenarios
