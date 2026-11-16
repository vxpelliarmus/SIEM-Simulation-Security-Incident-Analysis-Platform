"""
Master Security Event Generator for SOC-SIM platform.
Coordinates baseline background activity and synthetic attack scenarios.
"""

import os
import json
import uuid
import random
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional

from .ssh_simulator import SSHSimulator
from .login_simulator import LoginSimulator
from .network_simulator import NetworkSimulator
from .system_simulator import SystemSimulator


class SecurityEventGenerator:
    """Orchestrates generation of realistic synthetic security events and baseline telemetry."""

    HOSTNAMES = ["srv-app-01", "srv-db-01", "ws-finance-04", "ws-dev-09", "gw-edge-01"]
    INTERNAL_IPS = ["192.168.1.10", "192.168.1.25", "192.168.1.105", "10.0.1.5", "10.0.1.15"]
    NORMAL_USERS = ["asmith", "bwayne", "jdoe", "sysadmin_rob", "backup_agent"]

    REQUIRED_FIELDS = [
        "event_id",
        "timestamp",
        "hostname",
        "username",
        "source_ip",
        "event_category",
        "event_type",
        "action",
        "result",
        "metadata",
        "scenario"
    ]

    def __init__(self):
        self.ssh_sim = SSHSimulator()
        self.login_sim = LoginSimulator()
        self.network_sim = NetworkSimulator()
        self.system_sim = SystemSimulator()

    @classmethod
    def validate_event_schema(cls, event: Dict[str, Any]) -> bool:
        """Verify that an event dictionary conforms to the required SOC-SIM schema."""
        if not isinstance(event, dict):
            return False
        for field in cls.REQUIRED_FIELDS:
            if field not in event or event[field] is None:
                return False
        if not isinstance(event.get("metadata"), dict):
            return False
        return True

    def generate_baseline_events(
        self,
        count: int = 50,
        start_time: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
        """
        Generate realistic benign background activities that should NOT trigger security alerts.
        Includes routine authorized logons, web requests, cron jobs, and admin maintenance.
        """
        if start_time is None:
            start_time = datetime.now(timezone.utc) - timedelta(minutes=45)

        events = []
        for i in range(count):
            t = start_time + timedelta(seconds=i * 20 + random.randint(1, 10))
            category_choice = random.choice(["authentication", "network", "process", "system"])
            host = random.choice(self.HOSTNAMES)
            src_ip = random.choice(self.INTERNAL_IPS)
            user = random.choice(self.NORMAL_USERS)

            if category_choice == "authentication":
                events.append({
                    "event_id": f"EVT-BASE-{uuid.uuid4().hex[:12].upper()}",
                    "timestamp": t.isoformat(),
                    "hostname": host,
                    "username": user,
                    "source_ip": src_ip,
                    "event_category": "authentication",
                    "event_type": "ssh_login",
                    "action": "login_attempt",
                    "result": "success",
                    "metadata": {
                        "auth_method": "publickey",
                        "port": 22,
                        "session_id": f"sess-{uuid.uuid4().hex[:6]}"
                    },
                    "scenario": "baseline"
                })
            elif category_choice == "network":
                events.append({
                    "event_id": f"EVT-BASE-{uuid.uuid4().hex[:12].upper()}",
                    "timestamp": t.isoformat(),
                    "hostname": host,
                    "username": "www-data",
                    "source_ip": src_ip,
                    "event_category": "network",
                    "event_type": "http_request",
                    "action": "get_resource",
                    "result": "allowed",
                    "metadata": {
                        "dest_port": 80,
                        "http_status": 200,
                        "uri": random.choice(["/index.html", "/api/health", "/assets/app.js", "/style.css"]),
                        "bytes_transferred": random.randint(250, 4200)
                    },
                    "scenario": "baseline"
                })
            elif category_choice == "process":
                events.append({
                    "event_id": f"EVT-BASE-{uuid.uuid4().hex[:12].upper()}",
                    "timestamp": t.isoformat(),
                    "hostname": host,
                    "username": "root",
                    "source_ip": "127.0.0.1",
                    "event_category": "process",
                    "event_type": "cron_job",
                    "action": "execute",
                    "result": "success",
                    "metadata": {
                        "command": "/usr/sbin/logrotate /etc/logrotate.conf",
                        "pid": random.randint(2000, 3500)
                    },
                    "scenario": "baseline"
                })
            else:
                events.append({
                    "event_id": f"EVT-BASE-{uuid.uuid4().hex[:12].upper()}",
                    "timestamp": t.isoformat(),
                    "hostname": host,
                    "username": "sysadmin_rob",
                    "source_ip": src_ip,
                    "event_category": "process",
                    "event_type": "sudo_exec",
                    "action": "elevate",
                    "result": "success",
                    "metadata": {
                        "command": "systemctl status chronyd",
                        "target_uid": 0,
                        "tty": "pts/0"
                    },
                    "scenario": "baseline"
                })

        return events

    def generate_scenario(
        self,
        scenario_name: str,
        base_time: Optional[datetime] = None,
        **kwargs
    ) -> List[Dict[str, Any]]:
        """
        Generate events for a specific attack scenario or integrated multi-stage attack.
        """
        if base_time is None:
            base_time = datetime.now(timezone.utc) - timedelta(minutes=20)

        if scenario_name == "ssh_bruteforce":
            return self.ssh_sim.generate_brute_force(
                attempts=kwargs.get("attempts", 7),
                include_success=kwargs.get("include_success", False),
                base_time=base_time
            )
        elif scenario_name == "suspicious_login":
            return self.login_sim.generate_account_probing(base_time=base_time)
        elif scenario_name == "port_scan":
            return self.network_sim.generate_port_scan(base_time=base_time)
        elif scenario_name == "privilege_escalation":
            return self.system_sim.generate_privilege_escalation(base_time=base_time)
        elif scenario_name == "file_modification":
            return self.system_sim.generate_file_modification(base_time=base_time)
        elif scenario_name == "suspicious_process":
            return self.system_sim.generate_suspicious_process(base_time=base_time)
        elif scenario_name == "multi_stage_attack":
            # Realistic progressive sequence:
            # Reconnaissance (Port Scan) -> Brute Force -> Compromise -> Priv Esc -> File Tamper -> Reverse Shell
            all_events = []
            t = base_time

            # 1. Port scan reconnaissance
            all_events.extend(self.network_sim.generate_port_scan(base_time=t))
            t += timedelta(minutes=4)

            # 2. SSH Brute Force leading to credential access
            all_events.extend(self.ssh_sim.generate_brute_force(
                attempts=6,
                include_success=True,
                base_time=t
            ))
            t += timedelta(minutes=3)

            # 3. Privilege Escalation via Sudo
            all_events.extend(self.system_sim.generate_privilege_escalation(base_time=t))
            t += timedelta(minutes=2)

            # 4. Sensitive File Tampering
            all_events.extend(self.system_sim.generate_file_modification(base_time=t))
            t += timedelta(minutes=1)

            # 5. Reverse Shell Process Execution
            all_events.extend(self.system_sim.generate_suspicious_process(base_time=t))

            return all_events
        elif scenario_name == "baseline":
            return self.generate_baseline_events(count=kwargs.get("count", 40), start_time=base_time)
        else:
            raise ValueError(f"Unknown scenario: {scenario_name}")

    def save_events_to_file(self, events: List[Dict[str, Any]], filepath: str) -> str:
        """Write events list to JSON file on disk."""
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(events, f, indent=2)
        return filepath
