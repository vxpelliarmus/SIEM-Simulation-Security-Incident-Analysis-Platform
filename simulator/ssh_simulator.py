"""
SSH event simulation module for SOC-SIM.
Simulates SSH brute force attacks and successful breaches.
"""

import uuid
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional


class SSHSimulator:
    """Generates synthetic SSH authentication event sequences."""

    ATTACKER_IP = "198.51.100.45"  # RFC 5737 TEST-NET-2 documentation IP
    TARGET_HOST = "srv-app-01"

    @staticmethod
    def generate_brute_force(
        source_ip: str = ATTACKER_IP,
        target_host: str = TARGET_HOST,
        target_user: str = "root",
        attempts: int = 7,
        include_success: bool = False,
        base_time: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
        """
        Generate a sequence of rapid failed SSH authentication attempts,
        optionally concluding with an unauthorized successful login.
        """
        if base_time is None:
            base_time = datetime.now(timezone.utc) - timedelta(minutes=15)

        events = []
        passwords_tried = ["admin123", "password", "root2026", "toor", "123456", "letmein", "server!"]

        for i in range(attempts):
            event_time = base_time + timedelta(seconds=i * 8 + (i % 3))
            events.append({
                "event_id": f"EVT-SSH-{uuid.uuid4().hex[:12].upper()}",
                "timestamp": event_time.isoformat(),
                "hostname": target_host,
                "username": target_user,
                "source_ip": source_ip,
                "event_category": "authentication",
                "event_type": "ssh_login",
                "action": "login_attempt",
                "result": "failure",
                "metadata": {
                    "auth_method": "password",
                    "port": 22,
                    "attempt_number": i + 1,
                    "failure_reason": "invalid_credentials",
                    "user_agent": "SSH-2.0-OpenSSH_8.9p1",
                    "password_sample": passwords_tried[i % len(passwords_tried)]
                },
                "scenario": "ssh_bruteforce"
            })

        if include_success:
            success_time = base_time + timedelta(seconds=attempts * 8 + 12)
            events.append({
                "event_id": f"EVT-SSH-{uuid.uuid4().hex[:12].upper()}",
                "timestamp": success_time.isoformat(),
                "hostname": target_host,
                "username": target_user,
                "source_ip": source_ip,
                "event_category": "authentication",
                "event_type": "ssh_login",
                "action": "login_attempt",
                "result": "success",
                "metadata": {
                    "auth_method": "password",
                    "port": 22,
                    "session_id": f"sess-{uuid.uuid4().hex[:8]}",
                    "note": "Compromised credential login after failed attempts"
                },
                "scenario": "ssh_bruteforce"
            })

        return events
