"""
Login anomaly and account probing simulation module for SOC-SIM.
"""

import uuid
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional


class LoginSimulator:
    """Generates synthetic anomalous login patterns and user enumeration sequences."""

    PROBER_IP = "198.51.100.72"  # RFC 5737 TEST-NET-2 documentation IP
    TARGET_HOST = "srv-app-01"

    @staticmethod
    def generate_account_probing(
        source_ip: str = PROBER_IP,
        target_host: str = TARGET_HOST,
        target_users: Optional[List[str]] = None,
        base_time: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
        """
        Simulate a single IP cycling through multiple distinct usernames (password spraying / enumeration).
        """
        if base_time is None:
            base_time = datetime.now(timezone.utc) - timedelta(minutes=20)

        if target_users is None:
            target_users = ["admin", "root", "oracle", "postgres", "guest", "deploy", "ubuntu"]

        events = []
        for i, user in enumerate(target_users):
            event_time = base_time + timedelta(seconds=i * 12 + 3)
            events.append({
                "event_id": f"EVT-AUTH-{uuid.uuid4().hex[:12].upper()}",
                "timestamp": event_time.isoformat(),
                "hostname": target_host,
                "username": user,
                "source_ip": source_ip,
                "event_category": "authentication",
                "event_type": "ssh_login",
                "action": "login_attempt",
                "result": "failure",
                "metadata": {
                    "auth_method": "password",
                    "port": 22,
                    "target_account": user,
                    "failure_reason": "user_unknown_or_bad_pwd",
                    "user_agent": "SSH-2.0-libssh_0.9.6"
                },
                "scenario": "suspicious_login"
            })

        return events

    @staticmethod
    def generate_off_hours_login(
        source_ip: str = "203.0.113.19",  # RFC 5737 TEST-NET-3
        target_host: str = TARGET_HOST,
        username: str = "finance_admin",
        base_time: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
        """
        Simulate an unexpected successful login during non-business hours (e.g. 03:15 AM).
        """
        if base_time is None:
            # Set to 03:15 AM UTC of today
            now = datetime.now(timezone.utc)
            base_time = now.replace(hour=3, minute=15, second=22)

        return [{
            "event_id": f"EVT-AUTH-{uuid.uuid4().hex[:12].upper()}",
            "timestamp": base_time.isoformat(),
            "hostname": target_host,
            "username": username,
            "source_ip": source_ip,
            "event_category": "authentication",
            "event_type": "ssh_login",
            "action": "login_attempt",
            "result": "success",
            "metadata": {
                "auth_method": "publickey",
                "port": 22,
                "login_hour_utc": base_time.hour,
                "anomaly_flag": "off_hours_access"
            },
            "scenario": "suspicious_login"
        }]
