"""
Event correlation module for SOC-SIM.
Detects multi-event attack patterns such as repeated failed logins followed by success,
and full kill-chain progression across multiple security domains.
"""

import os
import uuid
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional

from database.db_manager import DatabaseManager


class EventCorrelator:
    """Correlates multiple sequential or distributed events into compound security alerts and incidents."""

    def __init__(self, db_manager: Optional[DatabaseManager] = None):
        self.db_manager = db_manager or DatabaseManager()

    def _parse_ts(self, ts_str: str) -> datetime:
        """Parse ISO-8601 string to datetime object."""
        try:
            if ts_str.endswith("Z"):
                ts_str = ts_str[:-1] + "+00:00"
            dt = datetime.fromisoformat(ts_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            return datetime.now(timezone.utc)

    def correlate_failed_then_successful_login(
        self,
        events: List[Dict[str, Any]],
        failure_threshold: int = 3,
        correlation_window_seconds: int = 300
    ) -> List[Dict[str, Any]]:
        """
        RULE-002: Correlate repeated failed login attempts followed by a successful login
        from the same source IP within the time window.
        """
        auth_events = [
            e for e in events
            if e.get("event_category") == "authentication"
            and e.get("event_type") == "ssh_login"
        ]

        by_ip: Dict[str, List[Dict[str, Any]]] = {}
        for e in auth_events:
            ip = e.get("source_ip", "0.0.0.0")
            by_ip.setdefault(ip, []).append(e)

        alerts = []
        for ip, ip_events in by_ip.items():
            ip_events.sort(key=lambda x: self._parse_ts(x["timestamp"]))

            # Look for success events
            for i, evt in enumerate(ip_events):
                if evt.get("result") == "success":
                    success_time = self._parse_ts(evt["timestamp"])

                    # Look backwards for failures within the correlation window
                    prior_failures = [
                        prev for prev in ip_events[:i]
                        if prev.get("result") == "failure"
                        and 0 <= (success_time - self._parse_ts(prev["timestamp"])).total_seconds() <= correlation_window_seconds
                    ]

                    if len(prior_failures) >= failure_threshold:
                        supporting_ids = [f["event_id"] for f in prior_failures] + [evt["event_id"]]
                        user = evt.get("username", "unknown")
                        host = evt.get("hostname", "unknown-host")

                        alert = {
                            "alert_id": f"ALT-COMPR-{uuid.uuid4().hex[:8].upper()}",
                            "rule_id": "RULE-002",
                            "rule_name": "Successful Authentication Following Repeated Failures",
                            "severity": "Critical",
                            "description": f"Potential account compromise! Source IP {ip} successfully logged in as '{user}' on {host} after {len(prior_failures)} failed attempts within {correlation_window_seconds}s.",
                            "mitre_technique_id": "T1110.001",
                            "mitre_technique_name": "Password Guessing (Compromised Credential)",
                            "mitre_tactic": "Initial Access / Credential Access",
                            "source_ip": ip,
                            "affected_user": user,
                            "affected_host": host,
                            "timestamp": evt["timestamp"],
                            "supporting_event_ids": supporting_ids,
                            "recommended_steps": "Immediately quarantine host; revoke active sessions; initiate credential reset and security forensic audit.",
                            "status": "New"
                        }
                        alerts.append(alert)
                        break

        # Persist generated correlation alerts
        persisted = []
        for a in alerts:
            if self.db_manager.insert_alert(a):
                persisted.append(a)

        return persisted

    def correlate_multi_stage_campaign(
        self,
        events: List[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        """
        Identify multi-stage cyber kill chain activities:
        Reconnaissance -> Credential Access -> Privilege Escalation -> Impact/Execution.
        """
        scenarios_present = {e.get("scenario") for e in events if e.get("scenario")}
        required_stages = {"port_scan", "ssh_bruteforce", "privilege_escalation"}

        if not required_stages.issubset(scenarios_present):
            return None

        # Collect key evidence
        correlated_event_ids = [
            e["event_id"] for e in events
            if e.get("scenario") in ("port_scan", "ssh_bruteforce", "privilege_escalation", "file_modification", "suspicious_process")
        ]

        incident_id = f"INC-AUTO-{uuid.uuid4().hex[:6].upper()}"
        target_hosts = list({e.get("hostname") for e in events if e.get("hostname")})
        sources = list({e.get("source_ip") for e in events if e.get("source_ip") and not e.get("source_ip").startswith("192.168.") and e.get("source_ip") != "127.0.0.1"})

        incident = {
            "incident_id": incident_id,
            "title": "Coordinated Multi-Stage Intrusion Campaign",
            "severity": "Critical",
            "summary": (
                f"Automated correlation identified an active multi-stage intrusion targeting host(s) "
                f"{', '.join(target_hosts)} originating from external IP(s) {', '.join(sources)}. "
                f"Observed stages include Port Scanning (Reconnaissance), SSH Brute Forcing (Credential Access), "
                f"Sudo Abuse (Privilege Escalation), and Unauthorized System Modification."
            ),
            "status": "Open",
            "supporting_event_ids": correlated_event_ids,
            "created_at": datetime.now(timezone.utc).isoformat()
        }

        self.db_manager.save_incident(incident)
        return incident
