"""
Detection Engine for SOC-SIM SIEM platform.
Loads YAML rules and configuration, applies sliding time windows and thresholds,
and generates structured alerts with supporting event evidence and MITRE mappings.
"""

import os
import yaml
import uuid
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional

from database.db_manager import DatabaseManager


class DetectionEngine:
    """Core rule-based detection engine for identifying security threats."""

    CONFIG_PATH = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "config",
        "detection_config.yaml"
    )

    def __init__(self, db_manager: Optional[DatabaseManager] = None, config_path: Optional[str] = None):
        self.db_manager = db_manager or DatabaseManager()
        self.config_path = config_path or self.CONFIG_PATH
        self.config = self.load_config()

    def load_config(self) -> Dict[str, Any]:
        """Load detection configuration from YAML."""
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    return yaml.safe_load(f) or {}
            except Exception as e:
                print(f"Warning: Failed to load config from {self.config_path}: {e}")
        return {}

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

    def detect_ssh_bruteforce(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        RULE-001: Detects multiple failed SSH logins from one source IP within time window.
        """
        rule_cfg = self.config.get("rules", {}).get("RULE-001", {})
        if not rule_cfg.get("enabled", True):
            return []

        threshold = rule_cfg.get("threshold", 5)
        window_seconds = rule_cfg.get("time_window_seconds", 120)

        # Filter SSH failed attempts
        failed_events = [
            e for e in events
            if e.get("event_category") == "authentication"
            and e.get("event_type") == "ssh_login"
            and e.get("result") == "failure"
        ]

        # Group by source IP
        by_ip: Dict[str, List[Dict[str, Any]]] = {}
        for e in failed_events:
            ip = e.get("source_ip", "0.0.0.0")
            by_ip.setdefault(ip, []).append(e)

        alerts = []
        for ip, ip_events in by_ip.items():
            if len(ip_events) < threshold:
                continue

            # Sort by timestamp
            ip_events.sort(key=lambda x: self._parse_ts(x["timestamp"]))

            # Sliding window check
            window_start_idx = 0
            for i in range(len(ip_events)):
                current_time = self._parse_ts(ip_events[i]["timestamp"])
                while (current_time - self._parse_ts(ip_events[window_start_idx]["timestamp"])).total_seconds() > window_seconds:
                    window_start_idx += 1

                events_in_window = ip_events[window_start_idx : i + 1]
                if len(events_in_window) >= threshold:
                    supporting_ids = [evt["event_id"] for evt in events_in_window]
                    target_users = list({evt.get("username", "unknown") for evt in events_in_window})
                    host = events_in_window[-1].get("hostname", "unknown-host")
                    latest_ts = events_in_window[-1]["timestamp"]

                    alert = {
                        "alert_id": f"ALT-BF-{uuid.uuid4().hex[:8].upper()}",
                        "rule_id": "RULE-001",
                        "rule_name": rule_cfg.get("name", "SSH Brute Force Attack Detected"),
                        "severity": rule_cfg.get("severity", "High"),
                        "description": f"Detected {len(events_in_window)} failed SSH login attempts from {ip} targeting account(s): {', '.join(target_users)} within {window_seconds}s.",
                        "mitre_technique_id": rule_cfg.get("technique_id", "T1110"),
                        "mitre_technique_name": rule_cfg.get("technique_name", "Brute Force"),
                        "mitre_tactic": rule_cfg.get("tactic", "Credential Access"),
                        "source_ip": ip,
                        "affected_user": ", ".join(target_users),
                        "affected_host": host,
                        "timestamp": latest_ts,
                        "supporting_event_ids": supporting_ids,
                        "recommended_steps": "; ".join(rule_cfg.get("recommended_steps", [])),
                        "status": "New"
                    }
                    alerts.append(alert)
                    break  # Alert generated for this IP batch

        return alerts

    def detect_suspicious_login_patterns(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        RULE-003: Detects rapid attempts across multiple distinct accounts from one source IP.
        """
        rule_cfg = self.config.get("rules", {}).get("RULE-003", {})
        if not rule_cfg.get("enabled", True):
            return []

        user_threshold = rule_cfg.get("unique_user_threshold", 3)
        window_seconds = rule_cfg.get("time_window_seconds", 180)

        auth_events = [
            e for e in events
            if e.get("event_category") == "authentication"
            and e.get("scenario") != "baseline"
        ]

        by_ip: Dict[str, List[Dict[str, Any]]] = {}
        for e in auth_events:
            ip = e.get("source_ip", "0.0.0.0")
            by_ip.setdefault(ip, []).append(e)

        alerts = []
        for ip, ip_events in by_ip.items():
            ip_events.sort(key=lambda x: self._parse_ts(x["timestamp"]))

            window_start_idx = 0
            for i in range(len(ip_events)):
                current_time = self._parse_ts(ip_events[i]["timestamp"])
                while (current_time - self._parse_ts(ip_events[window_start_idx]["timestamp"])).total_seconds() > window_seconds:
                    window_start_idx += 1

                events_in_window = ip_events[window_start_idx : i + 1]
                unique_users = {evt.get("username") for evt in events_in_window if evt.get("username")}
                if len(unique_users) >= user_threshold:
                    supporting_ids = [evt["event_id"] for evt in events_in_window]
                    host = events_in_window[-1].get("hostname", "unknown-host")
                    latest_ts = events_in_window[-1]["timestamp"]

                    alert = {
                        "alert_id": f"ALT-SPRAY-{uuid.uuid4().hex[:8].upper()}",
                        "rule_id": "RULE-003",
                        "rule_name": rule_cfg.get("name", "Suspicious Login Pattern - Multiple Account Probing"),
                        "severity": rule_cfg.get("severity", "Medium"),
                        "description": f"Source IP {ip} probed {len(unique_users)} distinct user accounts ({', '.join(sorted(unique_users))}) within {window_seconds}s.",
                        "mitre_technique_id": rule_cfg.get("technique_id", "T1078"),
                        "mitre_technique_name": rule_cfg.get("technique_name", "Valid Accounts"),
                        "mitre_tactic": rule_cfg.get("tactic", "Defense Evasion / Initial Access"),
                        "source_ip": ip,
                        "affected_user": ", ".join(sorted(unique_users)),
                        "affected_host": host,
                        "timestamp": latest_ts,
                        "supporting_event_ids": supporting_ids,
                        "recommended_steps": "; ".join(rule_cfg.get("recommended_steps", [])),
                        "status": "New"
                    }
                    alerts.append(alert)
                    break

        return alerts

    def detect_port_scan(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        RULE-004: Detects network port scanning (connections to >= N distinct ports within window).
        """
        rule_cfg = self.config.get("rules", {}).get("RULE-004", {})
        if not rule_cfg.get("enabled", True):
            return []

        port_threshold = rule_cfg.get("port_threshold", 5)
        window_seconds = rule_cfg.get("time_window_seconds", 60)

        net_events = [
            e for e in events
            if e.get("event_category") == "network"
            and e.get("event_type") == "port_probe"
        ]

        by_ip: Dict[str, List[Dict[str, Any]]] = {}
        for e in net_events:
            ip = e.get("source_ip", "0.0.0.0")
            by_ip.setdefault(ip, []).append(e)

        alerts = []
        for ip, ip_events in by_ip.items():
            ip_events.sort(key=lambda x: self._parse_ts(x["timestamp"]))

            window_start_idx = 0
            for i in range(len(ip_events)):
                current_time = self._parse_ts(ip_events[i]["timestamp"])
                while (current_time - self._parse_ts(ip_events[window_start_idx]["timestamp"])).total_seconds() > window_seconds:
                    window_start_idx += 1

                events_in_window = ip_events[window_start_idx : i + 1]
                distinct_ports = {
                    evt.get("metadata", {}).get("dest_port")
                    for evt in events_in_window
                    if evt.get("metadata", {}).get("dest_port") is not None
                }
                if len(distinct_ports) >= port_threshold:
                    supporting_ids = [evt["event_id"] for evt in events_in_window]
                    host = events_in_window[-1].get("hostname", "unknown-host")
                    latest_ts = events_in_window[-1]["timestamp"]

                    alert = {
                        "alert_id": f"ALT-SCAN-{uuid.uuid4().hex[:8].upper()}",
                        "rule_id": "RULE-004",
                        "rule_name": rule_cfg.get("name", "Network Port Scanning / Host Reconnaissance"),
                        "severity": rule_cfg.get("severity", "Medium"),
                        "description": f"Source IP {ip} probed {len(distinct_ports)} distinct ports on {host} within {window_seconds}s.",
                        "mitre_technique_id": rule_cfg.get("technique_id", "T1046"),
                        "mitre_technique_name": rule_cfg.get("technique_name", "Network Service Discovery"),
                        "mitre_tactic": rule_cfg.get("tactic", "Discovery"),
                        "source_ip": ip,
                        "affected_user": "network_stack",
                        "affected_host": host,
                        "timestamp": latest_ts,
                        "supporting_event_ids": supporting_ids,
                        "recommended_steps": "; ".join(rule_cfg.get("recommended_steps", [])),
                        "status": "New"
                    }
                    alerts.append(alert)
                    break

        return alerts

    def detect_sudo_abuse(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        RULE-005: Detects unauthorized sudo attempts or suspicious commands executed via sudo.
        """
        rule_cfg = self.config.get("rules", {}).get("RULE-005", {})
        if not rule_cfg.get("enabled", True):
            return []

        suspicious_cmds = rule_cfg.get("suspicious_commands", [
            "/bin/bash", "/bin/sh", "chmod +s", "cat /etc/shadow", "su -", "passwd root"
        ])

        alerts = []
        for e in events:
            if e.get("event_category") == "process" and e.get("event_type") == "sudo_exec":
                cmd = str(e.get("metadata", {}).get("command", "")).strip()
                result = e.get("result", "")

                is_suspicious_cmd = any(s in cmd for s in suspicious_cmds)
                is_denied = result == "denied"

                if (is_suspicious_cmd or is_denied) and e.get("scenario") != "baseline":
                    user = e.get("username", "unknown-user")
                    host = e.get("hostname", "unknown-host")
                    ip = e.get("source_ip", "127.0.0.1")

                    reason = f"Attempted execution of suspicious command '{cmd}' via sudo" if is_suspicious_cmd else f"Unauthorized sudo privilege elevation attempt by '{user}' (Access Denied)"

                    alert = {
                        "alert_id": f"ALT-SUDO-{uuid.uuid4().hex[:8].upper()}",
                        "rule_id": "RULE-005",
                        "rule_name": rule_cfg.get("name", "Suspicious Privilege Escalation / Sudo Abuse"),
                        "severity": rule_cfg.get("severity", "High"),
                        "description": f"{reason} on host {host}.",
                        "mitre_technique_id": rule_cfg.get("technique_id", "T1548.003"),
                        "mitre_technique_name": rule_cfg.get("technique_name", "Sudo and Sudo Caching"),
                        "mitre_tactic": rule_cfg.get("tactic", "Privilege Escalation"),
                        "source_ip": ip,
                        "affected_user": user,
                        "affected_host": host,
                        "timestamp": e.get("timestamp"),
                        "supporting_event_ids": [e["event_id"]],
                        "recommended_steps": "; ".join(rule_cfg.get("recommended_steps", [])),
                        "status": "New"
                    }
                    alerts.append(alert)

        return alerts

    def detect_file_tampering(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        RULE-006: Detects sensitive file modification (e.g. /etc/shadow, /etc/passwd).
        """
        rule_cfg = self.config.get("rules", {}).get("RULE-006", {})
        if not rule_cfg.get("enabled", True):
            return []

        monitored_paths = set(rule_cfg.get("monitored_paths", [
            "/etc/shadow", "/etc/passwd", "/etc/sudoers", "/etc/ssh/sshd_config", "/var/log/auth.log"
        ]))

        alerts = []
        for e in events:
            if e.get("event_category") == "file" and e.get("action") == "modify":
                target_path = e.get("metadata", {}).get("filepath", "")
                if target_path in monitored_paths and e.get("scenario") != "baseline":
                    user = e.get("username", "root")
                    host = e.get("hostname", "unknown-host")
                    ip = e.get("source_ip", "127.0.0.1")

                    alert = {
                        "alert_id": f"ALT-FILE-{uuid.uuid4().hex[:8].upper()}",
                        "rule_id": "RULE-006",
                        "rule_name": rule_cfg.get("name", "Sensitive System File Modification"),
                        "severity": rule_cfg.get("severity", "Critical"),
                        "description": f"Critical security file '{target_path}' was modified on host {host} by user '{user}'.",
                        "mitre_technique_id": rule_cfg.get("technique_id", "T1565.001"),
                        "mitre_technique_name": rule_cfg.get("technique_name", "Stored Data Manipulation"),
                        "mitre_tactic": rule_cfg.get("tactic", "Impact / Persistence"),
                        "source_ip": ip,
                        "affected_user": user,
                        "affected_host": host,
                        "timestamp": e.get("timestamp"),
                        "supporting_event_ids": [e["event_id"]],
                        "recommended_steps": "; ".join(rule_cfg.get("recommended_steps", [])),
                        "status": "New"
                    }
                    alerts.append(alert)

        return alerts

    def detect_suspicious_process(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        RULE-007: Detects suspicious process execution / reverse shell spawning.
        """
        rule_cfg = self.config.get("rules", {}).get("RULE-007", {})
        if not rule_cfg.get("enabled", True):
            return []

        suspicious_patterns = rule_cfg.get("suspicious_patterns", [
            "/dev/tcp/", "nc -e", "nc -c", "ncat -e", "python -c import socket",
            "curl | bash", "wget | bash", "bash -i", "sh -i"
        ])

        alerts = []
        for e in events:
            if e.get("event_category") == "process" and e.get("event_type") == "process_spawn":
                cmd = e.get("metadata", {}).get("command_line", "")
                if any(p in cmd for p in suspicious_patterns) and e.get("scenario") != "baseline":
                    user = e.get("username", "unknown-user")
                    host = e.get("hostname", "unknown-host")
                    ip = e.get("source_ip", "0.0.0.0")

                    alert = {
                        "alert_id": f"ALT-SHELL-{uuid.uuid4().hex[:8].upper()}",
                        "rule_id": "RULE-007",
                        "rule_name": rule_cfg.get("name", "Suspicious Process Execution / Command Shell Spawning"),
                        "severity": rule_cfg.get("severity", "High"),
                        "description": f"Suspicious interactive shell or reverse socket command executed by '{user}' on {host}: '{cmd}'",
                        "mitre_technique_id": rule_cfg.get("technique_id", "T1059.004"),
                        "mitre_technique_name": rule_cfg.get("technique_name", "Unix Shell"),
                        "mitre_tactic": rule_cfg.get("tactic", "Execution"),
                        "source_ip": ip,
                        "affected_user": user,
                        "affected_host": host,
                        "timestamp": e.get("timestamp"),
                        "supporting_event_ids": [e["event_id"]],
                        "recommended_steps": "; ".join(rule_cfg.get("recommended_steps", [])),
                        "status": "New"
                    }
                    alerts.append(alert)

        return alerts

    def run_detection(self, events: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
        """
        Run all detection rules against provided events (or recent events from DB).
        Inserts new alerts into the SQLite database and returns the list of generated alerts.
        """
        if events is None:
            # Query recent events from SQLite
            events = self.db_manager.get_events(limit=5000)

        all_alerts: List[Dict[str, Any]] = []

        all_alerts.extend(self.detect_ssh_bruteforce(events))
        all_alerts.extend(self.detect_suspicious_login_patterns(events))
        all_alerts.extend(self.detect_port_scan(events))
        all_alerts.extend(self.detect_sudo_abuse(events))
        all_alerts.extend(self.detect_file_tampering(events))
        all_alerts.extend(self.detect_suspicious_process(events))

        # Save to SQLite database
        persisted_alerts = []
        for alert in all_alerts:
            inserted = self.db_manager.insert_alert(alert)
            if inserted:
                persisted_alerts.append(alert)

        return persisted_alerts
