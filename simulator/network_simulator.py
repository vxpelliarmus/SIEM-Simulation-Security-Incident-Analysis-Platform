"""
Network event simulation module for SOC-SIM.
Simulates network port scanning and service discovery.
"""

import uuid
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional


class NetworkSimulator:
    """Generates synthetic network reconnaissance and port scanning event sequences."""

    SCANNER_IP = "203.0.113.88"  # RFC 5737 TEST-NET-3 documentation IP
    TARGET_HOST = "srv-app-01"

    @staticmethod
    def generate_port_scan(
        source_ip: str = SCANNER_IP,
        target_host: str = TARGET_HOST,
        ports: Optional[List[int]] = None,
        base_time: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
        """
        Simulate a rapid TCP SYN port scan across multiple distinct service ports.
        """
        if base_time is None:
            base_time = datetime.now(timezone.utc) - timedelta(minutes=25)

        if ports is None:
            ports = [21, 22, 23, 25, 80, 110, 443, 445, 1433, 3306, 3389, 8080]

        events = []
        for i, port in enumerate(ports):
            event_time = base_time + timedelta(seconds=i * 2 + (i % 2))
            # Most ports are closed/denied; 22 and 80 might be open
            result = "allowed" if port in (22, 80) else "denied"
            tcp_flag = "SYN-ACK" if result == "allowed" else "RST"

            events.append({
                "event_id": f"EVT-NET-{uuid.uuid4().hex[:12].upper()}",
                "timestamp": event_time.isoformat(),
                "hostname": target_host,
                "username": "network_stack",
                "source_ip": source_ip,
                "event_category": "network",
                "event_type": "port_probe",
                "action": "connection_attempt",
                "result": result,
                "metadata": {
                    "dest_port": port,
                    "proto": "TCP",
                    "tcp_flags": f"SYN/{tcp_flag}",
                    "scanner_signature": "Nmap NSE script engine",
                    "bytes_sent": 60,
                    "bytes_received": 40 if result == "allowed" else 0
                },
                "scenario": "port_scan"
            })

        return events
