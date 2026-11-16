"""
Event normalizer for SOC-SIM.
Validates schemas, normalizes timestamps to ISO-8601 UTC, sanitizes fields,
and handles missing or malformed attributes gracefully.
"""

import re
import json
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Tuple


class EventNormalizer:
    """Normalizes raw heterogeneous security logs into a consistent schema."""

    @staticmethod
    def parse_timestamp(raw_ts: Any) -> str:
        """
        Convert diverse timestamp formats into a uniform ISO-8601 UTC string.
        Supports ISO-8601 strings, UNIX epoch seconds/ms, and standard SQL datetime strings.
        """
        if not raw_ts:
            return datetime.now(timezone.utc).isoformat()

        if isinstance(raw_ts, (int, float)):
            # Epoch milliseconds or seconds
            if raw_ts > 1e11:  # likely milliseconds
                raw_ts = raw_ts / 1000.0
            try:
                dt = datetime.fromtimestamp(raw_ts, tz=timezone.utc)
                return dt.isoformat()
            except Exception:
                return datetime.now(timezone.utc).isoformat()

        if isinstance(raw_ts, str):
            clean_ts = raw_ts.strip()
            # Standard ISO formats
            try:
                if clean_ts.endswith("Z"):
                    clean_ts = clean_ts[:-1] + "+00:00"
                dt = datetime.fromisoformat(clean_ts)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc).isoformat()
            except Exception:
                pass

            # Try common syslog / Apache / custom formats
            for fmt in (
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%d %H:%M:%S.%f",
                "%b %d %H:%M:%S",
                "%d/%b/%Y:%H:%M:%S %z"
            ):
                try:
                    dt = datetime.strptime(clean_ts, fmt)
                    if dt.year == 1900:  # syslog without year
                        dt = dt.replace(year=datetime.now(timezone.utc).year)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    return dt.astimezone(timezone.utc).isoformat()
                except Exception:
                    continue

        return datetime.now(timezone.utc).isoformat()

    @classmethod
    def normalize_event(cls, raw: Dict[str, Any]) -> Tuple[Dict[str, Any], bool]:
        """
        Normalize a raw event into a standardized SOC-SIM event dictionary.
        Returns a tuple: (normalized_event_dict, is_clean).
        """
        if not isinstance(raw, dict):
            raw = {"unparsed_payload": str(raw)}

        is_clean = True

        # Preserve the original raw representation
        raw_repr = json.dumps(raw)

        # 1. Event ID
        event_id = raw.get("event_id")
        if not event_id or not isinstance(event_id, str):
            event_id = f"EVT-NORM-{uuid.uuid4().hex[:12].upper()}"
            is_clean = False

        # 2. Timestamp normalization
        timestamp = cls.parse_timestamp(raw.get("timestamp"))

        # 3. Hostname sanitization
        hostname = str(raw.get("hostname", "unknown-host")).strip().lower()

        # 4. Username sanitization
        username = str(raw.get("username", "unknown-user")).strip()

        # 5. Source IP validation / sanitization
        raw_ip = str(raw.get("source_ip", "0.0.0.0")).strip()
        # Basic IPv4 format check
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", raw_ip):
            source_ip = "0.0.0.0"
            is_clean = False
        else:
            source_ip = raw_ip

        # 6. Event Category, Type, Action, Result
        category = str(raw.get("event_category", "system")).strip().lower()
        event_type = str(raw.get("event_type", "unknown")).strip().lower()
        action = str(raw.get("action", "unknown")).strip().lower()
        result = str(raw.get("result", "unknown")).strip().lower()

        # 7. Metadata handling
        meta = raw.get("metadata")
        if isinstance(meta, str):
            try:
                metadata = json.loads(meta)
            except Exception:
                metadata = {"raw_metadata_string": meta}
                is_clean = False
        elif isinstance(meta, dict):
            metadata = meta
        else:
            metadata = {}
            if meta is not None:
                is_clean = False

        # 8. Scenario tag
        scenario = str(raw.get("scenario", "unclassified")).strip().lower()

        normalized = {
            "event_id": event_id,
            "timestamp": timestamp,
            "hostname": hostname,
            "username": username,
            "source_ip": source_ip,
            "event_category": category,
            "event_type": event_type,
            "action": action,
            "result": result,
            "metadata": metadata,
            "scenario": scenario,
            "raw_json": raw_repr
        }

        return normalized, is_clean
