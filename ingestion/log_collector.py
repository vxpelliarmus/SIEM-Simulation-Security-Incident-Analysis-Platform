"""
Log collector module for SOC-SIM.
Reads JSON log files, coordinates normalization, archives raw logs,
and loads normalized events into SQLite while rejecting duplicates.
"""

import os
import json
import shutil
from datetime import datetime, timezone
from typing import List, Dict, Any, Union, Optional

from .normalizer import EventNormalizer
from database.db_manager import DatabaseManager


class LogCollector:
    """Manages the ingestion pipeline from raw log files/streams into the normalized SQLite store."""

    def __init__(self, db_manager: Optional[DatabaseManager] = None, raw_archive_dir: Optional[str] = None):
        self.db_manager = db_manager or DatabaseManager()
        self.raw_archive_dir = raw_archive_dir or os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "data",
            "raw"
        )
        os.makedirs(self.raw_archive_dir, exist_ok=True)

    def ingest_file(self, filepath: str) -> Dict[str, Any]:
        """
        Ingest a JSON or JSONL log file.
        Archives the raw file in data/raw/, normalizes events, and commits them to SQLite.
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Log file not found: {filepath}")

        # Archive raw file
        filename = os.path.basename(filepath)
        timestamp_prefix = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        archive_dest = os.path.join(self.raw_archive_dir, f"{timestamp_prefix}_{filename}")
        try:
            shutil.copy2(filepath, archive_dest)
        except Exception:
            pass

        # Parse records
        raw_records = []
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read().strip()
            if not content:
                return {"total_read": 0, "inserted": 0, "duplicates": 0, "malformed": 0}

            # Check if JSON lines or JSON array/object
            if content.startswith("[") and content.endswith("]"):
                raw_records = json.loads(content)
            elif content.startswith("{") and not "\n{" in content:
                raw_records = [json.loads(content)]
            else:
                # Process line by line
                for line in content.splitlines():
                    line = line.strip()
                    if line:
                        try:
                            raw_records.append(json.loads(line))
                        except Exception:
                            # Malformed line record
                            raw_records.append({"raw_line": line})

        return self.ingest_records(raw_records)

    def ingest_records(self, records: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Ingest an in-memory list of raw or pre-structured event records.
        """
        if not records:
            return {"total_read": 0, "inserted": 0, "duplicates": 0, "malformed": 0}

        normalized_events = []
        malformed_count = 0

        for r in records:
            norm_event, is_clean = EventNormalizer.normalize_event(r)
            if not is_clean:
                malformed_count += 1
            normalized_events.append(norm_event)

        inserted_count = self.db_manager.insert_events(normalized_events)
        duplicate_count = len(normalized_events) - inserted_count

        return {
            "total_read": len(records),
            "inserted": inserted_count,
            "duplicates": duplicate_count,
            "malformed": malformed_count,
            "normalized_events": normalized_events
        }
