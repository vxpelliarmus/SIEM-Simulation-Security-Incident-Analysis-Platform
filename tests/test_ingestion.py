"""
Unit tests for log ingestion and normalization pipeline.
"""

import os
import json
import tempfile
import pytest
from datetime import datetime, timezone

from ingestion.normalizer import EventNormalizer
from ingestion.log_collector import LogCollector
from database.db_manager import DatabaseManager


class TestIngestion:

    def setup_method(self):
        # Create a temporary SQLite database for test isolation
        self.temp_db_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db = DatabaseManager(db_path=self.temp_db_file.name)
        self.temp_dir = tempfile.TemporaryDirectory()
        self.collector = LogCollector(db_manager=self.db, raw_archive_dir=self.temp_dir.name)

    def teardown_method(self):
        self.temp_db_file.close()
        if os.path.exists(self.temp_db_file.name):
            os.unlink(self.temp_db_file.name)
        self.temp_dir.cleanup()

    def test_parse_timestamp_formats(self):
        """Verify normalizer handles multiple timestamp representations."""
        # ISO with Z
        iso_z = EventNormalizer.parse_timestamp("2026-11-16T08:00:00Z")
        assert "2026-11-16T08:00:00+00:00" in iso_z or "2026-11-16T08:00:00" in iso_z

        # ISO with offset
        iso_offset = EventNormalizer.parse_timestamp("2026-11-16T10:00:00+02:00")
        assert "2026-11-16T08:00:00+00:00" in iso_offset

        # Epoch seconds (1700000000)
        epoch_sec = EventNormalizer.parse_timestamp(1700000000)
        assert "2023" in epoch_sec

        # Epoch milliseconds (1700000000000)
        epoch_ms = EventNormalizer.parse_timestamp(1700000000000)
        assert "2023" in epoch_ms

        # Empty / None
        empty_ts = EventNormalizer.parse_timestamp(None)
        assert isinstance(empty_ts, str) and len(empty_ts) > 10

    def test_normalize_clean_event(self):
        """Clean event retains all fields and reports clean status."""
        raw = {
            "event_id": "EVT-CLEAN-001",
            "timestamp": "2026-11-16T08:00:00Z",
            "hostname": "SRV-APP-01",
            "username": "root",
            "source_ip": "198.51.100.45",
            "event_category": "authentication",
            "event_type": "ssh_login",
            "action": "login_attempt",
            "result": "failure",
            "metadata": {"port": 22},
            "scenario": "ssh_bruteforce"
        }
        norm, is_clean = EventNormalizer.normalize_event(raw)
        assert is_clean is True
        assert norm["event_id"] == "EVT-CLEAN-001"
        assert norm["hostname"] == "srv-app-01"  # lowercased
        assert norm["source_ip"] == "198.51.100.45"
        assert norm["raw_json"] is not None

    def test_normalize_malformed_event(self):
        """Malformed event has fields repaired and is_clean=False."""
        raw_bad = {
            # Missing event_id
            "hostname": "srv-test",
            "source_ip": "not_an_ip",  # Invalid IP
            "metadata": "non-json-string"  # String instead of dict
        }
        norm, is_clean = EventNormalizer.normalize_event(raw_bad)
        assert is_clean is False
        assert norm["event_id"].startswith("EVT-NORM-")
        assert norm["source_ip"] == "0.0.0.0"
        assert isinstance(norm["metadata"], dict)

    def test_duplicate_prevention_on_ingestion(self):
        """Ingesting the exact same event batch twice must not cause duplicates in SQLite."""
        sample_events = [
            {
                "event_id": "EVT-DUP-01",
                "timestamp": "2026-11-16T08:00:00Z",
                "hostname": "srv-app-01",
                "username": "test_user",
                "source_ip": "192.168.1.100",
                "event_category": "authentication",
                "event_type": "ssh_login",
                "action": "login_attempt",
                "result": "success",
                "metadata": {},
                "scenario": "baseline"
            }
        ]

        # First ingestion
        res1 = self.collector.ingest_records(sample_events)
        assert res1["inserted"] == 1
        assert res1["duplicates"] == 0

        # Second ingestion of same record
        res2 = self.collector.ingest_records(sample_events)
        assert res2["inserted"] == 0
        assert res2["duplicates"] == 1

        # Check total rows in database
        events_in_db = self.db.get_events()
        assert len(events_in_db) == 1

    def test_ingest_json_file(self):
        """Test ingesting from a JSON file and verifying raw archive preservation."""
        test_file = os.path.join(self.temp_dir.name, "test_events.json")
        sample_events = [
            {
                "event_id": "EVT-FILE-TEST-1",
                "timestamp": "2026-11-16T08:00:00Z",
                "hostname": "srv-app-01",
                "username": "admin",
                "source_ip": "10.0.1.5",
                "event_category": "system",
                "event_type": "log_rotate",
                "action": "execute",
                "result": "success",
                "metadata": {},
                "scenario": "baseline"
            }
        ]
        with open(test_file, "w") as f:
            json.dump(sample_events, f)

        res = self.collector.ingest_file(test_file)
        assert res["inserted"] == 1

        # Verify archive created
        archived_files = os.listdir(self.temp_dir.name)
        assert any("test_events.json" in fn for fn in archived_files)
