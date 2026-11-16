"""
Demonstration script showing the full end-to-end SOC-SIM workflow:
1. Generate simulated SSH brute-force activity with breach
2. Ingest and normalize events into SQLite
3. Run detection and correlation engine to generate alerts
4. Verify alerts in database
5. Record analyst investigation notes
6. Automatically compile and save a formal incident report
"""

import os
import sys
import json

from database.db_manager import DatabaseManager
from simulator.event_generator import SecurityEventGenerator
from ingestion.log_collector import LogCollector
from detection.engine import DetectionEngine
from detection.correlation import EventCorrelator
from incident_reports.report_generator import IncidentReportGenerator


def run_demonstration():
    print("=" * 70)
    print("SOC-SIM: END-TO-END SECURITY INCIDENT WORKFLOW DEMONSTRATION")
    print("=" * 70)

    # Initialize components
    db = DatabaseManager()
    gen = SecurityEventGenerator()
    collector = LogCollector(db_manager=db)
    engine = DetectionEngine(db_manager=db)
    correlator = EventCorrelator(db_manager=db)
    reporter = IncidentReportGenerator()

    # Step 1: Generate simulated SSH brute-force activity + baseline noise
    print("\n[Step 1] Generating simulated events (Baseline telemetry + SSH Brute Force)...")
    baseline_events = gen.generate_baseline_events(count=20)
    attack_events = gen.generate_scenario("ssh_bruteforce", attempts=6, include_success=True)
    all_events = baseline_events + attack_events
    print(f"  -> Generated {len(baseline_events)} benign baseline events.")
    print(f"  -> Generated {len(attack_events)} attack events (SSH brute-force + credential compromise).")

    # Save to raw file to demonstrate file ingestion capability
    sample_file = os.path.join(os.path.dirname(__file__), "data", "raw", "demo_attack_batch.json")
    gen.save_events_to_file(all_events, sample_file)
    print(f"  -> Saved raw telemetry batch to: {sample_file}")

    # Step 2: Ingest & Normalize into SQLite
    print("\n[Step 2] Ingesting and normalizing events into SQLite store...")
    ingest_result = collector.ingest_file(sample_file)
    print(f"  -> Total records read: {ingest_result['total_read']}")
    print(f"  -> Inserted: {ingest_result['inserted']}")
    print(f"  -> Duplicate skipped: {ingest_result['duplicates']}")
    print(f"  -> Malformed: {ingest_result['malformed']}")

    # Step 3: Run Detection Engine
    print("\n[Step 3] Executing Detection Engine and Correlation Engine...")
    alerts = engine.run_detection()
    corr_alerts = correlator.correlate_failed_then_successful_login(attack_events)
    total_alerts = alerts + corr_alerts
    print(f"  -> Detection Engine triggered {len(alerts)} alerts.")
    print(f"  -> Correlation Engine triggered {len(corr_alerts)} compound alerts.")

    for i, a in enumerate(total_alerts, 1):
        print(f"     [{i}] {a['rule_id']}: {a['rule_name']} ({a['severity']}) - Target: {a['affected_host']} / {a['affected_user']}")

    # Step 4: Verify Database State
    stats = db.get_stats()
    print("\n[Step 4] Current SQLite Database Metrics:")
    print(f"  -> Total Events in DB: {stats['total_events']}")
    print(f"  -> Total Alerts in DB: {stats['total_alerts']}")
    print(f"  -> Critical Alerts: {stats['critical_alerts']}")
    print(f"  -> High Alerts: {stats['high_alerts']}")

    # Step 5: Incident Investigation & Analyst Notes
    print("\n[Step 5] SOC Analyst Triage & Investigation...")
    active_alerts = db.get_alerts()
    target_alert = next((a for a in active_alerts if a["rule_id"] in ("RULE-001", "RULE-002")), active_alerts[0])
    print(f"  -> Selected Alert for Investigation: {target_alert['alert_id']} ({target_alert['rule_name']})")

    # Update status and record notes
    db.update_alert_status(target_alert["alert_id"], "In Progress")
    db.add_analyst_note(
        target_alert["alert_id"],
        "Lead Analyst",
        "Confirmed 6 dictionary password attempts from 198.51.100.45 followed by authentication. Host isolated."
    )
    print("  -> Updated alert status to 'In Progress'.")
    print("  -> Persisted analyst forensic notes to SQLite.")

    # Step 6: Generate Incident Report in Markdown
    print("\n[Step 6] Compiling Formal SOC Incident Report...")
    supporting_events = [db.get_event_by_id(eid) for eid in target_alert.get("supporting_event_ids", [])]
    supporting_events = [e for e in supporting_events if e is not None]
    notes = db.get_analyst_notes(target_alert["alert_id"])

    incident_id = f"INC-DEMO-{target_alert['alert_id'].replace('ALT-', '')}"
    report_md = reporter.generate_report(
        incident_id=incident_id,
        alert=target_alert,
        supporting_events=supporting_events,
        analyst_notes=notes,
        analyst_name="Lead Analyst"
    )
    saved_report = reporter.save_report(incident_id, report_md)
    print(f"  -> Incident Report generated and saved to: {saved_report}")

    print("\n" + "=" * 70)
    print("WORKFLOW COMPLETE: All 6 stages executed successfully!")
    print("Launch dashboard via: streamlit run dashboard/app.py")
    print("=" * 70)


if __name__ == "__main__":
    run_demonstration()
