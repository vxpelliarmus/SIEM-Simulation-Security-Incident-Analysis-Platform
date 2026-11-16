"""
SOC-SIM: Interactive Security Operations Center (SOC) Dashboard.
Built with Streamlit, Plotly, Pandas, and SQLite.
"""

import os
import sys
import json
import sqlite3
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from datetime import datetime, timezone

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from database.db_manager import DatabaseManager
from simulator.event_generator import SecurityEventGenerator
from ingestion.log_collector import LogCollector
from detection.engine import DetectionEngine
from detection.correlation import EventCorrelator
from incident_reports.report_generator import IncidentReportGenerator

# ---------------------------------------------------------
# Streamlit Page Configuration
# ---------------------------------------------------------
st.set_page_config(
    page_title="SOC-SIM — Security Incident Analysis Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom High-Tech SOC Dark Theme Styling
st.markdown("""
<style>
    .main {
        background-color: #0b0f19;
        color: #e2e8f0;
    }
    .stMetric {
        background-color: #151d30;
        border: 1px solid #233150;
        border-radius: 8px;
        padding: 12px 16px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.4);
    }
    .badge-critical {
        background-color: #ff3366;
        color: white;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.8rem;
    }
    .badge-high {
        background-color: #ff6b4a;
        color: white;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.8rem;
    }
    .badge-medium {
        background-color: #f5a623;
        color: black;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.8rem;
    }
    .badge-low {
        background-color: #00b4d8;
        color: white;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.8rem;
    }
    .card {
        background-color: #151d30;
        border: 1px solid #233150;
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 16px;
    }
</style>
""", unsafe_allow_html=True)


# Initialize Core Services
@st.cache_resource
def get_services():
    db = DatabaseManager()
    gen = SecurityEventGenerator()
    collector = LogCollector(db_manager=db)
    engine = DetectionEngine(db_manager=db)
    correlator = EventCorrelator(db_manager=db)
    reporter = IncidentReportGenerator()
    return db, gen, collector, engine, correlator, reporter

db, generator, collector, engine, correlator, reporter = get_services()


# ---------------------------------------------------------
# Sidebar Navigation & Platform Status
# ---------------------------------------------------------
st.sidebar.image("https://img.icons8.com/fluency/96/shield.png", width=64)
st.sidebar.title("SOC-SIM")
st.sidebar.caption("SIEM Simulation & Security Incident Analysis")

st.sidebar.markdown("---")
page = st.sidebar.radio(
    "Navigation",
    [
        "📊 SOC Overview",
        "🔍 Event Explorer",
        "🚨 Alert Center",
        "🛡️ Threat Intelligence & MITRE",
        "🕵️ Incident Investigation",
        "⚙️ Simulation Control"
    ]
)

st.sidebar.markdown("---")
# Quick DB Metrics in Sidebar
stats = db.get_stats()
st.sidebar.markdown(f"**Total Events:** `{stats['total_events']:,}`")
st.sidebar.markdown(f"**Total Alerts:** `{stats['total_alerts']:,}`")
st.sidebar.caption("Environment: Kali Linux Local Simulation")
st.sidebar.caption("Telemetry: Synthetic RFC-5737")


# ---------------------------------------------------------
# PAGE 1: SOC OVERVIEW
# ---------------------------------------------------------
if page == "📊 SOC Overview":
    st.title("🛡️ Security Operations Center Overview")
    st.markdown("Real-time monitoring and aggregate security metrics from SQLite telemetry store.")

    # KPI Metric Cards
    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.metric("Total Events", f"{stats['total_events']:,}")
    with col2:
        st.metric("Total Alerts", f"{stats['total_alerts']:,}")
    with col3:
        st.metric("Critical Alerts", f"{stats['critical_alerts']:,}", delta_color="inverse")
    with col4:
        st.metric("High Alerts", f"{stats['high_alerts']:,}", delta_color="inverse")
    with col5:
        st.metric("Medium/Low Alerts", f"{stats['medium_alerts'] + stats['low_alerts']:,}")

    st.markdown("---")

    if stats["total_events"] == 0:
        st.info("💡 The database currently contains no events. Navigate to **⚙️ Simulation Control** to generate simulation traffic or baseline events.")
    else:
        # Load events for visualizations
        events_raw = db.get_events(limit=5000)
        df_events = pd.DataFrame(events_raw)

        chart_col1, chart_col2 = st.columns([2, 1])

        with chart_col1:
            st.subheader("📈 Security Event Ingestion Timeline")
            if not df_events.empty and "timestamp" in df_events.columns:
                df_events["dt"] = pd.to_datetime(df_events["timestamp"], errors="coerce")
                df_ts = df_events.dropna(subset=["dt"]).set_index("dt")
                df_resampled = df_ts.resample("1min").count()["event_id"].reset_index()
                df_resampled.columns = ["Timestamp", "Event Count"]

                fig_line = px.line(
                    df_resampled,
                    x="Timestamp",
                    y="Event Count",
                    template="plotly_dark",
                    title="Events Processed per Minute",
                    markers=True
                )
                fig_line.update_traces(line_color="#00e5ff")
                fig_line.update_layout(
                    paper_bgcolor="#111827",
                    plot_bgcolor="#111827",
                    margin=dict(l=20, r=20, t=40, b=20)
                )
                st.plotly_chart(fig_line, use_container_width=True)

        with chart_col2:
            st.subheader("🎯 Alerts by Severity")
            alerts_data = stats["severity_breakdown"]
            if alerts_data:
                fig_donut = px.pie(
                    names=list(alerts_data.keys()),
                    values=list(alerts_data.values()),
                    hole=0.55,
                    template="plotly_dark",
                    color=list(alerts_data.keys()),
                    color_discrete_map={
                        "Critical": "#ff3366",
                        "High": "#ff6b4a",
                        "Medium": "#f5a623",
                        "Low": "#00b4d8",
                        "Informational": "#7b2cbf"
                    }
                )
                fig_donut.update_layout(
                    paper_bgcolor="#111827",
                    plot_bgcolor="#111827",
                    margin=dict(l=20, r=20, t=40, b=20)
                )
                st.plotly_chart(fig_donut, use_container_width=True)
            else:
                st.write("No alerts recorded.")

        chart_col3, chart_col4 = st.columns(2)

        with chart_col3:
            st.subheader("📊 Event Distribution by Scenario")
            scen_data = stats["scenario_breakdown"]
            if scen_data:
                fig_scen = px.bar(
                    x=list(scen_data.keys()),
                    y=list(scen_data.values()),
                    template="plotly_dark",
                    labels={"x": "Simulation Scenario", "y": "Total Events"},
                    color=list(scen_data.keys()),
                    color_discrete_sequence=px.colors.qualitative.Dark24
                )
                fig_scen.update_layout(
                    showlegend=False,
                    paper_bgcolor="#111827",
                    plot_bgcolor="#111827",
                    margin=dict(l=20, r=20, t=40, b=20)
                )
                st.plotly_chart(fig_scen, use_container_width=True)

        with chart_col4:
            st.subheader("🚨 Alert Status Distribution")
            status_data = stats["status_breakdown"]
            if status_data:
                fig_status = px.bar(
                    x=list(status_data.keys()),
                    y=list(status_data.values()),
                    template="plotly_dark",
                    labels={"x": "Alert Status", "y": "Count"},
                    color_discrete_sequence=["#10b981"]
                )
                fig_status.update_layout(
                    paper_bgcolor="#111827",
                    plot_bgcolor="#111827",
                    margin=dict(l=20, r=20, t=40, b=20)
                )
                st.plotly_chart(fig_status, use_container_width=True)

        st.subheader("🔔 Recent Security Alerts")
        recent_alerts = db.get_alerts(limit=5)
        if recent_alerts:
            df_recent = pd.DataFrame(recent_alerts)[[
                "alert_id", "severity", "rule_name", "source_ip", "affected_user", "timestamp", "status"
            ]]
            st.dataframe(df_recent, use_container_width=True)


# ---------------------------------------------------------
# PAGE 2: EVENT EXPLORER
# ---------------------------------------------------------
elif page == "🔍 Event Explorer":
    st.title("🔍 Security Event Explorer")
    st.markdown("Search, filter, and drill into raw and normalized security telemetry records.")

    # Filter Controls
    f_col1, f_col2, f_col3, f_col4 = st.columns(4)
    with f_col1:
        search_kw = st.text_input("Text Search", placeholder="IP, host, user, keyword...")
    with f_col2:
        cat_filter = st.selectbox("Category", ["All", "authentication", "network", "process", "file", "system"])
    with f_col3:
        scen_filter = st.selectbox("Scenario", ["All", "baseline", "ssh_bruteforce", "suspicious_login", "port_scan", "privilege_escalation", "file_modification", "suspicious_process"])
    with f_col4:
        result_filter = st.selectbox("Result", ["All", "success", "failure", "denied", "allowed", "modified"])

    events = db.get_events(
        limit=500,
        category=None if cat_filter == "All" else cat_filter,
        scenario=None if scen_filter == "All" else scen_filter,
        result=None if result_filter == "All" else result_filter,
        search_query=search_kw if search_kw.strip() else None
    )

    st.markdown(f"**Found {len(events)} matching events** (showing up to 500)")

    if events:
        df_display = pd.DataFrame(events)[[
            "event_id", "timestamp", "hostname", "username", "source_ip",
            "event_category", "event_type", "action", "result", "scenario"
        ]]
        st.dataframe(df_display, use_container_width=True)

        st.markdown("---")
        st.subheader("🔬 Event Inspection & Raw Record Viewer")
        selected_event_id = st.selectbox("Select Event ID to inspect:", [e["event_id"] for e in events])
        selected_event = next((e for e in events if e["event_id"] == selected_event_id), None)

        if selected_event:
            view_col1, view_col2 = st.columns(2)
            with view_col1:
                st.markdown("##### Normalized Event Structure")
                st.json(selected_event)
            with view_col2:
                st.markdown("##### Original Raw JSON Representation")
                raw_str = selected_event.get("raw_json") or "{}"
                try:
                    st.json(json.loads(raw_str))
                except Exception:
                    st.text(raw_str)


# ---------------------------------------------------------
# PAGE 3: ALERT CENTER
# ---------------------------------------------------------
elif page == "🚨 Alert Center":
    st.title("🚨 Alert Center & Triage")
    st.markdown("Manage detection engine alerts, view supporting evidence, and track investigation status.")

    al_col1, al_col2 = st.columns(2)
    with al_col1:
        sev_filter = st.selectbox("Filter Severity", ["All", "Critical", "High", "Medium", "Low"])
    with al_col2:
        status_filter = st.selectbox("Filter Status", ["All", "New", "In Progress", "Closed - True Positive", "Closed - False Positive"])

    alerts = db.get_alerts(
        severity=None if sev_filter == "All" else sev_filter,
        status=None if status_filter == "All" else status_filter
    )

    st.markdown(f"**Active Alerts: {len(alerts)}**")

    if alerts:
        df_al = pd.DataFrame(alerts)[[
            "alert_id", "severity", "rule_id", "rule_name", "mitre_technique_id",
            "source_ip", "affected_user", "affected_host", "timestamp", "status"
        ]]
        st.dataframe(df_al, use_container_width=True)

        st.markdown("---")
        st.subheader("📋 Alert Detail & Status Management")
        selected_alert_id = st.selectbox("Select Alert to Triage:", [a["alert_id"] for a in alerts])
        selected_alert = next((a for a in alerts if a["alert_id"] == selected_alert_id), None)

        if selected_alert:
            ad_col1, ad_col2 = st.columns([2, 1])
            with ad_col1:
                st.markdown(f"#### **{selected_alert['rule_name']}** (`{selected_alert['rule_id']}`)")
                st.markdown(f"**Description:** {selected_alert['description']}")
                st.markdown(f"**MITRE ATT&CK:** `{selected_alert['mitre_technique_id']}` - *{selected_alert['mitre_technique_name']}* ({selected_alert['mitre_tactic']})")
                st.markdown(f"**Host:** `{selected_alert['affected_host']}` | **User:** `{selected_alert['affected_user']}` | **Source IP:** `{selected_alert['source_ip']}`")
                st.markdown(f"**Recommended Steps:** {selected_alert.get('recommended_steps', 'None provided')}")

                # Supporting Events Evidence
                supporting_ids = selected_alert.get("supporting_event_ids", [])
                st.markdown(f"**Supporting Log Evidence ({len(supporting_ids)} events):**")
                if supporting_ids:
                    supp_events = [db.get_event_by_id(eid) for eid in supporting_ids]
                    supp_events = [se for se in supp_events if se is not None]
                    if supp_events:
                        st.dataframe(pd.DataFrame(supp_events)[[
                            "event_id", "timestamp", "event_type", "result", "metadata"
                        ]], use_container_width=True)

            with ad_col2:
                st.markdown("##### Update Alert Status")
                current_status = selected_alert.get("status", "New")
                new_status = st.selectbox(
                    "Change Status to:",
                    ["New", "In Progress", "Closed - True Positive", "Closed - False Positive"],
                    index=["New", "In Progress", "Closed - True Positive", "Closed - False Positive"].index(current_status)
                )

                if st.button("Save Alert Status", key="btn_save_status"):
                    db.update_alert_status(selected_alert["alert_id"], new_status)
                    st.success(f"Status updated to: {new_status}")
                    st.rerun()


# ---------------------------------------------------------
# PAGE 4: THREAT INTELLIGENCE & MITRE
# ---------------------------------------------------------
elif page == "🛡️ Threat Intelligence & MITRE":
    st.title("🛡️ Threat Intelligence & MITRE ATT&CK Mapping")
    st.info("ℹ️ **Notice:** Curated reference intelligence mapping for educational security simulation. No external live threat intelligence feeds are connected.")

    st.markdown("""
    The SOC-SIM platform maps detection rules, simulation behaviors, and analyst reports directly to the **MITRE ATT&CK Enterprise Matrix**.
    """)

    mitre_data = [
        {
            "Technique ID": "T1110",
            "Technique Name": "Brute Force",
            "Tactic": "Credential Access",
            "Simulated Scenario": "SSH Brute Force",
            "Detection Rule": "RULE-001 (SSH Brute Force)",
            "Severity": "High",
            "Description": "Adversaries may use brute force techniques to attempt authentication credentials."
        },
        {
            "Technique ID": "T1110.001",
            "Technique Name": "Password Guessing",
            "Tactic": "Initial Access / Credential Access",
            "Simulated Scenario": "SSH Brute Force with Breach",
            "Detection Rule": "RULE-002 (Failed Then Success Login)",
            "Severity": "Critical",
            "Description": "Adversaries may systematically guess passwords to gain unauthorized access."
        },
        {
            "Technique ID": "T1078",
            "Technique Name": "Valid Accounts",
            "Tactic": "Defense Evasion / Initial Access",
            "Simulated Scenario": "Suspicious Login / Account Probing",
            "Detection Rule": "RULE-003 (Multiple Account Probing)",
            "Severity": "Medium",
            "Description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access."
        },
        {
            "Technique ID": "T1046",
            "Technique Name": "Network Service Discovery",
            "Tactic": "Discovery",
            "Simulated Scenario": "Network Port Scanning",
            "Detection Rule": "RULE-004 (Port Scan Reconnaissance)",
            "Severity": "Medium",
            "Description": "Adversaries may attempt to get a listing of services running on remote hosts."
        },
        {
            "Technique ID": "T1548.003",
            "Technique Name": "Sudo and Sudo Caching",
            "Tactic": "Privilege Escalation",
            "Simulated Scenario": "Privilege Escalation",
            "Detection Rule": "RULE-005 (Sudo Abuse)",
            "Severity": "High",
            "Description": "Adversaries may perform sudo caching and/or use sudoers configuration to elevate privileges."
        },
        {
            "Technique ID": "T1565.001",
            "Technique Name": "Stored Data Manipulation",
            "Tactic": "Impact / Persistence",
            "Simulated Scenario": "Sensitive File Modification",
            "Detection Rule": "RULE-006 (File Modification)",
            "Severity": "Critical",
            "Description": "Adversaries may insert or modify stored data (/etc/shadow, /etc/passwd) to disrupt system integrity."
        },
        {
            "Technique ID": "T1059.004",
            "Technique Name": "Unix Shell",
            "Tactic": "Execution",
            "Simulated Scenario": "Suspicious Process Execution",
            "Detection Rule": "RULE-007 (Reverse Shell / Spawning)",
            "Severity": "High",
            "Description": "Adversaries may abuse Unix shell commands and scripting interpreters for command execution."
        }
    ]

    df_mitre = pd.DataFrame(mitre_data)
    st.dataframe(df_mitre, use_container_width=True)

    st.markdown("---")
    st.subheader("📊 ATT&CK Tactics Coverage Visualization")

    tactics_summary = {
        "Discovery": 1,
        "Credential Access": 2,
        "Initial Access": 2,
        "Privilege Escalation": 1,
        "Execution": 1,
        "Persistence / Impact": 1
    }

    fig_cov = px.bar(
        x=list(tactics_summary.keys()),
        y=list(tactics_summary.values()),
        template="plotly_dark",
        labels={"x": "ATT&CK Tactic", "y": "Implemented Rules"},
        color=list(tactics_summary.keys()),
        color_discrete_sequence=px.colors.sequential.Tealgrn
    )
    fig_cov.update_layout(
        showlegend=False,
        paper_bgcolor="#111827",
        plot_bgcolor="#111827",
        margin=dict(l=20, r=20, t=30, b=20)
    )
    st.plotly_chart(fig_cov, use_container_width=True)


# ---------------------------------------------------------
# PAGE 5: INCIDENT INVESTIGATION
# ---------------------------------------------------------
elif page == "🕵️ Incident Investigation":
    st.title("🕵️ Incident Investigation & Case Dossier")
    st.markdown("Conduct deep-dive forensic investigation, reconstruct chronological kill-chain timelines, record analyst notes, and compile formal incident reports.")

    alerts = db.get_alerts()
    if not alerts:
        st.warning("No alerts available to investigate. Generate simulated activity in the **⚙️ Simulation Control** page.")
    else:
        alert_options = {f"{a['alert_id']} — {a['rule_name']} ({a['severity']})": a['alert_id'] for a in alerts}
        selected_label = st.selectbox("Select Incident / Alert to Investigate:", list(alert_options.keys()))
        selected_id = alert_options[selected_label]
        alert = db.get_alert_by_id(selected_id)

        if alert:
            # Investigation Header
            inv_col1, inv_col2, inv_col3 = st.columns(3)
            with inv_col1:
                st.markdown(f"**Target Host:** `{alert['affected_host']}`")
                st.markdown(f"**Affected Account:** `{alert['affected_user']}`")
            with inv_col2:
                st.markdown(f"**Source IP:** `{alert['source_ip']}`")
                st.markdown(f"**Severity:** `{alert['severity']}`")
            with inv_col3:
                st.markdown(f"**Trigger Time:** `{alert['timestamp']}`")
                st.markdown(f"**Status:** `{alert['status']}`")

            st.markdown("---")

            # Timeline Reconstruction
            st.subheader("⏱️ Chronological Event Reconstruction")
            supporting_ids = alert.get("supporting_event_ids", [])
            supporting_events = [db.get_event_by_id(eid) for eid in supporting_ids]
            supporting_events = [e for e in supporting_events if e is not None]
            supporting_events.sort(key=lambda x: x.get("timestamp", ""))

            if supporting_events:
                df_supp = pd.DataFrame(supporting_events)[[
                    "timestamp", "hostname", "username", "source_ip", "event_category", "event_type", "result"
                ]]
                st.dataframe(df_supp, use_container_width=True)
            else:
                st.write("No supporting log events attached to this alert.")

            st.markdown("---")

            # Analyst Notes & Observations
            note_col1, note_col2 = st.columns(2)
            with note_col1:
                st.subheader("📝 Analyst Notes & Collaboration")
                existing_notes = db.get_analyst_notes(alert["alert_id"])
                if existing_notes:
                    for n in existing_notes:
                        st.markdown(f"**{n['analyst_name']}** (`{n['created_at']}`):")
                        st.info(n['note'])
                else:
                    st.caption("No notes recorded for this alert yet.")

            with note_col2:
                st.subheader("➕ Add Analyst Observation")
                analyst_name = st.text_input("Analyst Name", value="Security Analyst")
                note_text = st.text_area("Observation / Forensic Finding", placeholder="e.g. Confirmed source IP is non-standard. Correlated with auth failure spikes...")
                if st.button("Add Observation Note"):
                    if note_text.strip():
                        db.add_analyst_note(alert["alert_id"], analyst_name, note_text.strip())
                        st.success("Analyst note persisted to SQLite.")
                        st.rerun()

            st.markdown("---")

            # Incident Report Compilation
            st.subheader("📄 Automated Incident Report Generation")
            st.markdown("Generate a comprehensive SOC Incident Report in Markdown adhering to NIST/SANS incident handling guidelines.")

            incident_id = f"INC-{alert['alert_id'].replace('ALT-', '')}"
            if st.button("Generate & Preview Incident Report", type="primary"):
                report_md = reporter.generate_report(
                    incident_id=incident_id,
                    alert=alert,
                    supporting_events=supporting_events,
                    analyst_notes=existing_notes,
                    analyst_name=analyst_name
                )
                saved_path = reporter.save_report(incident_id, report_md)

                st.success(f"Report compiled and saved to `{saved_path}`")
                st.markdown("### Report Preview")
                st.markdown(report_md)

                st.download_button(
                    label="📥 Download Incident Report (.md)",
                    data=report_md,
                    file_name=f"{incident_id}.md",
                    mime="text/markdown"
                )


# ---------------------------------------------------------
# PAGE 6: SIMULATION CONTROL
# ---------------------------------------------------------
elif page == "⚙️ Simulation Control":
    st.title("⚙️ Security Simulation Control Panel")
    st.markdown("Execute controlled, synthetic attack scenarios and baseline traffic through the end-to-end SIEM pipeline.")

    sim_box = st.container()
    with sim_box:
        st.subheader("🚀 Run Security Scenario")

        col_s1, col_s2 = st.columns(2)
        with col_s1:
            scenario_choice = st.selectbox(
                "Select Simulation Scenario:",
                [
                    "Multi-Stage Cyber Attack (Full Kill-Chain)",
                    "SSH Brute Force (T1110)",
                    "SSH Brute Force + Compromise (T1110.001)",
                    "Suspicious Login / Account Probing (T1078)",
                    "Network Port Scanning (T1046)",
                    "Privilege Escalation / Sudo Abuse (T1548.003)",
                    "Sensitive File Modification (T1565.001)",
                    "Suspicious Process Execution / Reverse Shell (T1059.004)",
                    "Baseline Background Telemetry (Normal Activity)"
                ]
            )

        with col_s2:
            event_vol = st.slider("Event Volume Multiplier", min_value=1, max_value=5, value=1)

        run_btn = st.button("▶️ Execute Simulation Pipeline", type="primary")

        if run_btn:
            with st.spinner("Executing simulation, ingestion, normalization, detection, and correlation..."):
                generated_events = []

                if scenario_choice == "Multi-Stage Cyber Attack (Full Kill-Chain)":
                    generated_events = generator.generate_scenario("multi_stage_attack")
                elif scenario_choice == "SSH Brute Force (T1110)":
                    generated_events = generator.generate_scenario("ssh_bruteforce", attempts=6 * event_vol, include_success=False)
                elif scenario_choice == "SSH Brute Force + Compromise (T1110.001)":
                    generated_events = generator.generate_scenario("ssh_bruteforce", attempts=5 * event_vol, include_success=True)
                elif scenario_choice == "Suspicious Login / Account Probing (T1078)":
                    generated_events = generator.generate_scenario("suspicious_login")
                elif scenario_choice == "Network Port Scanning (T1046)":
                    generated_events = generator.generate_scenario("port_scan")
                elif scenario_choice == "Privilege Escalation / Sudo Abuse (T1548.003)":
                    generated_events = generator.generate_scenario("privilege_escalation")
                elif scenario_choice == "Sensitive File Modification (T1565.001)":
                    generated_events = generator.generate_scenario("file_modification")
                elif scenario_choice == "Suspicious Process Execution / Reverse Shell (T1059.004)":
                    generated_events = generator.generate_scenario("suspicious_process")
                elif scenario_choice == "Baseline Background Telemetry (Normal Activity)":
                    generated_events = generator.generate_scenario("baseline", count=30 * event_vol)

                # 1. Ingest & Normalize
                ingest_res = collector.ingest_records(generated_events)

                # 2. Run Detection Engine
                new_alerts = engine.run_detection()

                # 3. Run Correlation Engine
                corr_alerts = correlator.correlate_failed_then_successful_login(generated_events)
                new_alerts.extend(corr_alerts)

                if scenario_choice == "Multi-Stage Cyber Attack (Full Kill-Chain)":
                    correlator.correlate_multi_stage_campaign(generated_events)

                st.success(
                    f"Pipeline Execution Complete! Generated {len(generated_events)} events | "
                    f"Inserted: {ingest_res['inserted']} | Duplicates: {ingest_res['duplicates']} | "
                    f"New Alerts Triggered: {len(new_alerts)}"
                )

                if new_alerts:
                    st.markdown("##### 🚨 New Alerts Triggered During This Run:")
                    st.dataframe(pd.DataFrame(new_alerts)[[
                        "alert_id", "severity", "rule_name", "source_ip", "affected_user"
                    ]])

    st.markdown("---")

    # Database Reset Section
    st.subheader("🧹 Reset & Purge Simulation Telemetry")
    st.warning("Purging the database permanently clears all events, alerts, analyst notes, and incidents.")
    confirm_purge = st.checkbox("I confirm that I want to purge all simulation data.")

    if st.button("🗑️ Reset Database", disabled=not confirm_purge):
        db.clear_all_data()
        st.success("Database wiped successfully. Clean environment restored.")
        st.rerun()
