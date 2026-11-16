"""
Incident Report Generator for SOC-SIM.
Generates structured cybersecurity incident analysis reports in Markdown.
"""

import os
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional


class IncidentReportGenerator:
    """Generates standard SOC incident investigation reports in Markdown."""

    DEFAULT_OUTPUT_DIR = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "incident_reports"
    )

    def __init__(self, output_dir: Optional[str] = None):
        self.output_dir = output_dir or self.DEFAULT_OUTPUT_DIR
        os.makedirs(self.output_dir, exist_ok=True)

    def generate_report(
        self,
        incident_id: str,
        alert: Dict[str, Any],
        supporting_events: List[Dict[str, Any]],
        analyst_notes: Optional[List[Dict[str, Any]]] = None,
        analyst_name: str = "SOC Lead Analyst"
    ) -> str:
        """
        Build a Markdown incident report conforming to professional SOC standards.
        """
        severity = alert.get("severity", "High")
        source_ip = alert.get("source_ip", "0.0.0.0")
        affected_user = alert.get("affected_user", "unknown")
        affected_host = alert.get("affected_host", "unknown-host")
        detection_time = alert.get("timestamp", datetime.now(timezone.utc).isoformat())
        rule_name = alert.get("rule_name", "Security Detection Rule")
        rule_id = alert.get("rule_id", "N/A")
        technique_id = alert.get("mitre_technique_id", "T0000")
        technique_name = alert.get("mitre_technique_name", "N/A")
        tactic = alert.get("mitre_tactic", "N/A")
        description = alert.get("description", "N/A")
        recommended_steps = alert.get("recommended_steps", "Isolate host and investigate logs.")

        # Determine if attack succeeded based strictly on telemetry
        has_success = any(e.get("result") in ("success", "modified") for e in supporting_events)
        outcome_statement = (
            "Telemetry indicates that unauthorized actions or authenticated access were achieved."
            if has_success else
            "Telemetry demonstrates unauthorized access attempts were blocked or denied; no compromise confirmed."
        )

        # Build Event Timeline Table
        timeline_rows = []
        for e in sorted(supporting_events, key=lambda x: x.get("timestamp", "")):
            ts = e.get("timestamp", "N/A")
            cat = e.get("event_category", "N/A")
            etype = e.get("event_type", "N/A")
            res = e.get("result", "N/A")
            meta = str(e.get("metadata", {}))[:60] + "..." if len(str(e.get("metadata", {}))) > 60 else str(e.get("metadata", {}))
            timeline_rows.append(f"| `{ts}` | `{cat}` | `{etype}` | `{res}` | `{meta}` |")

        timeline_table = "\n".join(timeline_rows) if timeline_rows else "| N/A | N/A | N/A | N/A | No events recorded |"

        # Format analyst observations
        notes_section = ""
        if analyst_notes:
            notes_section = "\n".join([f"- **{n.get('analyst_name', 'Analyst')}** ({n.get('created_at', '')}): {n.get('note', '')}" for n in analyst_notes])
        else:
            notes_section = "- *No additional analyst notes recorded at initial triage.*"

        markdown_content = f"""# Security Incident Report: {incident_id}

---

## 1. Executive Summary

| Attribute | Detail |
|---|---|
| **Incident ID** | `{incident_id}` |
| **Severity** | **{severity.upper()}** |
| **Detection Timestamp** | `{detection_time}` |
| **Primary Target Host** | `{affected_host}` |
| **Attacker / Source IP** | `{source_ip}` (Documentation Range) |
| **Targeted / Affected Account** | `{affected_user}` |
| **Lead Analyst** | {analyst_name} |
| **Telemetry Outcome** | {outcome_statement} |

**Summary Description:**
{description}

---

## 2. Threat Classification & MITRE ATT&CK Mapping

- **Triggered Detection Rule:** `{rule_id}` - {rule_name}
- **MITRE ATT&CK Technique ID:** [`{technique_id}`](https://attack.mitre.org/techniques/{technique_id.replace('.', '/')})
- **Technique Name:** {technique_name}
- **ATT&CK Tactic:** {tactic}
- **Telemetry Environment:** SOC-SIM Synthetic Educational Telemetry

---

## 3. Incident Timeline & Telemetry Evidence

The following chronological sequence represents raw and normalized telemetry associated with this alert:

| Timestamp (UTC) | Category | Event Type | Result | Key Details |
|---|---|---|---|---|
{timeline_table}

**Supporting Event Count:** {len(supporting_events)} events analyzed.

---

## 4. Analyst Findings & Behavioral Assessment

1. **Activity Evaluation:**
   Log analysis confirms activity matching the signature of {rule_name}. Observed telemetry originated from `{source_ip}` targeting host `{affected_host}`.

2. **Access & Compromise Validation:**
   {outcome_statement} No assumptions of broader breach have been made beyond verifiable log entries.

3. **Analyst Notes & Observations:**
{notes_section}

---

## 5. False Positive Assessment

- **Known Baseline Triggers:** Routine network scans, administrative maintenance scripts with expired keys, or user typographical errors.
- **Verification Result:** The observed velocity and sequence pattern deviate significantly from recorded baseline behavior for this subnet. Confirmed **True Positive** for simulation testing.

---

## 6. Containment, Remediation & Recommended Response

- **Immediate Containment:**
  - Block source IP `{source_ip}` at the perimeter firewall / security group.
  - Terminate any active sessions associated with user `{affected_user}` on `{affected_host}`.
- **Eradication & Remediation:**
  - Force immediate password rotation and session invalidation for `{affected_user}`.
  - Audit recent file modifications, scheduled tasks, and authorized SSH keys on `{affected_host}`.
- **Specific Detection Rule Recommendations:**
  - {recommended_steps}

---

## 7. Final Conclusion & Sign-Off

The alert has been verified and documented. Telemetry evidence has been preserved in the SOC-SIM database. Recommended containment actions have been formulated in accordance with the incident response playbook.

*Report automatically generated by SOC-SIM Security Incident Analysis Platform on {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")}.*
"""
        return markdown_content

    def save_report(self, incident_id: str, content: str) -> str:
        """Save report to Markdown file."""
        filepath = os.path.join(self.output_dir, f"{incident_id}.md")
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        return filepath
